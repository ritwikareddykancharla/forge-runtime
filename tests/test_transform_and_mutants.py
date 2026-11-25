"""Unit tests for ForgeRuntime v2: Tarjan-SCC Wave Modernization & AST Mutant-Kill Verifier."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forge_runtime.mutant_verifier import (
    ASTMutantSynthesizer,
    DEFAULT_MUTANT_TARGET_CODE,
    MutantAdequacyVerifier,
    MutantSandboxScanner,
    MutantSecurityViolation,
    SUITE_NAIVE_LLM_HAPPY_PATH,
    SUITE_SURVIVOR_GUIDED_ADEQUATE,
    SUITE_TAUTOLOGICAL_RUBBER_STAMP,
)
from forge_runtime.transform_wave import (
    FencedCheckpointStore,
    SCCNode,
    StaleFencingTokenError,
    TarjanSCCWavePlanner,
    WaveModernizationOrchestrator,
)


class TestTarjanSCCAndFencedModernization(unittest.TestCase):
    def test_tarjan_scc_collapses_cycles_and_orders_leaf_to_root_waves(self) -> None:
        synthetic_repo = {
            "leaf/math_ops.py": "def add(a, b):\n    return a + b\n",
            "cycle/alpha.py": "from cycle.beta import beta_fn\nfrom leaf.math_ops import add\ndef alpha_fn(x):\n    return add(x, 1)\n",
            "cycle/beta.py": "from cycle.alpha import alpha_fn\ndef beta_fn(x):\n    return alpha_fn(x)\n",
            "root/service.py": "from cycle.alpha import alpha_fn\ndef handle(x):\n    return alpha_fn(x)\n",
        }
        plan = TarjanSCCWavePlanner.plan_waves(synthetic_repo)
        self.assertEqual(plan["module_count"], 4)
        self.assertEqual(plan["scc_count"], 3)
        self.assertEqual(plan["cyclic_scc_count"], 1)
        self.assertEqual(plan["wave_count"], 3)

        w0_files = plan["waves"][0]["sccs"][0]["files"]
        w1_scc = plan["waves"][1]["sccs"][0]
        w2_files = plan["waves"][2]["sccs"][0]["files"]
        self.assertEqual(w0_files, ["leaf/math_ops.py"])
        self.assertTrue(w1_scc["is_cyclic"])
        self.assertEqual(sorted(w1_scc["files"]), ["cycle/alpha.py", "cycle/beta.py"])
        self.assertEqual(w2_files, ["root/service.py"])

    def test_sqlite_wal_fencing_token_and_idempotent_outbox_zero_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_file = str(Path(tmp) / "fenced_test.sqlite3")
            store = FencedCheckpointStore(db_path=db_file)
            try:
                calls = []
                l1 = store.acquire_lease("run-fenced-1", "worker-A")
                self.assertEqual(l1.fencing_token, 1)

                r1 = store.execute_fenced_outbox_step(
                    run_id="run-fenced-1",
                    fencing_token=l1.fencing_token,
                    idempotency_key="run-fenced-1:publish:SCC-00",
                    step_name="publish",
                    request_payload={"scc": "SCC-00"},
                    side_effect_fn=lambda: (calls.append("executed") or {"artifact": "v1"}),
                )
                self.assertFalse(r1.replayed_from_outbox)
                self.assertEqual(len(calls), 1)

                # Failover Worker B acquires fencing_token = 2
                l2 = store.acquire_lease("run-fenced-1", "worker-B")
                self.assertEqual(l2.fencing_token, 2)

                # Zombie Worker A with stale fencing_token = 1 MUST be rejected
                with self.assertRaises(StaleFencingTokenError):
                    store.save_wave_checkpoint(
                        run_id="run-fenced-1",
                        fencing_token=l1.fencing_token,
                        wave_index=0,
                        scc_id="SCC-00",
                        status="ZOMBIE",
                        attempts_used=1,
                        snapshot_sha256="bad",
                        patched_files={},
                    )

                # Worker B re-executes the same idempotency_key -> replayed from outbox, 0 duplicate calls!
                r2 = store.execute_fenced_outbox_step(
                    run_id="run-fenced-1",
                    fencing_token=l2.fencing_token,
                    idempotency_key="run-fenced-1:publish:SCC-00",
                    step_name="publish",
                    request_payload={"scc": "SCC-00"},
                    side_effect_fn=lambda: (calls.append("duplicate!") or {"artifact": "v2"}),
                )
                self.assertTrue(r2.replayed_from_outbox)
                self.assertEqual(len(calls), 1)
                tel = store.telemetry("run-fenced-1")
                self.assertEqual(tel["stale_fencing_rejections"], 1)
                self.assertEqual(tel["outbox_idempotent_replays"], 1)
            finally:
                store.close()

    def test_wave_orchestrator_self_repair_crash_recovery_and_atomic_rollback(self) -> None:
        orchestrator = WaveModernizationOrchestrator(max_repair_attempts=3)
        side_effects = []
        res = orchestrator.run_modernization(
            run_id="ut-wave-repair-crash",
            inject_first_attempt_bug=True,
            simulate_crash_after_wave=1,
            side_effect_log=side_effects,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["duplicate_side_effects"], 0)
        self.assertEqual(res["post_migration_findings_count"], 0)
        self.assertTrue(res["crash_recovery"]["zombie_write_blocked"])

        # Verify Wave 2 (`services/settlement_worker.py`) triggered Attempt 1 traceback -> Attempt 2 repair
        w2 = next(s for s in res["wave_steps"] if "services/settlement_worker.py" in s["files"])
        self.assertEqual(w2["attempts_used"], 2)
        self.assertFalse(w2["passed_on_attempt_1"])
        self.assertGreaterEqual(len(w2["repair_tracebacks"]), 1)

        # Verify atomic rollback when all k=3 repair attempts fail
        def _broken_patcher(scc: SCCNode, attempt: int, tb: str) -> dict[str, str]:
            return {fp: "def broken_stub():\n    return None\n" for fp in scc.files}

        rb_orch = WaveModernizationOrchestrator(max_repair_attempts=3)
        rb_res = rb_orch.run_modernization(
            run_id="ut-wave-rollback",
            simulate_crash_after_wave=None,
            custom_patch_fn=_broken_patcher,
        )
        self.assertFalse(rb_res["ok"])
        self.assertEqual(rb_res["status"], "ROLLED_BACK")
        self.assertEqual(rb_res["wave_steps"][0]["attempts_used"], 3)


class TestASTMutantVerifier(unittest.TestCase):
    def test_synthesizes_all_five_ast_mutant_families(self) -> None:
        mutants = ASTMutantSynthesizer.synthesize_mutants(DEFAULT_MUTANT_TARGET_CODE, max_mutants=20)
        self.assertGreaterEqual(len(mutants), 12)
        operators = {m.operator for m in mutants}
        self.assertIn("RELATIONAL_BOUNDARY", operators)
        self.assertIn("OFF_BY_ONE_BOUNDARY", operators)
        self.assertIn("ARITHMETIC_OP", operators)
        self.assertIn("LOGICAL_CONNECTOR", operators)
        self.assertIn("BOOLEAN_CONSTANT", operators)

    def test_scanner_blocks_dangerous_imports_and_builtins(self) -> None:
        for bad_snippet in (
            "import os\nos.system('id')",
            "import subprocess",
            "data = open('/etc/passwd').read()",
            "x = ().__class__.__subclasses__()",
            "eval('1+1')",
        ):
            with self.assertRaises(MutantSecurityViolation):
                MutantSandboxScanner.validate_source(bad_snippet)

    def test_rejects_tautological_tests_and_verifies_survivor_guided_suite(self) -> None:
        verifier = MutantAdequacyVerifier(max_workers=4)

        taut = verifier.verify_suite(
            DEFAULT_MUTANT_TARGET_CODE,
            SUITE_TAUTOLOGICAL_RUBBER_STAMP,
            max_mutants=16,
        )
        self.assertFalse(taut["ok"])
        self.assertEqual(taut["adequacy_verdict"], "REJECTED_TAUTOLOGICAL_SUITE")
        self.assertTrue(taut["tautological_rubber_stamp_detected"])
        self.assertGreaterEqual(taut["line_coverage_pct"], 90.0)
        self.assertEqual(taut["mutation_kill_score_pct"], 0.0)

        naive = verifier.verify_suite(
            DEFAULT_MUTANT_TARGET_CODE,
            SUITE_NAIVE_LLM_HAPPY_PATH,
            max_mutants=16,
        )
        self.assertFalse(naive["ok"])
        self.assertEqual(naive["adequacy_verdict"], "REJECTED_WEAK_MUTANT_KILL")
        self.assertGreater(naive["mutation_kill_score_pct"], 25.0)
        self.assertLess(naive["mutation_kill_score_pct"], 85.0)

        guided = verifier.verify_suite(
            DEFAULT_MUTANT_TARGET_CODE,
            SUITE_SURVIVOR_GUIDED_ADEQUATE,
            max_mutants=16,
        )
        self.assertTrue(guided["ok"])
        self.assertEqual(guided["adequacy_verdict"], "ADEQUATE_SUITE_VERIFIED")
        self.assertGreaterEqual(guided["mutation_kill_score_pct"], 93.0)


if __name__ == "__main__":
    unittest.main()
