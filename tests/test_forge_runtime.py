"""Comprehensive unit, security, and integration test suite for ForgeRuntime."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from forge_runtime import (
    AWSSTSAssumeRoleAdapter,
    ASTRepoGraph,
    BedrockConverseRuntimeAdapter,
    CLAUDE_OPUS_ID,
    CLAUDE_SONNET_4_ID,
    CallerGovernanceContext,
    CedarPolicyEngine,
    CedarRequest,
    CedarSTSGate,
    CodingTaskRequest,
    GovernedLakeMCPServer,
    MultiModelRouter,
    NOVA_LITE_ID,
    STSOnBehalfOfMinter,
    StrandsToolRegistryAdapter,
    WarmSandboxPool,
    build_reference_enterprise_repo,
    run_ast_graph_benchmark,
    run_model_router_benchmark,
)
from forge_runtime.cedar_sts_gate import ADVERSARIAL_ESCAPE_PAYLOADS, ColdSubprocessExecutor
from forge_runtime.cli import main as cli_main


PACKAGE_DIR = Path(__file__).resolve().parent.parent / "forge_runtime"


class TestASTRepoGraph(unittest.TestCase):
    def test_graph_indexes_symbols_and_typed_edges(self) -> None:
        graph = ASTRepoGraph.from_sources(build_reference_enterprise_repo())
        stats = graph.summary_stats()
        self.assertEqual(stats["files_indexed"], 6)
        self.assertGreaterEqual(stats["node_counts_by_kind"]["Class"], 8)
        self.assertGreaterEqual(stats["node_counts_by_kind"]["Function"], 20)
        self.assertGreaterEqual(stats["edge_counts_by_type"]["CALLS"], 8)
        self.assertGreaterEqual(stats["edge_counts_by_type"]["IMPORTS"], 5)
        self.assertGreaterEqual(stats["edge_counts_by_type"]["INHERITS"], 1)

    def test_pack_minimal_context_compression_and_full_recall(self) -> None:
        bench = run_ast_graph_benchmark(repo_path=PACKAGE_DIR)
        agg = bench["aggregate_metrics"]
        self.assertGreaterEqual(agg["token_compression_ratio_vs_touched_files"], 5.0)
        self.assertLessEqual(agg["token_compression_ratio_vs_touched_files"], 8.5)
        self.assertEqual(agg["call_neighborhood_recall_pct"], 100.0)
        self.assertLess(agg["naive_single_file_recall_pct"], 50.0)

    def test_self_hosted_forge_runtime_codebase_indexing(self) -> None:
        live_graph = ASTRepoGraph.from_directory(PACKAGE_DIR)
        pack = live_graph.pack_minimal_context("authorize_and_mint", hop_budget=2)
        self.assertIn("authorize_and_mint", pack.focal_symbol_id)
        self.assertEqual(pack.neighborhood_recall, 1.0)
        self.assertGreater(pack.compression_ratio_vs_full_repo, 5.0)


class TestMultiModelRouter(unittest.TestCase):
    def test_routing_tiers_and_sla_budget_guardrails(self) -> None:
        router = MultiModelRouter()

        fast_dec = router.route(
            CodingTaskRequest(
                task_id="T1",
                prompt="Lint and quick explain symbol signature",
                input_tokens=300,
                expected_output_tokens=100,
                files_touched=1,
                ast_hop_depth=0,
                cyclomatic_complexity=2,
            )
        )
        self.assertEqual(fast_dec.selected_model, NOVA_LITE_ID)

        mid_dec = router.route(
            CodingTaskRequest(
                task_id="T2",
                prompt="Implement SQL bugfix patch and unit test",
                input_tokens=1200,
                expected_output_tokens=400,
                files_touched=2,
                ast_hop_depth=2,
                cyclomatic_complexity=7,
            )
        )
        self.assertEqual(mid_dec.selected_model, CLAUDE_SONNET_4_ID)

        heavy_dec = router.route(
            CodingTaskRequest(
                task_id="T3",
                prompt="Cross-module architectural refactor for distributed lock consensus",
                input_tokens=4500,
                expected_output_tokens=1500,
                files_touched=5,
                ast_hop_depth=3,
                cyclomatic_complexity=18,
            )
        )
        self.assertEqual(heavy_dec.selected_model, CLAUDE_OPUS_ID)

        # Hard SLA cap downgrades Opus -> Nova Lite
        sla_dec = router.route(
            CodingTaskRequest(
                task_id="T4",
                prompt="Cross-module architectural refactor under strict autocomplete SLA",
                input_tokens=4000,
                expected_output_tokens=800,
                files_touched=5,
                ast_hop_depth=3,
                cyclomatic_complexity=16,
                sla_max_p95_ms=330.0,
            )
        )
        self.assertEqual(sla_dec.ideal_unconstrained_model, CLAUDE_OPUS_ID)
        self.assertEqual(sla_dec.selected_model, NOVA_LITE_ID)
        self.assertTrue(sla_dec.sla_constrained)

        # Hard USD budget cap downgrades Opus -> Sonnet or Nova Lite
        budget_dec = router.route(
            CodingTaskRequest(
                task_id="T5",
                prompt="Cross-module architectural refactor with tight per-call cost ceiling",
                input_tokens=4000,
                expected_output_tokens=1000,
                files_touched=5,
                ast_hop_depth=3,
                cyclomatic_complexity=16,
                max_cost_usd=0.001,
            )
        )
        self.assertEqual(budget_dec.selected_model, NOVA_LITE_ID)
        self.assertTrue(budget_dec.budget_constrained)

    def test_benchmark_100_pct_accuracy(self) -> None:
        bench = run_model_router_benchmark()
        self.assertEqual(bench["summary"]["tier_routing_accuracy_pct"], 100.0)
        self.assertGreater(bench["summary"]["cost_savings_vs_opus_pct"], 30.0)


class TestCedarSTSandSandbox(unittest.TestCase):
    def test_cedar_forbid_always_overrides_permit_and_default_deny(self) -> None:
        policy_src = """
        @id("broad-admin-permit")
        permit(principal, action, resource);

        @id("forbid-drop-table")
        forbid(principal, action == Action::"DropTable", resource);

        @id("forbid-prod-unless-approved")
        forbid(principal, action == Action::"MutateProd", resource)
        when { context.env == "prod" }
        unless { context.human_approved == true };
        """
        engine = CedarPolicyEngine(policy_src)

        # DropTable MUST be denied even though `broad-admin-permit` matches everything
        drop_res = engine.evaluate(
            CedarRequest(
                principal='Agent::"admin-bot"',
                action='Action::"DropTable"',
                resource='Table::"billing"',
                context={"env": "prod", "human_approved": True},
            )
        )
        self.assertEqual(drop_res.decision, "DENY")
        self.assertEqual(drop_res.reason_code, "EXPLICIT_FORBID_OVERRIDE")
        self.assertIn("broad-admin-permit", drop_res.matched_permits)
        self.assertIn("forbid-drop-table", drop_res.matched_forbids)

        # Unapproved prod mutation denied
        unapproved = engine.evaluate(
            CedarRequest(
                principal='Agent::"admin-bot"',
                action='Action::"MutateProd"',
                resource='Service::"payments"',
                context={"env": "prod", "human_approved": False},
            )
        )
        self.assertEqual(unapproved.decision, "DENY")

        # Approved prod mutation allowed
        approved = engine.evaluate(
            CedarRequest(
                principal='Agent::"admin-bot"',
                action='Action::"MutateProd"',
                resource='Service::"payments"',
                context={"env": "prod", "human_approved": True},
            )
        )
        self.assertEqual(approved.decision, "ALLOW")

        # Empty policy engine enforces implicit default deny
        empty_engine = CedarPolicyEngine()
        default_deny = empty_engine.evaluate(
            CedarRequest(
                principal='Agent::"any"',
                action='Action::"Read"',
                resource='Table::"any"',
            )
        )
        self.assertEqual(default_deny.decision, "DENY")
        self.assertEqual(default_deny.reason_code, "IMPLICIT_DEFAULT_DENY")

    def test_sts_obo_minter_signature_expiry_and_tamper_detection(self) -> None:
        minter = STSOnBehalfOfMinter(kms_hmac_secret="unit-test-secret-key")
        bundle = minter.mint_session_token(
            role_name="ForgeDataLakeReader",
            agent_id="agent:kiro-07",
            approved_by="human:staff-eng@company.com",
            risk_rung="RUNG_1_READ",
            correlation_id="ct-corr-998877",
            duration_seconds=600,
            issued_at_epoch=1_700_000_000,
        )
        ok, status = minter.verify_session_token(bundle, now_epoch=1_700_000_300)
        self.assertTrue(ok)
        self.assertEqual(status, "VALID_OBO_SESSION")

        # Expired check
        exp_ok, exp_status = minter.verify_session_token(bundle, now_epoch=1_700_000_999)
        self.assertFalse(exp_ok)
        self.assertEqual(exp_status, "SESSION_TOKEN_EXPIRED")

        # Tamper check on PrincipalTag:ApprovedBy
        tampered = json.loads(json.dumps(bundle))
        tampered["claims"]["PrincipalTags"]["PrincipalTag:ApprovedBy"] = "human:attacker@evil.example"
        t_ok, t_status = minter.verify_session_token(tampered, now_epoch=1_700_000_300)
        self.assertFalse(t_ok)
        self.assertEqual(t_status, "SIGNATURE_TAMPERED")

        # CedarSTSGate refuses to mint STS bundle when Cedar denies
        gate = CedarSTSGate()
        denied_out = gate.authorize_and_mint(
            CedarRequest(
                principal='Agent::"rogue-bot"',
                action='Action::"DropTable"',
                resource='Table::"prod.billing"',
                context={"environment": "prod", "human_approved": True, "approval_ticket": "T-1"},
            ),
            role_name="AdminRole",
            approved_by="human:sre",
            risk_rung="RUNG_3",
        )
        self.assertFalse(denied_out["authorized"])
        self.assertIsNone(denied_out["sts_obo_bundle"])

    def test_warm_sandbox_pool_vs_cold_and_escape_containment(self) -> None:
        cold = ColdSubprocessExecutor()
        with WarmSandboxPool(pool_size=2) as pool:
            warm_runs = [
                pool.execute("sum(x * 2 for x in vals)", inputs={"vals": [1, 2, 3, 4]})
                for _ in range(6)
            ]
            for r in warm_runs:
                self.assertTrue(r.ok)
                self.assertEqual(r.result, 20)

            cold_run = cold.execute("sum(x * 2 for x in vals)", inputs={"vals": [1, 2, 3, 4]})
            self.assertTrue(cold_run.ok)
            self.assertEqual(cold_run.result, 20)

            median_warm = sorted(r.dispatch_latency_ms for r in warm_runs)[len(warm_runs) // 2]
            self.assertLess(median_warm, 5.0)
            self.assertLess(median_warm, cold_run.dispatch_latency_ms)

            # Verify 100% containment across all 10 adversarial escape vectors
            for attack_id, code in ADVERSARIAL_ESCAPE_PAYLOADS:
                res = pool.execute(code, timeout_sec=0.12)
                self.assertFalse(res.ok, f"Escape payload {attack_id} was not blocked!")
                self.assertIn(res.status, ("SECURITY_BLOCKED", "TIMEOUT_CONTAINED"))

            # Pool recovers cleanly after killing infinite-loop worker
            after = pool.execute("math_res = [x + 1 for x in [9, 19]]\nresult = sum(math_res)")
            self.assertTrue(after.ok)
            self.assertEqual(after.result, 30)


class TestGovernedLakeMCP(unittest.TestCase):
    def setUp(self) -> None:
        self.server = GovernedLakeMCPServer()

    def tearDown(self) -> None:
        self.server.close()

    def test_catalog_and_lineage_tools(self) -> None:
        tables = self.server.call_tool("list_tables", {"include_columns": True})
        self.assertTrue(tables["ok"])
        self.assertEqual(tables["table_count"], 3)

        lineage = self.server.call_tool("describe_lineage", {"table_name": "ads_campaigns"})
        self.assertTrue(lineage["ok"])
        self.assertEqual(lineage["owner_team"], "ads-ai-core-spektr")

    def test_readonly_pii_rls_and_schema_contract_gates(self) -> None:
        emea_ctx = CallerGovernanceContext(
            principal_id="agent:emea-partner-analyst",
            allowed_classifications={"PUBLIC", "INTERNAL"},
            allowed_regions={"EMEA"},
            sts_correlation_id="ct-emea-01",
        )

        # 1. Valid governed query scoped automatically to EMEA
        ok_res = self.server.call_tool(
            "validate_and_query_sql",
            {"sql": "SELECT DISTINCT region FROM ads_campaigns"},
            caller_context=emea_ctx,
        )
        self.assertTrue(ok_res["ok"])
        self.assertTrue(ok_res["schema_contract_validated"])
        self.assertEqual([r["region"] for r in ok_res["rows"]], ["EMEA"])

        # 2. Mutating SQL blocked (`DROP`, `DELETE`, `UPDATE`, `ATTACH`, multi-statement)
        for bad_sql in (
            "DROP TABLE customer_billing",
            "DELETE FROM ads_campaigns WHERE region = 'NA'",
            "UPDATE customer_billing SET payment_status = 'SETTLED'",
            "ATTACH DATABASE ':memory:' AS aux",
            "SELECT 1; SELECT 2;",
        ):
            bad_res = self.server.call_tool(
                "validate_and_query_sql",
                {"sql": bad_sql},
                caller_context=emea_ctx,
            )
            self.assertFalse(bad_res["ok"])
            self.assertEqual(bad_res["error_code"], "READ_ONLY_SQL_VIOLATION")

        # 3. Column-level PII/PCI ACL blocks both explicit columns and `SELECT *`
        for pii_sql in (
            "SELECT customer_email FROM customer_billing LIMIT 2",
            "SELECT raw_card_token FROM customer_billing LIMIT 2",
            "SELECT * FROM customer_billing LIMIT 2",
        ):
            pii_res = self.server.call_tool(
                "validate_and_query_sql",
                {"sql": pii_sql},
                caller_context=emea_ctx,
            )
            self.assertFalse(pii_res["ok"])
            self.assertEqual(pii_res["error_code"], "COLUMN_ACL_VIOLATION")

        # 4. Hallucinated column caught in EXPLAIN QUERY PLAN pre-validation
        halluc_res = self.server.call_tool(
            "validate_and_query_sql",
            {"sql": "SELECT campaign_id, nonexistent_roas_v9 FROM ads_campaigns"},
            caller_context=emea_ctx,
        )
        self.assertFalse(halluc_res["ok"])
        self.assertEqual(halluc_res["error_code"], "SCHEMA_CONTRACT_VIOLATION")


class TestCLIAndAdapters(unittest.TestCase):
    def test_all_cli_modes_emit_valid_json(self) -> None:
        for mode in ("ast-graph", "cedar-sts", "sandbox-bench", "lake-mcp", "demo-all"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["--mode", mode, "--iterations", "6"])
            self.assertEqual(rc, 0)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(parsed["platform"], "ForgeRuntime")
            self.assertEqual(parsed["mode"], mode)

    def test_aws_and_strands_adapters(self) -> None:
        bedrock_adapter = BedrockConverseRuntimeAdapter(region_name="us-west-2")
        payload = bedrock_adapter.build_converse_request(
            CLAUDE_SONNET_4_ID, "Generate governed Iceberg ROAS SQL."
        )
        kwargs = payload.to_boto3_kwargs()
        self.assertIn("claude-sonnet-4", kwargs["modelId"])

        minter = STSOnBehalfOfMinter()
        bundle = minter.mint_session_token(
            role_name="ForgeRole",
            agent_id="agent:kiro",
            approved_by="human:lead",
            risk_rung="RUNG_1",
        )
        sts_kwargs = AWSSTSAssumeRoleAdapter.to_boto3_assume_role_kwargs(bundle)
        self.assertIn("ApprovedBy", sts_kwargs["TransitiveTagKeys"])
        self.assertEqual(len(sts_kwargs["Tags"]), 4)

        with GovernedLakeMCPServer() as mcp:
            strands_specs = StrandsToolRegistryAdapter.export_tool_specs(mcp.list_mcp_tools())
        self.assertEqual(len(strands_specs), 3)
        self.assertEqual(strands_specs[0]["toolSpec"]["name"], "list_tables")


if __name__ == "__main__":
    unittest.main()
