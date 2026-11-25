"""Unit tests for `forge_runtime/web_api.py` CloudFront `/api/*` IDE backend."""

from __future__ import annotations

import os
import unittest

from forge_runtime import web_api


class TestForgeRuntimeWebAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["FORGERUNTIME_OFFLINE_LLM"] = "1"

    @classmethod
    def tearDownClass(cls) -> None:
        if web_api.IDE._warm_pool is not None:
            web_api.IDE._warm_pool.close()

    def test_01_health_and_initial_state(self) -> None:
        st, health = web_api.route_api_request("GET", "/api/health", {}, {})
        self.assertEqual(st, 200)
        self.assertEqual(health["service"], "forge-runtime")

        st2, snap = web_api.route_api_request("GET", "/api/state", {}, {})
        self.assertEqual(st2, 200)
        self.assertEqual(len(snap["repo_files"]), 6)
        self.assertEqual(snap["initial_slice"]["neighborhood_recall_pct"], 100.0)
        self.assertEqual(snap["initial_slice"]["benchmark_aggregate"]["token_compression_ratio_vs_full_repo"], 5.97)

    def test_02_modernize_and_sandbox_escape_suite(self) -> None:
        st, mod = web_api.route_api_request(
            "POST", "/api/modernize/synthesize", {}, {"task_id": "MOD-01-DECIMAL-SETTLEMENT"}
        )
        self.assertEqual(st, 200)
        self.assertTrue(mod["sandbox_run"]["warm"]["ok"])

        st2, esc = web_api.route_api_request("POST", "/api/sandbox/escapes", {}, {})
        self.assertEqual(st2, 200)
        self.assertEqual(esc["blocked_count"], 10)
        self.assertEqual(esc["containment_rate_pct"], 100.0)
        self.assertTrue(esc["post_timeout_worker_recovery"]["ok"])

    def test_03_customer_ads_pii_blocked_and_auditor_email_allowed(self) -> None:
        # Partner analyst blocked on email/ssn
        st, partner = web_api.route_api_request(
            "POST",
            "/api/lake/query",
            {},
            {"sql": "SELECT email, ssn FROM customer_ads LIMIT 3", "persona_id": "partner_analyst"},
        )
        self.assertEqual(st, 200)
        self.assertFalse(partner["ok"])
        self.assertEqual(partner["error_code"], "COLUMN_ACL_VIOLATION")

        # FinOps auditor allowed email, still blocked on ssn
        st2, aud_ok = web_api.route_api_request(
            "POST",
            "/api/lake/query",
            {},
            {"sql": "SELECT account_id, region, email, roas FROM customer_ads LIMIT 3", "persona_id": "finops_auditor"},
        )
        self.assertEqual(st2, 200)
        self.assertTrue(aud_ok["ok"])
        self.assertEqual(aud_ok["row_count"], 3)

        st3, aud_ssn = web_api.route_api_request(
            "POST",
            "/api/lake/query",
            {},
            {"sql": "SELECT account_id, ssn FROM customer_ads LIMIT 3", "persona_id": "finops_auditor"},
        )
        self.assertEqual(st3, 200)
        self.assertFalse(aud_ssn["ok"])
        self.assertEqual(aud_ssn["error_code"], "COLUMN_ACL_VIOLATION")

    def test_04_transform_wave_and_mutants_verify_routes(self) -> None:
        st_w, wave = web_api.route_api_request(
            "POST",
            "/api/transform/wave",
            {},
            {"simulate_crash_after_wave": 1, "inject_first_attempt_bug": True},
        )
        self.assertEqual(st_w, 200)
        self.assertTrue(wave["ok"])
        self.assertEqual(wave["duplicate_side_effects"], 0)
        self.assertEqual(wave["plan"]["cyclic_scc_count"], 1)

        # GET /api/mutants/verify returns 200 with verified survivor_guided suite
        st_m_get, mut_get = web_api.route_api_request("GET", "/api/mutants/verify", {}, {})
        self.assertEqual(st_m_get, 200)
        self.assertTrue(mut_get["ok"])
        self.assertEqual(mut_get["adequacy_verdict"], "ADEQUATE_SUITE_VERIFIED")

        # POST /api/mutants/verify rejects tautological suite and synthesizes survivor killers
        st_m_post, mut_taut = web_api.route_api_request(
            "POST",
            "/api/mutants/verify",
            {},
            {"suite_id": "tautological", "synthesize_survivors": True},
        )
        self.assertEqual(st_m_post, 200)
        self.assertFalse(mut_taut["ok"])
        self.assertEqual(mut_taut["adequacy_verdict"], "REJECTED_TAUTOLOGICAL_SUITE")
        self.assertTrue(mut_taut["survivor_refinement"]["refined_verification"]["ok"])

        # Security block on malicious test code over public endpoint
        st_sec, sec_out = web_api.route_api_request(
            "POST",
            "/api/mutants/verify",
            {},
            {"test_code": "import os\nos.system('whoami')"},
        )
        self.assertEqual(st_sec, 400)
        self.assertEqual(sec_out["error_code"], "MUTANT_SANDBOX_SECURITY_BLOCKED")


if __name__ == "__main__":
    unittest.main()
