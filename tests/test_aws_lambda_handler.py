"""Unit & integration tests for `forge_runtime/aws_lambda_handler.py`."""

from __future__ import annotations

import json
import unittest

from forge_runtime.aws_lambda_handler import handler


class TestAWSLambdaHandler(unittest.TestCase):
    def test_get_root_serves_interactive_html_ui(self) -> None:
        resp = handler(
            {
                "rawPath": "/",
                "requestContext": {"http": {"method": "GET"}},
            }
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("text/html", resp["headers"]["Content-Type"])
        self.assertIn("ForgeRuntime", resp["body"])
        self.assertIn("OrderSettlementEngine", resp["body"])
        self.assertIn("CedarPolicyGate", resp["body"])
        self.assertIn("IcebergQueryPlanner", resp["body"])

    def test_health_endpoint(self) -> None:
        resp = handler(
            {
                "rawPath": "/api/health",
                "requestContext": {"http": {"method": "GET"}},
            }
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["platform"], "ForgeRuntime")

    def test_post_api_run_live_modes(self) -> None:
        # 1. Router live evaluation
        r_router = handler(
            {
                "rawPath": "/api/run",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "mode": "router-eval",
                        "prompt": "Quick lint fix and symbol lookup",
                        "files_touched": 1,
                        "cyclomatic_complexity": 2,
                    }
                ),
            }
        )
        self.assertEqual(r_router["statusCode"], 200)
        router_payload = json.loads(r_router["body"])
        self.assertEqual(router_payload["data"]["selected_model"], "bedrock/amazon.nova-lite-v1")

        # 2. Sandbox escape containment over Lambda API
        r_sbx = handler(
            {
                "rawPath": "/api/run",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "mode": "sandbox-exec",
                        "code": "import os\nos.system('id')",
                    }
                ),
            }
        )
        self.assertEqual(r_sbx["statusCode"], 200)
        sbx_payload = json.loads(r_sbx["body"])
        self.assertEqual(sbx_payload["data"]["status"], "SECURITY_BLOCKED")

        # 3. Governed SQL execution & PII block over Lambda API
        r_sql = handler(
            {
                "rawPath": "/api/run",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "mode": "governed-sql",
                        "sql": "SELECT raw_card_token FROM customer_billing",
                    }
                ),
            }
        )
        self.assertEqual(r_sql["statusCode"], 200)
        sql_payload = json.loads(r_sql["body"])
        self.assertFalse(sql_payload["data"]["ok"])
        self.assertEqual(sql_payload["data"]["error_code"], "COLUMN_ACL_VIOLATION")

        # 4. Direct /api/mutants/verify and /api/transform/wave over Lambda handler
        r_mut = handler(
            {
                "rawPath": "/api/mutants/verify",
                "requestContext": {"http": {"method": "GET"}},
            }
        )
        self.assertEqual(r_mut["statusCode"], 200)
        self.assertTrue(json.loads(r_mut["body"])["ok"])

        r_wave = handler(
            {
                "rawPath": "/api/transform/wave",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps({"simulate_crash_after_wave": 1}),
            }
        )
        self.assertEqual(r_wave["statusCode"], 200)
        self.assertTrue(json.loads(r_wave["body"])["ok"])


if __name__ == "__main__":
    unittest.main()
