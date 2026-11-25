"""AWS Lambda Function URL & Local HTTP Handler (`forge_runtime/aws_lambda_handler.py`).

Serves both:
  - `GET  /`            -> Self-contained interactive web app (`docs/index.html`)
  - `GET  /api/health`  -> Runtime & Python environment telemetry
  - `POST /api/run`     -> Live Python execution across AST Repo Graph, Multi-Model Router,
                           Cedar + AWS STS On-Behalf-Of Gate, Warm Sandbox Pool, and
                           Governed Iceberg / SQLite MCP Server.

Compatible with AWS Lambda Function URLs (`AuthType=NONE`, Payload Format v2.0) and
runnable locally via:
    python3 -m forge_runtime.aws_lambda_handler --port 8085
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import platform
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .cedar_sts_gate import WarmSandboxPool
from .cli import SUPPORTED_MODES, execute_cli_mode
from .governed_lake_mcp import CallerGovernanceContext, GovernedLakeMCPServer
from .model_router import CodingTaskRequest, MultiModelRouter


DOCS_INDEX_CANDIDATES = (
    Path(__file__).resolve().parent.parent / "docs" / "index.html",
    Path(__file__).resolve().parent / "docs" / "index.html",
)

CORS_HEADERS: Dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _load_index_html() -> str:
    for candidate in DOCS_INDEX_CANDIDATES:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return "<html><body><h1>ForgeRuntime Live Lambda Endpoint</h1><p>POST /api/run</p></body></html>"


def _json_response(payload: Dict[str, Any], status_code: int = 200) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            **CORS_HEADERS,
            "Content-Type": "application/json; charset=utf-8",
        },
        "body": json.dumps(payload, indent=2),
    }


def _html_response(html_body: str, status_code: int = 200) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            **CORS_HEADERS,
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-cache",
        },
        "body": html_body,
    }


def _execute_live_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    mode = str(body.get("mode", "demo-all")).strip()

    if mode in SUPPORTED_MODES:
        return execute_cli_mode(
            mode,
            symbol=body.get("symbol"),
            hops=int(body.get("hops", 2)),
            repo_path=body.get("repo_path"),
            sql=body.get("sql"),
            iterations=max(1, min(25, int(body.get("iterations", 8)))),
        )

    if mode == "router-eval":
        router = MultiModelRouter()
        req = CodingTaskRequest(
            task_id=str(body.get("task_id", "LIVE-REQ")),
            prompt=str(body.get("prompt", "Write governed Iceberg SQL patch")),
            input_tokens=int(body.get("input_tokens", 1200)),
            expected_output_tokens=int(body.get("expected_output_tokens", 420)),
            files_touched=int(body.get("files_touched", 2)),
            ast_hop_depth=int(body.get("ast_hop_depth", 2)),
            cyclomatic_complexity=int(body.get("cyclomatic_complexity", 6)),
            sla_max_p95_ms=(
                float(body["sla_max_p95_ms"]) if body.get("sla_max_p95_ms") is not None else None
            ),
            max_cost_usd=(
                float(body["max_cost_usd"]) if body.get("max_cost_usd") is not None else None
            ),
        )
        decision = router.route(req)
        dec_dict = decision.to_dict() if hasattr(decision, "to_dict") else dataclasses.asdict(decision)
        return {
            "platform": "ForgeRuntime",
            "version": __version__,
            "mode": mode,
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "data": dec_dict,
        }

    if mode == "sandbox-exec":
        code = str(body.get("code", "result = 2 + 2"))
        with WarmSandboxPool(pool_size=1) as pool:
            res = pool.execute(code, timeout_sec=0.25)
        res_dict = res.to_dict() if hasattr(res, "to_dict") else dataclasses.asdict(res)
        return {
            "platform": "ForgeRuntime",
            "version": __version__,
            "mode": mode,
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "data": res_dict,
        }

    if mode == "governed-sql":
        sql = str(body.get("sql", "SELECT region, COUNT(*) AS n FROM ads_campaigns GROUP BY region"))
        principal = str(body.get("principal_id", "agent:spektr-partner-analyst"))
        classifications = set(body.get("allowed_classifications", ["PUBLIC", "INTERNAL"]))
        regions_raw = body.get("allowed_regions")
        regions = set(regions_raw) if regions_raw else {"NA"}
        ctx = CallerGovernanceContext(
            principal_id=principal,
            allowed_classifications=classifications,
            allowed_regions=regions,
        )
        with GovernedLakeMCPServer() as server:
            out = server.validate_and_query_sql(sql, caller_context=ctx, max_rows=25)
        return {
            "platform": "ForgeRuntime",
            "version": __version__,
            "mode": mode,
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "data": out,
        }

    raise ValueError(
        f"Unsupported mode '{mode}'. Choose from {list(SUPPORTED_MODES) + ['router-eval', 'sandbox-exec', 'governed-sql']}."
    )


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL (v2.0) and API Gateway (v1.0) entrypoint."""
    req_ctx = event.get("requestContext") or {}
    http_info = req_ctx.get("http") or {}
    method = (
        http_info.get("method")
        or event.get("httpMethod")
        or "GET"
    ).upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = event.get("queryStringParameters") or {}

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if method == "GET" and raw_path in ("/", "/index.html"):
        return _html_response(_load_index_html())

    if method == "GET" and raw_path == "/api/health":
        return _json_response(
            {
                "status": "ok",
                "platform": "ForgeRuntime",
                "version": __version__,
                "python_version": platform.python_version(),
                "supported_modes": list(SUPPORTED_MODES)
                + ["router-eval", "sandbox-exec", "governed-sql"],
            }
        )

    if raw_path in ("/api/transform/wave", "/api/mutants/verify"):
        from .web_api import route_api_request

        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded") and isinstance(raw_body, str):
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        body_dict = json.loads(raw_body) if isinstance(raw_body, str) and raw_body.strip() else {}
        status, payload = route_api_request(method, raw_path, dict(query_params), body_dict)
        return _json_response(payload, status_code=status)

    if raw_path == "/api/run":
        try:
            if method == "GET":
                payload_in: Dict[str, Any] = dict(query_params)
            else:
                raw_body = event.get("body") or "{}"
                if event.get("isBase64Encoded") and isinstance(raw_body, str):
                    raw_body = base64.b64decode(raw_body).decode("utf-8")
                payload_in = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
            result = _execute_live_payload(payload_in)
            return _json_response(result, status_code=200)
        except Exception as exc:  # noqa: BLE001
            return _json_response(
                {"status": "error", "error": str(exc)},
                status_code=400,
            )

    return _json_response({"status": "not_found", "path": raw_path}, status_code=404)


lambda_handler = handler


class _LocalForgeHTTPHandler(BaseHTTPRequestHandler):
    """Lightweight stdlib local adapter delegating directly to `handler()`."""

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        body_str = ""
        if method == "POST":
            length = int(self.headers.get("Content-Length", "0"))
            body_str = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        resp = handler(
            {
                "rawPath": parsed.path,
                "queryStringParameters": qs,
                "body": body_str,
                "requestContext": {"http": {"method": method}},
            }
        )
        raw_bytes = resp["body"].encode("utf-8")
        self.send_response(int(resp["statusCode"]))
        for k, v in resp.get("headers", {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw_bytes)))
        self.end_headers()
        self.wfile.write(raw_bytes)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch("OPTIONS")

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run ForgeRuntime HTTP/Lambda server locally.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8085)
    args = parser.parse_args(argv)
    srv = ThreadingHTTPServer((args.host, args.port), _LocalForgeHTTPHandler)
    print(f"ForgeRuntime live server listening on http://{args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
