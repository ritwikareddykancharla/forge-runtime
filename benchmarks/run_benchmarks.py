#!/usr/bin/env python3
"""End-to-end deterministic & OS-timed benchmark suite for ForgeRuntime.

Generates `benchmarks/latest_results.json` with verified metrics across:
  1. AST Repo Knowledge Graph & Minimal Context Packing (compression ratio & recall)
  2. Multi-Model Bedrock Router (tier accuracy, latency speedup & cost savings)
  3. Cedar Policy Engine & AWS STS On-Behalf-Of Session Token Minter
  4. Warm Sandbox Pool vs. Cold Subprocess Spawn & 10-Vector Escape Containment
  5. Governed Iceberg / SQLite Data-Lake MCP Server (SQL safety, PII ACLs & EXPLAIN QUERY PLAN)
"""

from __future__ import annotations

import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from forge_runtime.cli import execute_cli_mode


def main() -> int:
    t0 = time.perf_counter()
    demo_envelope = execute_cli_mode("demo-all", iterations=20)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    report = {
        "benchmark_suite": "ForgeRuntime End-to-End Verification Suite",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "python_version": platform.python_version(),
            "platform": f"{platform.system()}-{platform.machine()}",
            "external_dependencies": 0,
        },
        "total_benchmark_wall_time_ms": elapsed_ms,
        "headline_metrics": demo_envelope["data"]["headline_metrics"],
        "pillars": {
            "ast_repo_graph": demo_envelope["data"]["ast_graph"],
            "multi_model_router": demo_envelope["data"]["model_router"],
            "cedar_sts_gate": demo_envelope["data"]["cedar_sts"],
            "sandbox_runtime_benchmark": demo_envelope["data"]["sandbox_bench"],
            "governed_lake_mcp": demo_envelope["data"]["lake_mcp"],
        },
    }

    out_path = ROOT_DIR / "benchmarks" / "latest_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("=== ForgeRuntime Verified Benchmark Summary ===")
    print(json.dumps(report["headline_metrics"], indent=2))
    print(f"\nSaved full benchmark artifact -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
