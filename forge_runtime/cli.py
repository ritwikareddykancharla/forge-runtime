"""ForgeRuntime JSON CLI (`forge_runtime/cli.py`).

Supports live interactive execution from web backends or terminal workflows:
  python3 -m forge_runtime.cli --mode demo-all
  python3 -m forge_runtime.cli --mode ast-graph
  python3 -m forge_runtime.cli --mode model-router
  python3 -m forge_runtime.cli --mode cedar-sts
  python3 -m forge_runtime.cli --mode sandbox-bench
  python3 -m forge_runtime.cli --mode lake-mcp
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .ast_graph import ASTRepoGraph, build_reference_enterprise_repo, run_ast_graph_benchmark
from .cedar_sts_gate import run_cedar_sts_demo, run_sandbox_benchmark
from .governed_lake_mcp import CallerGovernanceContext, GovernedLakeMCPServer, run_governed_lake_demo
from .model_router import run_model_router_benchmark


SUPPORTED_MODES = (
    "demo-all",
    "ast-graph",
    "model-router",
    "cedar-sts",
    "sandbox-bench",
    "lake-mcp",
)


def execute_cli_mode(
    mode: str,
    *,
    symbol: Optional[str] = None,
    hops: int = 2,
    repo_path: Optional[str] = None,
    sql: Optional[str] = None,
    iterations: int = 12,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    pkg_dir = Path(__file__).resolve().parent

    if mode == "ast-graph":
        if symbol:
            graph = (
                ASTRepoGraph.from_directory(repo_path)
                if repo_path
                else ASTRepoGraph.from_sources(build_reference_enterprise_repo())
            )
            pack = graph.pack_minimal_context(symbol, hop_budget=hops)
            payload: Dict[str, Any] = {
                "graph_stats": graph.summary_stats(),
                "context_pack": pack.to_dict(),
            }
        else:
            payload = run_ast_graph_benchmark(repo_path=repo_path or pkg_dir)
            payload["model_router"] = run_model_router_benchmark()["summary"]

    elif mode == "model-router":
        payload = run_model_router_benchmark()

    elif mode == "cedar-sts":
        payload = run_cedar_sts_demo()

    elif mode == "sandbox-bench":
        payload = run_sandbox_benchmark(iterations=iterations)

    elif mode == "lake-mcp":
        if sql:
            with GovernedLakeMCPServer() as server:
                payload = server.call_tool(
                    "validate_and_query_sql",
                    {"sql": sql, "max_rows": 25},
                    caller_context=CallerGovernanceContext(),
                )
        else:
            payload = run_governed_lake_demo()

    elif mode == "demo-all":
        ast_res = run_ast_graph_benchmark(repo_path=repo_path or pkg_dir)
        router_res = run_model_router_benchmark()
        cedar_res = run_cedar_sts_demo()
        sandbox_res = run_sandbox_benchmark(iterations=iterations)
        lake_res = run_governed_lake_demo()
        payload = {
            "headline_metrics": {
                "ast_token_compression_vs_touched_files": ast_res["aggregate_metrics"][
                    "token_compression_ratio_vs_touched_files"
                ],
                "ast_token_compression_vs_full_repo": ast_res["aggregate_metrics"][
                    "token_compression_ratio_vs_full_repo"
                ],
                "ast_call_neighborhood_recall_pct": ast_res["aggregate_metrics"][
                    "call_neighborhood_recall_pct"
                ],
                "router_tier_accuracy_pct": router_res["summary"]["tier_routing_accuracy_pct"],
                "router_cost_savings_vs_opus_pct": router_res["summary"][
                    "cost_savings_vs_opus_pct"
                ],
                "router_latency_reduction_vs_opus_pct": router_res["summary"][
                    "latency_reduction_vs_opus_pct"
                ],
                "cedar_policy_invariant_accuracy_pct": cedar_res[
                    "policy_invariant_accuracy_pct"
                ],
                "sts_obo_hmac_tamper_detection": cedar_res[
                    "sts_hmac_tamper_detection_verified"
                ],
                "warm_sandbox_p50_ms": sandbox_res["warm_pool_latency_ms"]["p50"],
                "warm_sandbox_p95_ms": sandbox_res["warm_pool_latency_ms"]["p95"],
                "cold_subprocess_p50_ms": sandbox_res["cold_subprocess_latency_ms"]["p50"],
                "warm_vs_cold_p50_speedup": sandbox_res["p50_speedup_factor"],
                "sandbox_escape_containment_pct": sandbox_res["escape_containment_rate_pct"],
                "lake_governance_gate_accuracy_pct": lake_res["governance_gate_accuracy_pct"],
                "lake_schema_contract_valid_execution_pct": lake_res[
                    "valid_pipeline_schema_contract_rate_pct"
                ],
            },
            "ast_graph": ast_res,
            "model_router": router_res,
            "cedar_sts": cedar_res,
            "sandbox_bench": sandbox_res,
            "lake_mcp": lake_res,
        }
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    return {
        "platform": "ForgeRuntime",
        "version": __version__,
        "mode": mode,
        "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        "data": payload,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forge-runtime",
        description="ForgeRuntime: Sandboxed Coding & Governed Data-Lake Agent Platform CLI",
    )
    parser.add_argument(
        "--mode",
        choices=SUPPORTED_MODES,
        default="demo-all",
        help="Execution demo mode returning structured JSON.",
    )
    parser.add_argument(
        "--symbol",
        default=None,
        help="Optional focal symbol query for --mode ast-graph.",
    )
    parser.add_argument(
        "--hops",
        type=int,
        default=2,
        help="Hop budget for AST minimal context packing (default: 2).",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        help="Optional directory path to index with ASTRepoGraph.",
    )
    parser.add_argument(
        "--sql",
        default=None,
        help="Optional ad-hoc SQL query to validate and run in --mode lake-mcp.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=12,
        help="Iterations for Warm Sandbox Pool vs Cold Subprocess benchmark (default: 12).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional file path to persist JSON output.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    envelope = execute_cli_mode(
        args.mode,
        symbol=args.symbol,
        hops=args.hops,
        repo_path=args.repo_path,
        sql=args.sql,
        iterations=args.iterations,
    )
    serialized = json.dumps(envelope, indent=2)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized + "\n", encoding="utf-8")
    sys.stdout.write(serialized + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
