# ForgeRuntime — Code Context Slicer, SQL Policy Proxy & Sandbox Runner

> **Live AWS Endpoint (`us-west-2` Lambda Function URL):** [https://w6jkm2tnqcysmunvv72awnziya0dqlxn.lambda-url.us-west-2.on.aws/](https://w6jkm2tnqcysmunvv72awnziya0dqlxn.lambda-url.us-west-2.on.aws/)  
> **Health Check:** `https://w6jkm2tnqcysmunvv72awnziya0dqlxn.lambda-url.us-west-2.on.aws/api/health`  
> **Live API Call:** `curl -s -X POST https://w6jkm2tnqcysmunvv72awnziya0dqlxn.lambda-url.us-west-2.on.aws/api/run -H 'Content-Type: application/json' -d '{}'`  
> **Interactive Web UI:** [https://ritwikareddykancharla.github.io/forge-runtime/](https://ritwikareddykancharla.github.io/forge-runtime/)

**ForgeRuntime** is a zero-dependency Python runtime for coding and data-analytics agents. It slices multi-file repositories along AST import and call graphs so prompts include exact caller/callee definitions without raw-file bloat, runs untrusted Python patches inside a pre-warmed worker pool, routes requests across Bedrock model tiers by complexity and latency budget, and enforces column- and row-level SQL/Iceberg access policies via Cedar.

---

## What Problem This Solves

- **Raw file chunking wastes tokens and drops cross-file definitions:** Sending entire files to an LLM burns prompt budget on unrelated functions, while fixed-size text chunks split class methods from imported types. Parsing the AST call/import graph keeps **100%** of 2-hop caller/callee signatures while cutting prompt tokens by **83.2%** (**5.97x** compression).
- **Cold subprocess sandboxes add ~39 ms per test run:** Spawning a fresh `python3` interpreter on every generated patch adds startup overhead and risks host filesystem/network access if unguarded. Keeping pre-warmed `python3 -I` workers over persistent pipes lowers p50 dispatch latency from **38.7 ms to 0.63 ms** (**98.4%** reduction) while blocking disallowed imports and builtins (**10/10** escape tests blocked).
- **Routing every edit to a frontier model is slow and expensive:** Simple lint fixes and symbol lookups do not need Opus-class inference. Scoring AST complexity and latency SLAs before dispatch cuts p50 model latency by **59.7%** and token spend by **35.9%**.
- **Agent-generated SQL can leak restricted columns:** Analytics agents frequently emit `SELECT *` or join sensitive billing tables. Validating queries with Cedar rules, SQLite authorizer callbacks, tenant row filters, and `EXPLAIN QUERY PLAN` blocks **100%** of restricted PII/PCI column reads and invalid table/column references before execution.

---

## System Architecture

> **Excalidraw Source:** [`docs/architecture.excalidraw`](docs/architecture.excalidraw)

![ForgeRuntime Architecture Diagram](docs/architecture.svg)

## How It Works

1. **AST Call & Import Context Slicer (`forge_runtime/ast_graph.py`)**  
   Indexes Python and TypeScript modules, classes, and functions into directed `CALLS`, `IMPORTS`, and `INHERITS` edges (`ASTRepoGraph`). Given a target symbol and `hop_budget=2`, `pack_minimal_context()` emits full source for the target symbol (`Hop 0`) and compact type signatures plus docstrings for `Hop 1` and `Hop 2` callers, callees, and base classes.

2. **Complexity & Latency-Budget Model Router (`forge_runtime/model_router.py`)**  
   Scores cyclomatic complexity, AST hop count, files touched, and prompt size to select between `amazon.nova-lite-v1` (fast lint/lookup tasks under `<350 ms` p95), `anthropic.claude-sonnet-4` (standard patches, tests, and SQL generation), and `anthropic.claude-opus` (multi-file refactors), stepping down automatically when hard latency (`sla_max_p95_ms`) or cost (`max_cost_usd`) caps require it.

3. **Cedar Policy Check, Scoped STS Session Tags & Pre-Warmed Sandbox (`forge_runtime/cedar_sts_gate.py`)**  
   - **Cedar Evaluator:** Evaluates `permit` and `forbid` statements with explicit `forbid`-overrides-`permit` precedence and default `DENY` (for example, blocking `DropTable` or unapproved production writes even when broad role permits exist).
   - **AWS STS Session Tag Signer:** Signs scoped session attributes (`ApprovedBy`, `AgentId`, `CloudTrailCorrelationId`) with `HMAC-SHA256` (`hmac.compare_digest`) so downstream tools can detect tampered session claims.
   - **Pre-Warmed Worker Pool (`WarmSandboxPool`):** Maintains isolated `python3 -I` worker processes over persistent stdio pipes, combining a pre-execution AST check, restricted `__builtins__`, an allowlisted import hook, and a `select`-based timeout watchdog that kills and replaces runaway workers.

4. **SQL & Apache Iceberg Policy Proxy (`forge_runtime/governed_lake_mcp.py`)**  
   Exposes `list_tables`, `describe_lineage`, and `validate_and_query_sql` over `ads_campaigns`, `customer_billing`, and `agent_telemetry` tables with Iceberg partition/snapshot metadata:
   - Rejects mutating or multi-statement SQL (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `ATTACH`, `PRAGMA`).
   - Enforces column-level PII/PCI permissions (`customer_email`, `raw_card_token`, `tax_ein_ssn`, `caller_ip`) at SQLite query-compile time via `conn.set_authorizer` (`SQLITE_READ`), catching `SELECT *`, aliases, and CTEs.
   - Injects parameterized tenant and region (`NA`, `EMEA`, `APAC`) CTE filters and runs `EXPLAIN QUERY PLAN` prior to execution.

5. **AWS Bedrock & Lambda Adapters (`forge_runtime/adapters.py`, `forge_runtime/aws_lambda_handler.py`)**  
   Provides `boto3` (`bedrock-runtime` Converse API and `sts.assume_role`) tool wrappers alongside the live AWS Lambda Function URL handler.

---

## Benchmark Results

Reproducible on Python 3.10+ (stdlib only) via `python3 benchmarks/run_benchmarks.py` (saved in `benchmarks/latest_results.json`):

| Component & Metric | Measured Result | Baseline Comparison |
| :--- | :---: | :---: |
| **Multi-File Repo Prompt Token Reduction (`hop_budget=2`)** | **-83.2%** (**5.97x** compression; `734` vs `4,382` tokens) | **5.30x** vs. touched full files (`3,887` tokens) |
| **2-Hop Caller/Callee Definition Recall** | **100.0%** | `20.5%` single-file truncation |
| **Pre-Warmed Sandbox Startup Latency (`p50` / `p95`)** | **0.63 ms p50** / **1.08 ms p95** | **98.4% lower** (**61.9x** faster) than cold `subprocess` (`38.7 ms` p50) |
| **Sandbox Escape Test Suite (10 Attack Vectors)** | **10 / 10 blocked (100%)** | Blocks `os`, `socket`, `/etc/passwd`, dunder traversal & CPU spin |
| **Model Router Latency & Spend Reduction (12-Task Suite)** | **-59.7% p50 latency** / **-35.9% token spend** | vs. single-model Opus baseline (`12/12` tier match) |
| **Cedar SQL/Iceberg Policy & Schema Enforcement** | **100.0%** (`8/8` SQL + `4/4` Cedar cases) | Blocks restricted PII/PCI column reads & unapproved writes |

---

## Quickstart

Requires Python 3.10+ with zero external package dependencies:

```bash
# 1. Run unit, policy, and sandbox escape tests
python3 -m unittest discover -s tests -v

# 2. Reproduce all benchmark numbers in benchmarks/latest_results.json
python3 benchmarks/run_benchmarks.py

# 3. Run individual subsystem demos (JSON output)
python3 -m forge_runtime.cli --mode demo-all
python3 -m forge_runtime.cli --mode ast-graph
python3 -m forge_runtime.cli --mode model-router
python3 -m forge_runtime.cli --mode cedar-sts
python3 -m forge_runtime.cli --mode sandbox-bench
python3 -m forge_runtime.cli --mode lake-mcp
```
