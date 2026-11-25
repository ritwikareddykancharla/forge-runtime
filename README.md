# ForgeRuntime v2: Multi-Wave Repo Modernization, AST Mutant-Kill Verifier & Sandboxed Agent Runtime

**Live Production App (Amazon CloudFront + Private S3 OAC + Bedrock Nova):** [https://d33vgp4hlabu23.cloudfront.net](https://d33vgp4hlabu23.cloudfront.net)  
**Live Endpoints:** `https://d33vgp4hlabu23.cloudfront.net/api/health` · `/api/transform/wave` · `/api/mutants/verify`

**ForgeRuntime v2** addresses six structural bottlenecks in enterprise code-modernization, automated testing, and governed analytics agents:
1. **Tarjan-SCC Topological Multi-Wave Modernization (`transform_wave.py`)**: Parses cross-file Python import graphs, collapses mutual import cycles via Tarjan's Strongly Connected Components (`SCC`), orders bottom-up leaf-to-root modernization waves, checkpoints progress in SQLite WAL with monotonic fencing tokens (`0` duplicate side effects across `12/12` crash-recovery trials; `12/12` zombie writes rejected), and runs bounded `k <= 3` `Plan -> Patch -> Unittest -> Traceback Self-Repair` (`80.0%` `Pass@1` lifted to `100.0%` `Pass@3`).
2. **AST Mutation Testing & Mutant-Kill Adequacy Verifier (`mutant_verifier.py`)**: Synthesizes `16` real AST code mutants (`>` to `>=`, `+` to `-`, `True` to `False`, `and` to `or`, off-by-one boundary shifts) and runs candidate `unittest` suites inside isolated `subprocess.run(..., shell=False)` processes to compute real **Mutation Kill Score (`killed / total_mutants`)**, rejecting tautological `assert True` suites that hit `100.0%` line coverage while killing `0.0%` of bugs.
3. **2-Hop AST Call-Graph Context Slicer (`ast_graph.py`)**: Compresses multi-file repository context by `-83.2%` (`5.97x`; `733.7` mean tokens vs `4,382` full-repo tokens) while preserving `100.0%` 2-hop caller/callee contract recall.
4. **Complexity & Latency SLA Model Router (`model_router.py`)**: Routes tasks across Amazon Bedrock (`us.amazon.nova-lite-v1:0`, Sonnet 4, Opus), cutting p50 latency by `-59.71%` and token spend by `-35.89%` (`12/12` tier match).
5. **Cedar Policy, STS On-Behalf-Of & Pre-Warmed Sandbox (`cedar_sts_gate.py`)**: Enforces `forbid > permit` Cedar authorization, signs `HMAC-SHA256` `TransitiveTagKeys` session tokens, and executes untrusted Python over persistent `python3 -I` pipes in `0.324 ms` p50 (`56.2x` faster than `18.2 ms` cold spawns; `10/10` escape vectors blocked).
6. **4-Gate Apache Iceberg / SQLite Governance Proxy (`governed_lake_mcp.py`)**: Enforces SQLite C-engine `set_authorizer` column ACLs, regional CTE scoping, and `EXPLAIN QUERY PLAN` schema checks (`8/8` governance cases verified).

![ForgeRuntime CloudFront Architecture](docs/architecture.svg)

---

## Interactive 5-Tab Runtime Workbench

1. **Tab 01: Multi-Wave Modernization & AST Mutant-Kill Verifier (`/api/transform/wave` + `/api/mutants/verify`)**:
   - Execute 4-wave topological modernization across a 6-module legacy codebase with a 2-file cyclic Auth SCC, inject a mid-wave worker crash + stale zombie write to inspect SQLite WAL fencing-token rejection and idempotent tool outbox replay, and verify `Pass@1` traceback repair.
   - Compare **Tautological Smoke Tests (`100.0%` line coverage · `0.0%` mutant kill)**, **Naive Zero-Shot LLM Tests (`100.0%` line coverage · `37.5%` mutant kill)**, and **Survivor-Guided Boundary Tests (`100.0%` line coverage · `100.0%` mutant kill)**, or edit custom `unittest` assertions live.
2. **Tab 02: 2-Hop AST Call-Graph Context Slicer (`ASTRepoGraph`)**:
   - Inspect Hop 0, Hop 1, and Hop 2 slices across the 6-file enterprise billing repo (`56` nodes, `38` edges) and self-indexed ForgeRuntime v2 repo (`11` files, `227` nodes, `337` edges, `78,276` tokens).
3. **Tab 03: Complexity, Latency & Budget Bedrock Router (`MultiModelRouter`)**:
   - Tune SLA latency caps and USD ceilings or invoke live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) code modernization synthesis.
4. **Tab 04: Cedar Policy, STS On-Behalf-Of & Warm Sandbox (`CedarSTSGate` + `WarmSandboxPool`)**:
   - Test `forbid > permit` Cedar policies, simulate `PrincipalTag:RiskRung` HMAC tampering, and run all 10 adversarial sandbox escape vectors.
5. **Tab 05: 4-Gate Governed Apache Iceberg / SQLite MCP (`GovernedLakeMCPServer`)**:
   - Switch caller personas (`NA`, `EMEA`, `FinOps SOX Auditor`) to inspect C-level `set_authorizer` blocking on `raw_card_token`, `customer_email`, `SELECT *`, and nonexistent schema columns.

---

## Measured Benchmark Results (`benchmarks/latest_results.json`)

Reproducible on Python 3.10+ (using built-in Python runtime modules, `0` third-party packages required) via `python3 benchmarks/run_benchmarks.py` (`1,608.38 ms` total wall time):

| Component & Metric | Measured Result | Baseline / Verification Proof |
| :--- | :---: | :--- |
| **Tarjan-SCC Multi-Wave Modernization & Repair (`k <= 3`)** | **100.0% Pass@3** (`4` waves · `5` SCCs) | Collapses `1` mutual cyclic Auth SCC; lifts `80.0%` `Pass@1` to `100.0%` (`10 -> 0` anti-patterns; `6/6` tests) |
| **SQLite WAL Fencing & Idempotent Tool Outbox** | **100.0% recovery** (`12/12` crash trials) | **`0` duplicate side effects** · **`100.0%` (`12/12`)** stale zombie fencing tokens rejected |
| **AST Mutant-Kill Test Adequacy Verifier (`16` Mutants)** | **100.0% gate accuracy** (`3/3` suites) | Rejects `assert True` (`100.0%` cov, `0.0%` kill) & naive LLM (`37.5%` kill); verifies survivor-guided (`100.0%` kill) |
| **Multi-File Repo Prompt Token Reduction (`hop_budget=2`)** | **-83.2%** (**5.97x**; `733.7` vs `4,382` tokens) | **5.30x** vs touched full files (`3,887` tokens) at **100.0%** 2-hop neighborhood recall (`20.48%` single-file) |
| **Pre-Warmed Sandbox Dispatch Latency (`p50` / `p95`)** | **0.324 ms p50** / **0.387 ms p95** | **56.2x faster** than cold `subprocess` (`18.200 ms` p50 / `20.126 ms` p95; `38.53 ms` one-time warmup) |
| **Adversarial Sandbox Escape Containment** | **10 / 10 blocked (100.0%)** | Blocks `os`, `socket`, `/etc/passwd`, dunder traversal & CPU spin + automatic worker respawn |
| **Model Router Latency & Spend Reduction (12-Task Suite)** | **-59.71% p50 latency** / **-35.89% cost** | `$0.6069` vs `$0.9467` static Opus baseline (`12/12` tier routing accuracy) |
| **Cedar + STS OBO & 4-Gate SQL Governance** | **100.0%** (`4/4` Cedar · `8/8` SQL cases) | `HMAC-SHA256` `TransitiveTagKeys` tamper check + SQLite `set_authorizer` + `EXPLAIN QUERY PLAN` |

---

## Run Locally & Deploy to Amazon CloudFront

```bash
# 1. Run all 25 unit, fencing, mutant-kill, policy, and sandbox escape tests
python3 -m unittest discover -s tests -v
python3 benchmarks/run_benchmarks.py

# 2. Start the ForgeRuntime v2 Web IDE locally
python3 -m forge_runtime.web_api
# -> Open http://127.0.0.1:8086

# 3. Deploy to Amazon CloudFront + Private S3 (OAC) + Lambda /api/* + Amazon Bedrock (us-west-2)
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
export AWS_PROFILE=portfolio AWS_DEFAULT_REGION=us-west-2
chmod +x infra/deploy_cloudfront.sh
./infra/deploy_cloudfront.sh
```
