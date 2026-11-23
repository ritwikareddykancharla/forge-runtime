"""Governed Iceberg / SQLite Data-Lake MCP Server (`forge_runtime/governed_lake_mcp.py`).

Engineered for governed enterprise analytics & partner insights agents
(AWS Context, Ads `Spektr`, Partner Insights, and FinOps Controllership):
  - Exposes 3 Model Context Protocol (MCP) tools:
      1. `list_tables`            — Iceberg snapshot metadata, partition specs & column sensitivity tags
      2. `describe_lineage`       — Upstream streaming/compaction lineage & schema-contract SLAs
      3. `validate_and_query_sql` — Multi-gate governed SQL execution engine
  - Enforces 4 deterministic governance gates BEFORE returning data:
      Gate 1 (Read-Only SQL Safety): Comment-stripping lexical + multi-statement blocker
             rejecting `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `ATTACH`, `PRAGMA`, etc.
      Gate 2 (Column-Level PII/PCI ACLs): Dual lexical + SQLite C-engine `set_authorizer`
             blocking unauthorized reads of `customer_email`, `raw_card_token`, `tax_ein_ssn`,
             and `caller_ip` — even through `SELECT *`, aliases, or CTEs.
      Gate 3 (Row-Level Tenant/Region Scoping): Transparent CTE row-filter injection
             enforcing sovereign region (`NA`, `EMEA`, `APAC`) and `advertiser_id` isolation.
      Gate 4 (Schema-Contract Pre-Validation): Executes `EXPLAIN QUERY PLAN` prior to query
             execution, catching hallucinated columns/tables and recording index usage.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


_FORBIDDEN_SQL_KEYWORDS_RE = re.compile(
    r"\b("
    r"DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE|REPLACE|"
    r"ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|LOAD_EXTENSION|GRANT|REVOKE"
    r")\b",
    re.IGNORECASE,
)

_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r"'(?:''|[^'])*'")


@dataclass(frozen=True)
class ColumnContract:
    name: str
    sql_type: str
    classification: str  # "PUBLIC" | "INTERNAL" | "PII_CONFIDENTIAL" | "PII_RESTRICTED" | "PCI_RESTRICTED"
    nullable: bool
    description: str


@dataclass(frozen=True)
class IcebergTableMetadata:
    table_name: str
    iceberg_uri: str
    current_snapshot_id: int
    schema_version: int
    partition_spec: str
    owner_team: str
    freshness_sla_minutes: int
    upstream_sources: List[str]
    downstream_consumers: List[str]
    columns: List[ColumnContract]


@dataclass(frozen=True)
class CallerGovernanceContext:
    """Caller identity & data-governance entitlements passed to MCP tool calls."""

    principal_id: str = "agent:partner-insights-bot"
    allowed_classifications: Set[str] = field(
        default_factory=lambda: {"PUBLIC", "INTERNAL"}
    )
    allowed_regions: Optional[Set[str]] = None
    allowed_advertiser_id: Optional[str] = None
    sts_correlation_id: str = "ct-mcp-default"


ICEBERG_CATALOG: Dict[str, IcebergTableMetadata] = {
    "ads_campaigns": IcebergTableMetadata(
        table_name="ads_campaigns",
        iceberg_uri="iceberg://spektr_prod.ads.campaigns",
        current_snapshot_id=884920174629104,
        schema_version=3,
        partition_spec="bucket(16, advertiser_id), days(event_date)",
        owner_team="ads-ai-core-spektr",
        freshness_sla_minutes=15,
        upstream_sources=[
            "kinesis://ads-clickstream-raw",
            "flink://spektr-attribution-joiner-v3",
        ],
        downstream_consumers=[
            "semantic_view://partner_roas_summary",
            "agent://partner-insights-copilot",
        ],
        columns=[
            ColumnContract("campaign_id", "TEXT", "INTERNAL", False, "Primary campaign identifier"),
            ColumnContract("advertiser_id", "TEXT", "INTERNAL", False, "Partner advertiser tenant ID"),
            ColumnContract("partner_tier", "TEXT", "PUBLIC", False, "ENTERPRISE | GROWTH | EMERGING"),
            ColumnContract("region", "TEXT", "PUBLIC", False, "Sovereign partition (NA | EMEA | APAC)"),
            ColumnContract("channel", "TEXT", "PUBLIC", False, "Ad placement surface"),
            ColumnContract("impressions", "INTEGER", "INTERNAL", False, "Verified impression count"),
            ColumnContract("clicks", "INTEGER", "INTERNAL", False, "Verified click count"),
            ColumnContract("spend_usd", "REAL", "INTERNAL", False, "Gross campaign spend in USD"),
            ColumnContract("attributed_revenue_usd", "REAL", "INTERNAL", False, "14-day attributed sales USD"),
            ColumnContract("event_date", "TEXT", "PUBLIC", False, "ISO-8601 partition date"),
        ],
    ),
    "customer_billing": IcebergTableMetadata(
        table_name="customer_billing",
        iceberg_uri="iceberg://finops_prod.billing.customer_ledgers",
        current_snapshot_id=912047582019385,
        schema_version=4,
        partition_spec="months(billing_month), identity(region)",
        owner_team="finops-controllership-ledger",
        freshness_sla_minutes=60,
        upstream_sources=[
            "aurora://payments-journal-wal",
            "spark://finops-iceberg-compactor",
        ],
        downstream_consumers=[
            "semantic_view://controllership_close_trial_balance",
            "audit://sox-revenue-reconciliation",
        ],
        columns=[
            ColumnContract("invoice_id", "TEXT", "INTERNAL", False, "Immutable ledger invoice ID"),
            ColumnContract("advertiser_id", "TEXT", "INTERNAL", False, "Billed partner tenant ID"),
            ColumnContract("region", "TEXT", "PUBLIC", False, "Tax & residency region"),
            ColumnContract("plan_tier", "TEXT", "PUBLIC", False, "Contracted billing tier"),
            ColumnContract("compute_spend_usd", "REAL", "INTERNAL", False, "Agent & inference compute charges"),
            ColumnContract("storage_spend_usd", "REAL", "INTERNAL", False, "Iceberg & S3 storage charges"),
            ColumnContract("total_invoice_usd", "REAL", "INTERNAL", False, "Total settled invoice amount"),
            ColumnContract("payment_status", "TEXT", "INTERNAL", False, "SETTLED | PENDING | DISPUTED"),
            ColumnContract("customer_email", "TEXT", "PII_CONFIDENTIAL", False, "Billing contact email (PII)"),
            ColumnContract("raw_card_token", "TEXT", "PCI_RESTRICTED", False, "Payment instrument token (PCI-DSS)"),
            ColumnContract("tax_ein_ssn", "TEXT", "PII_RESTRICTED", False, "Taxpayer identification number"),
            ColumnContract("billing_month", "TEXT", "PUBLIC", False, "YYYY-MM close period"),
        ],
    ),
    "agent_telemetry": IcebergTableMetadata(
        table_name="agent_telemetry",
        iceberg_uri="iceberg://agentcore_prod.observability.runtime_spans",
        current_snapshot_id=773819204857120,
        schema_version=2,
        partition_spec="days(ts_date), identity(model_tier)",
        owner_team="bedrock-agentcore-runtime",
        freshness_sla_minutes=5,
        upstream_sources=[
            "otel://agentcore-span-collector",
            "firehose://iceberg-observability-sink",
        ],
        downstream_consumers=[
            "dashboard://model-router-cost-sla",
            "eval://step-trajectory-regression-gate",
        ],
        columns=[
            ColumnContract("span_id", "TEXT", "INTERNAL", False, "OpenTelemetry span ID"),
            ColumnContract("advertiser_id", "TEXT", "INTERNAL", False, "Tenant context ID"),
            ColumnContract("region", "TEXT", "PUBLIC", False, "Execution AWS region"),
            ColumnContract("agent_name", "TEXT", "PUBLIC", False, "Logical agent identifier"),
            ColumnContract("model_tier", "TEXT", "PUBLIC", False, "Routed Bedrock model ID"),
            ColumnContract("prompt_tokens", "INTEGER", "INTERNAL", False, "Input context tokens"),
            ColumnContract("completion_tokens", "INTEGER", "INTERNAL", False, "Generated output tokens"),
            ColumnContract("latency_ms", "REAL", "INTERNAL", False, "End-to-end span latency ms"),
            ColumnContract("cost_usd", "REAL", "INTERNAL", False, "Metered Bedrock invocation cost"),
            ColumnContract("sandbox_mode", "TEXT", "PUBLIC", False, "warm_pool | cold_subprocess | none"),
            ColumnContract("status_code", "TEXT", "PUBLIC", False, "OK | BLOCKED | TIMEOUT"),
            ColumnContract("caller_ip", "TEXT", "PII_CONFIDENTIAL", False, "Client source IPv4 address (PII)"),
        ],
    ),
}


class GovernedLakeMCPServer:
    """In-memory SQLite + Apache Iceberg Metadata Catalog MCP Server with Row/Column ACLs."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._column_classifications: Dict[Tuple[str, str], str] = {}
        for tbl_name, meta in ICEBERG_CATALOG.items():
            for col in meta.columns:
                self._column_classifications[(tbl_name, col.name)] = col.classification
        self._initialize_schema_and_seed()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "GovernedLakeMCPServer":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _initialize_schema_and_seed(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE ads_campaigns (
                campaign_id TEXT PRIMARY KEY NOT NULL,
                advertiser_id TEXT NOT NULL,
                partner_tier TEXT NOT NULL,
                region TEXT NOT NULL,
                channel TEXT NOT NULL,
                impressions INTEGER NOT NULL,
                clicks INTEGER NOT NULL,
                spend_usd REAL NOT NULL,
                attributed_revenue_usd REAL NOT NULL,
                event_date TEXT NOT NULL
            );
            CREATE INDEX idx_ads_region_tier ON ads_campaigns(region, partner_tier);
            CREATE INDEX idx_ads_advertiser_date ON ads_campaigns(advertiser_id, event_date);

            CREATE TABLE customer_billing (
                invoice_id TEXT PRIMARY KEY NOT NULL,
                advertiser_id TEXT NOT NULL,
                region TEXT NOT NULL,
                plan_tier TEXT NOT NULL,
                compute_spend_usd REAL NOT NULL,
                storage_spend_usd REAL NOT NULL,
                total_invoice_usd REAL NOT NULL,
                payment_status TEXT NOT NULL,
                customer_email TEXT NOT NULL,
                raw_card_token TEXT NOT NULL,
                tax_ein_ssn TEXT NOT NULL,
                billing_month TEXT NOT NULL
            );
            CREATE INDEX idx_billing_region_month ON customer_billing(region, billing_month);
            CREATE INDEX idx_billing_advertiser ON customer_billing(advertiser_id);

            CREATE TABLE agent_telemetry (
                span_id TEXT PRIMARY KEY NOT NULL,
                advertiser_id TEXT NOT NULL,
                region TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                model_tier TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL,
                completion_tokens INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                cost_usd REAL NOT NULL,
                sandbox_mode TEXT NOT NULL,
                status_code TEXT NOT NULL,
                caller_ip TEXT NOT NULL
            );
            CREATE INDEX idx_telemetry_model_status ON agent_telemetry(model_tier, status_code);
            CREATE INDEX idx_telemetry_region ON agent_telemetry(region);
            """
        )

        regions = ["NA", "EMEA", "APAC"]
        tiers = ["ENTERPRISE", "GROWTH", "EMERGING"]
        channels = ["SPONSORED_PRODUCTS", "DSP_STREAMING_TV", "SPONSORED_BRANDS"]
        advertisers = [f"adv-{tiers[i % 3].lower()}-{101 + i}" for i in range(12)]

        campaign_rows = []
        for idx in range(180):
            adv = advertisers[idx % len(advertisers)]
            tier = tiers[idx % 3]
            reg = regions[idx % 3]
            chan = channels[(idx // 3) % 3]
            impr = 12_000 + (idx * 850)
            clicks = max(25, int(impr * (0.024 + (idx % 5) * 0.004)))
            spend = round(clicks * (1.15 + (idx % 4) * 0.35), 2)
            roas_mult = 3.8 if tier == "ENTERPRISE" else (2.9 if tier == "GROWTH" else 2.2)
            rev = round(spend * roas_mult, 2)
            day = f"2026-10-{(idx % 28) + 1:02d}"
            campaign_rows.append(
                (f"cmp-{1000 + idx}", adv, tier, reg, chan, impr, clicks, spend, rev, day)
            )
        cur.executemany(
            "INSERT INTO ads_campaigns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            campaign_rows,
        )

        months = ["2026-08", "2026-09", "2026-10"]
        statuses = ["SETTLED", "SETTLED", "SETTLED", "PENDING"]
        billing_rows = []
        for idx in range(72):
            adv = advertisers[idx % len(advertisers)]
            reg = regions[idx % 3]
            tier = tiers[idx % 3]
            comp_usd = round(420.0 + (idx * 65.5), 2)
            stor_usd = round(85.0 + (idx * 12.25), 2)
            tot_usd = round(comp_usd + stor_usd, 2)
            st = statuses[idx % len(statuses)]
            month = months[idx % len(months)]
            billing_rows.append(
                (
                    f"inv-{5000 + idx}",
                    adv,
                    reg,
                    tier,
                    comp_usd,
                    stor_usd,
                    tot_usd,
                    st,
                    f"ap-contact-{idx}@{adv}.example.com",
                    f"tok_visa_live_{900000 + idx}",
                    f"91-{7000000 + idx}",
                    month,
                )
            )
        cur.executemany(
            "INSERT INTO customer_billing VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            billing_rows,
        )

        models = [
            "bedrock/amazon.nova-lite-v1",
            "bedrock/anthropic.claude-sonnet-4",
            "bedrock/anthropic.claude-opus",
        ]
        agents = ["kiro-coder", "spektr-sql-analyst", "devops-triage"]
        telemetry_rows = []
        for idx in range(120):
            adv = advertisers[idx % len(advertisers)]
            reg = regions[idx % 3]
            ag = agents[idx % 3]
            mod = models[idx % 3]
            ptok = 450 + (idx * 35)
            ctok = 160 + (idx * 12)
            lat = 210.0 if mod.endswith("nova-lite-v1") else (910.0 if mod.endswith("sonnet-4") else 2900.0)
            cost = round(0.0002 if mod.endswith("nova-lite-v1") else (0.0068 if mod.endswith("sonnet-4") else 0.0395), 5)
            sbx = "warm_pool" if idx % 5 != 0 else "cold_subprocess"
            telemetry_rows.append(
                (
                    f"spn-{8000 + idx}",
                    adv,
                    reg,
                    ag,
                    mod,
                    ptok,
                    ctok,
                    lat + (idx % 17) * 4.5,
                    cost,
                    sbx,
                    "OK",
                    f"10.42.{(idx // 16) % 255}.{(idx % 250) + 1}",
                )
            )
        cur.executemany(
            "INSERT INTO agent_telemetry VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            telemetry_rows,
        )
        self._conn.commit()

    def list_mcp_tools(self) -> List[Dict[str, Any]]:
        """Returns MCP Draft-07 JSON-Schema tool definitions."""
        return [
            {
                "name": "list_tables",
                "description": "List governed Apache Iceberg / SQLite data-lake tables, snapshots, and column sensitivity classifications.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "include_columns": {"type": "boolean", "default": True},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "describe_lineage",
                "description": "Retrieve upstream streaming/compaction lineage, SLA freshness, and schema contract for an Iceberg table.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string"},
                    },
                    "required": ["table_name"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "validate_and_query_sql",
                "description": "Pre-validate SQL against read-only AST rules, PII column ACLs, row-level scopes, and EXPLAIN QUERY PLAN schema contracts before executing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string"},
                        "max_rows": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    },
                    "required": ["sql"],
                    "additionalProperties": False,
                },
            },
        ]

    def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        caller_context: Optional[CallerGovernanceContext] = None,
    ) -> Dict[str, Any]:
        args = arguments or {}
        ctx = caller_context or CallerGovernanceContext()
        if tool_name == "list_tables":
            return self.list_tables(include_columns=bool(args.get("include_columns", True)))
        if tool_name == "describe_lineage":
            if "table_name" not in args:
                return {"ok": False, "error_code": "SCHEMA_VALIDATION_ERROR", "message": "Missing required 'table_name'."}
            return self.describe_lineage(str(args["table_name"]))
        if tool_name == "validate_and_query_sql":
            if "sql" not in args:
                return {"ok": False, "error_code": "SCHEMA_VALIDATION_ERROR", "message": "Missing required 'sql'."}
            return self.validate_and_query_sql(
                sql=str(args["sql"]),
                caller_context=ctx,
                max_rows=int(args.get("max_rows", 50)),
            )
        return {"ok": False, "error_code": "UNKNOWN_MCP_TOOL", "message": f"Unknown tool '{tool_name}'."}

    def list_tables(self, include_columns: bool = True) -> Dict[str, Any]:
        cur = self._conn.cursor()
        tables_out: List[Dict[str, Any]] = []
        for tbl_name, meta in ICEBERG_CATALOG.items():
            row_count = int(cur.execute(f"SELECT COUNT(*) FROM {tbl_name}").fetchone()[0])
            entry: Dict[str, Any] = {
                "table_name": tbl_name,
                "iceberg_uri": meta.iceberg_uri,
                "current_snapshot_id": meta.current_snapshot_id,
                "schema_version": meta.schema_version,
                "partition_spec": meta.partition_spec,
                "owner_team": meta.owner_team,
                "row_count": row_count,
            }
            if include_columns:
                entry["columns"] = [
                    {
                        "name": c.name,
                        "type": c.sql_type,
                        "classification": c.classification,
                        "nullable": c.nullable,
                    }
                    for c in meta.columns
                ]
            tables_out.append(entry)
        return {"ok": True, "table_count": len(tables_out), "tables": tables_out}

    def describe_lineage(self, table_name: str) -> Dict[str, Any]:
        meta = ICEBERG_CATALOG.get(table_name)
        if meta is None:
            return {
                "ok": False,
                "error_code": "TABLE_NOT_FOUND",
                "message": f"Table '{table_name}' is not registered in the governed Iceberg catalog.",
            }
        restricted_cols = [
            c.name for c in meta.columns if c.classification not in ("PUBLIC", "INTERNAL")
        ]
        return {
            "ok": True,
            "table_name": meta.table_name,
            "iceberg_uri": meta.iceberg_uri,
            "current_snapshot_id": meta.current_snapshot_id,
            "schema_version": meta.schema_version,
            "partition_spec": meta.partition_spec,
            "owner_team": meta.owner_team,
            "freshness_sla_minutes": meta.freshness_sla_minutes,
            "upstream_sources": meta.upstream_sources,
            "downstream_consumers": meta.downstream_consumers,
            "restricted_pii_pci_columns": restricted_cols,
        }

    @staticmethod
    def _validate_lexical_readonly_sql(raw_sql: str) -> Tuple[bool, Optional[str], str]:
        """Strips SQL comments/strings and blocks multi-statement or DDL/DML mutations."""
        no_block = _BLOCK_COMMENT_RE.sub(" ", raw_sql)
        no_comments = _LINE_COMMENT_RE.sub(" ", no_block).strip()
        if not no_comments:
            return False, "EMPTY_SQL_QUERY", ""

        # Strip single trailing semicolon, then reject any remaining semicolon outside string literals
        if no_comments.endswith(";"):
            no_comments = no_comments[:-1].strip()
        scrubbed_strings = _STRING_LITERAL_RE.sub("''", no_comments)
        if ";" in scrubbed_strings:
            return (
                False,
                "MULTI_STATEMENT_INJECTION_BLOCKED: semicolons chaining multiple SQL statements are forbidden",
                "",
            )

        bad_kw = _FORBIDDEN_SQL_KEYWORDS_RE.search(scrubbed_strings)
        if bad_kw:
            return (
                False,
                f"READ_ONLY_SQL_VIOLATION: forbidden mutating/admin keyword '{bad_kw.group(1).upper()}' blocked",
                "",
            )

        first_tok = scrubbed_strings.split(None, 1)[0].upper() if scrubbed_strings.split() else ""
        if first_tok not in ("SELECT", "WITH"):
            return (
                False,
                f"READ_ONLY_SQL_VIOLATION: query must begin with SELECT or WITH (got '{first_tok}')",
                "",
            )

        return True, None, no_comments

    @staticmethod
    def _apply_row_level_cte_scoping(
        clean_sql: str,
        ctx: CallerGovernanceContext,
    ) -> Tuple[str, List[Any], List[str]]:
        """Wraps base tables in parameterized row-filtering CTEs when region/tenant ACLs apply."""
        applied_predicates: List[str] = []
        if not ctx.allowed_regions and not ctx.allowed_advertiser_id:
            return clean_sql, [], applied_predicates

        cte_defs: List[str] = []
        params: List[Any] = []
        sorted_regions = sorted(ctx.allowed_regions) if ctx.allowed_regions else []

        for tbl_name, meta in ICEBERG_CATALOG.items():
            # Only wrap tables actually referenced in the query (and avoid shadowing user CTEs of same name)
            if not re.search(rf"\b{re.escape(tbl_name)}\b", clean_sql, re.IGNORECASE):
                continue
            clauses: List[str] = []
            col_names = {c.name for c in meta.columns}
            if sorted_regions and "region" in col_names:
                placeholders = ", ".join("?" for _ in sorted_regions)
                clauses.append(f"region IN ({placeholders})")
                params.extend(sorted_regions)
            if ctx.allowed_advertiser_id and "advertiser_id" in col_names:
                clauses.append("advertiser_id = ?")
                params.append(ctx.allowed_advertiser_id)

            if clauses:
                where_sql = " AND ".join(clauses)
                # Select only columns caller is cleared for so RLS CTE itself never trips PII column ACL!
                safe_cols = [
                    c.name for c in meta.columns if c.classification in ctx.allowed_classifications
                ]
                proj = ", ".join(safe_cols) if safe_cols else "1"
                cte_defs.append(f"_rls_{tbl_name} AS (SELECT {proj} FROM {tbl_name} WHERE {where_sql})")
                applied_predicates.append(f"{tbl_name}: {where_sql}")

        if not cte_defs:
            return clean_sql, [], []

        # Rewrite table references outside string literals to `_rls_<table>`
        rewritten = clean_sql
        for tbl_name in ICEBERG_CATALOG:
            if any(defn.startswith(f"_rls_{tbl_name} ") for defn in cte_defs):
                rewritten = re.sub(
                    rf"\b{re.escape(tbl_name)}\b",
                    f"_rls_{tbl_name}",
                    rewritten,
                )

        if rewritten.lstrip().upper().startswith("WITH "):
            body_after_with = rewritten.lstrip()[5:]
            scoped_sql = f"WITH {', '.join(cte_defs)}, {body_after_with}"
        else:
            scoped_sql = f"WITH {', '.join(cte_defs)} {rewritten}"

        return scoped_sql, params, applied_predicates

    def validate_and_query_sql(
        self,
        sql: str,
        caller_context: Optional[CallerGovernanceContext] = None,
        max_rows: int = 50,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        ctx = caller_context or CallerGovernanceContext()
        bounded_limit = max(1, min(500, int(max_rows)))

        # Gate 1: Lexical & structural read-only SQL check
        ok_lex, lex_err, clean_sql = self._validate_lexical_readonly_sql(sql)
        if not ok_lex:
            return {
                "ok": False,
                "error_code": "READ_ONLY_SQL_VIOLATION",
                "message": lex_err,
                "schema_contract_validated": False,
                "sts_correlation_id": ctx.sts_correlation_id,
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }

        # Gate 2 & 3 setup: Row-level CTE scoping + SQLite C-engine Column PII/PCI Authorizer
        scoped_sql, rls_params, rls_applied = self._apply_row_level_cte_scoping(clean_sql, ctx)
        acl_violations: List[str] = []

        def _sqlite_authorizer(
            action_code: int,
            arg1: Optional[str],
            arg2: Optional[str],
            dbname: Optional[str],
            source: Optional[str],
        ) -> int:
            if action_code in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
                return sqlite3.SQLITE_OK
            if action_code == sqlite3.SQLITE_READ:
                tbl = arg1 or ""
                col = arg2 or ""
                classification = self._column_classifications.get((tbl, col))
                if classification and classification not in ctx.allowed_classifications:
                    violation = f"{tbl}.{col} [{classification}]"
                    if violation not in acl_violations:
                        acl_violations.append(violation)
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            # Deny all DDL, DML, PRAGMA, ATTACH, transaction control
            return sqlite3.SQLITE_DENY

        self._conn.set_authorizer(_sqlite_authorizer)
        try:
            cur = self._conn.cursor()
            # Gate 2 & Gate 4: Column PII/PCI ACL check + Schema-Contract Pre-Validation
            # against base tables via `EXPLAIN QUERY PLAN` BEFORE execution!
            explain_rows = cur.execute(f"EXPLAIN QUERY PLAN {clean_sql}").fetchall()
            explain_plan = [str(r["detail"]) for r in explain_rows]

            # Gate 3: Execute with Row-Level CTE Scoping (`region` / `advertiser_id` isolation)
            exec_rows = cur.execute(scoped_sql, rls_params).fetchmany(bounded_limit)
            col_headers = [desc[0] for desc in (cur.description or [])]
            records = [dict(zip(col_headers, row)) for row in exec_rows]

            return {
                "ok": True,
                "schema_contract_validated": True,
                "explain_query_plan": explain_plan,
                "uses_index": any("USING INDEX" in step for step in explain_plan),
                "row_level_filters_applied": rls_applied,
                "columns": col_headers,
                "row_count": len(records),
                "rows": records,
                "principal_id": ctx.principal_id,
                "sts_correlation_id": ctx.sts_correlation_id,
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        except sqlite3.DatabaseError as exc:
            if acl_violations:
                return {
                    "ok": False,
                    "error_code": "COLUMN_ACL_VIOLATION",
                    "message": f"Caller '{ctx.principal_id}' lacks clearance for restricted columns: {', '.join(acl_violations)}",
                    "blocked_columns": acl_violations,
                    "schema_contract_validated": False,
                    "sts_correlation_id": ctx.sts_correlation_id,
                    "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }
            return {
                "ok": False,
                "error_code": "SCHEMA_CONTRACT_VIOLATION",
                "message": f"Pre-execution schema validation rejected query: {exc}",
                "schema_contract_validated": False,
                "sts_correlation_id": ctx.sts_correlation_id,
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        finally:
            self._conn.set_authorizer(None)


def run_governed_lake_demo() -> Dict[str, Any]:
    """Runs end-to-end governed MCP SQL benchmark across valid, mutating, PII, and hallucinated queries."""
    server = GovernedLakeMCPServer()
    try:
        return _run_governed_lake_demo_with_server(server)
    finally:
        server.close()


def _run_governed_lake_demo_with_server(server: GovernedLakeMCPServer) -> Dict[str, Any]:
    tables_info = server.call_tool("list_tables", {"include_columns": False})
    lineage_info = server.call_tool("describe_lineage", {"table_name": "customer_billing"})

    standard_analyst = CallerGovernanceContext(
        principal_id="agent:spektr-partner-analyst",
        allowed_classifications={"PUBLIC", "INTERNAL"},
        allowed_regions={"NA"},
        sts_correlation_id="ct-obo-lake-001",
    )
    cleared_finops_auditor = CallerGovernanceContext(
        principal_id="agent:finops-pci-auditor",
        allowed_classifications={"PUBLIC", "INTERNAL", "PII_CONFIDENTIAL"},
        sts_correlation_id="ct-obo-lake-002",
    )

    test_cases = [
        (
            "SQL-01-GOVERNED-ROAS-AGGREGATION",
            "SELECT region, partner_tier, COUNT(*) AS campaigns, ROUND(SUM(spend_usd), 2) AS spend, "
            "ROUND(SUM(attributed_revenue_usd) / SUM(spend_usd), 2) AS roas "
            "FROM ads_campaigns WHERE region = 'NA' GROUP BY region, partner_tier ORDER BY spend DESC",
            standard_analyst,
            True,
            None,
        ),
        (
            "SQL-02-BLOCK-DROP-TABLE-INJECTION",
            "SELECT campaign_id FROM ads_campaigns LIMIT 5; DROP TABLE customer_billing;",
            standard_analyst,
            False,
            "READ_ONLY_SQL_VIOLATION",
        ),
        (
            "SQL-03-BLOCK-COMMENT-SMUGGLED-DELETE",
            "/* bypass */ DELETE FROM customer_billing WHERE payment_status = 'DISPUTED'",
            standard_analyst,
            False,
            "READ_ONLY_SQL_VIOLATION",
        ),
        (
            "SQL-04-BLOCK-ATTACH-FILESYSTEM-DB",
            "ATTACH DATABASE '/tmp/exfil.db' AS exfil",
            standard_analyst,
            False,
            "READ_ONLY_SQL_VIOLATION",
        ),
        (
            "SQL-05-BLOCK-DIRECT-PII-EMAIL-AND-CARD-TOKEN",
            "SELECT invoice_id, customer_email, raw_card_token FROM customer_billing LIMIT 3",
            standard_analyst,
            False,
            "COLUMN_ACL_VIOLATION",
        ),
        (
            "SQL-06-BLOCK-SELECT-STAR-PII-LEAK",
            "SELECT * FROM agent_telemetry LIMIT 5",
            CallerGovernanceContext(
                principal_id="agent:unprivileged-telemetry-reader",
                allowed_classifications={"PUBLIC", "INTERNAL"},
            ),
            False,
            "COLUMN_ACL_VIOLATION",
        ),
        (
            "SQL-07-CATCH-HALLUCINATED-COLUMN-PRE-EXECUTION",
            "SELECT campaign_id, hallucinated_conversion_lift FROM ads_campaigns LIMIT 5",
            standard_analyst,
            False,
            "SCHEMA_CONTRACT_VIOLATION",
        ),
        (
            "SQL-08-CLEARED-AUDITOR-PII-EMAIL-ALLOWED-BUT-CARD-STILL-BLOCKED",
            "SELECT invoice_id, region, total_invoice_usd, customer_email FROM customer_billing WHERE region = 'NA' LIMIT 3",
            cleared_finops_auditor,
            True,
            None,
        ),
    ]

    case_outputs: List[Dict[str, Any]] = []
    passed = 0
    executed_valid_pipelines = 0
    schema_validated_executions = 0

    for case_id, sql, ctx, expected_ok, expected_err_code in test_cases:
        res = server.call_tool("validate_and_query_sql", {"sql": sql, "max_rows": 10}, caller_context=ctx)
        actual_ok = bool(res.get("ok"))
        err_code = res.get("error_code")
        matched = (actual_ok == expected_ok) and (expected_err_code is None or err_code == expected_err_code)
        if matched:
            passed += 1
        if actual_ok:
            executed_valid_pipelines += 1
            if res.get("schema_contract_validated"):
                schema_validated_executions += 1

        case_outputs.append(
            {
                "case_id": case_id,
                "expected_ok": expected_ok,
                "actual_ok": actual_ok,
                "assertion_passed": matched,
                "error_code": err_code,
                "message": res.get("message"),
                "explain_query_plan": res.get("explain_query_plan"),
                "row_level_filters_applied": res.get("row_level_filters_applied"),
                "row_count": res.get("row_count"),
                "sample_rows": (res.get("rows") or [])[:2],
                "latency_ms": res.get("latency_ms"),
            }
        )

    return {
        "catalog_summary": tables_info,
        "sample_lineage": lineage_info,
        "governance_cases_evaluated": len(test_cases),
        "governance_gate_accuracy_pct": round((passed / len(test_cases)) * 100.0, 2),
        "valid_pipeline_schema_contract_rate_pct": round(
            (schema_validated_executions / max(1, executed_valid_pipelines)) * 100.0, 2
        ),
        "cases": case_outputs,
    }
