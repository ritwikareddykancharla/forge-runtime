"""Complexity-, Token-, and SLA-Aware Multi-Model Router (`forge_runtime/model_router.py`).

Routes coding, SQL synthesis, and architectural refactoring workloads across three
AWS Bedrock foundation model tiers:
  1. `bedrock/amazon.nova-lite-v1`       — Fast AST search, lint fix, single-symbol explain (<350ms p95)
  2. `bedrock/anthropic.claude-sonnet-4` — Standard multi-line patch, governed SQL, test generation
  3. `bedrock/anthropic.claude-opus`     — Multi-file architectural refactor & security boundary design

Tracks exact per-call token cost, predicted p50/p95 latency, SLA/budget guardrail
downgrades, and cumulative savings vs. static single-model baselines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


NOVA_LITE_ID = "bedrock/amazon.nova-lite-v1"
CLAUDE_SONNET_4_ID = "bedrock/anthropic.claude-sonnet-4"
CLAUDE_OPUS_ID = "bedrock/anthropic.claude-opus"


@dataclass(frozen=True)
class ModelTierSpec:
    """Pricing and latency profile for a Bedrock foundation model tier."""

    model_id: str
    tier_label: str
    input_usd_per_1m: float
    output_usd_per_1m: float
    p50_latency_ms: float
    p95_latency_ms: float
    max_context_tokens: int

    def estimate_cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        in_cost = (max(0, input_tokens) / 1_000_000.0) * self.input_usd_per_1m
        out_cost = (max(0, output_tokens) / 1_000_000.0) * self.output_usd_per_1m
        return in_cost + out_cost


MODEL_CATALOG: Dict[str, ModelTierSpec] = {
    NOVA_LITE_ID: ModelTierSpec(
        model_id=NOVA_LITE_ID,
        tier_label="FAST_SEARCH_LINT",
        input_usd_per_1m=0.06,
        output_usd_per_1m=0.24,
        p50_latency_ms=195.0,
        p95_latency_ms=320.0,
        max_context_tokens=300_000,
    ),
    CLAUDE_SONNET_4_ID: ModelTierSpec(
        model_id=CLAUDE_SONNET_4_ID,
        tier_label="STANDARD_PATCH_SQL",
        input_usd_per_1m=3.00,
        output_usd_per_1m=15.00,
        p50_latency_ms=890.0,
        p95_latency_ms=1420.0,
        max_context_tokens=200_000,
    ),
    CLAUDE_OPUS_ID: ModelTierSpec(
        model_id=CLAUDE_OPUS_ID,
        tier_label="ARCHITECTURAL_REFACTOR",
        input_usd_per_1m=15.00,
        output_usd_per_1m=75.00,
        p50_latency_ms=2850.0,
        p95_latency_ms=4500.0,
        max_context_tokens=200_000,
    ),
}

_TIER_ORDER: List[str] = [NOVA_LITE_ID, CLAUDE_SONNET_4_ID, CLAUDE_OPUS_ID]

_LIGHT_KEYWORDS = (
    "lint",
    "format",
    "docstring",
    "symbol lookup",
    "find references",
    "rename local",
    "typo",
    "syntax check",
    "quick explain",
    "autocomplete",
)
_HEAVY_KEYWORDS = (
    "architectural",
    "multi-file refactor",
    "cross-module",
    "migration",
    "distributed lock",
    "race condition",
    "security boundary",
    "consensus",
    "redesign",
    "zero-downtime",
)
_MEDIUM_KEYWORDS = (
    "patch",
    "bugfix",
    "unit test",
    "sql",
    "iceberg",
    "cedar policy",
    "endpoint",
    "validation",
    "retry",
)


@dataclass(frozen=True)
class CodingTaskRequest:
    """Input task metadata for complexity-, token-, and SLA-aware routing."""

    task_id: str
    prompt: str
    input_tokens: int = 800
    expected_output_tokens: int = 350
    files_touched: int = 1
    ast_hop_depth: int = 1
    cyclomatic_complexity: int = 4
    sla_max_p95_ms: Optional[float] = None
    max_cost_usd: Optional[float] = None
    force_architectural_review: bool = False


@dataclass(frozen=True)
class RoutingDecision:
    """Deterministic model selection decision with cost/latency comparison."""

    task_id: str
    selected_model: str
    ideal_unconstrained_model: str
    tier_label: str
    complexity_score: float
    estimated_cost_usd: float
    opus_baseline_cost_usd: float
    sonnet_baseline_cost_usd: float
    predicted_p50_latency_ms: float
    predicted_p95_latency_ms: float
    sla_constrained: bool
    budget_constrained: bool
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "selected_model": self.selected_model,
            "ideal_unconstrained_model": self.ideal_unconstrained_model,
            "tier_label": self.tier_label,
            "complexity_score": round(self.complexity_score, 4),
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "opus_baseline_cost_usd": round(self.opus_baseline_cost_usd, 6),
            "sonnet_baseline_cost_usd": round(self.sonnet_baseline_cost_usd, 6),
            "predicted_p50_latency_ms": self.predicted_p50_latency_ms,
            "predicted_p95_latency_ms": self.predicted_p95_latency_ms,
            "sla_constrained": self.sla_constrained,
            "budget_constrained": self.budget_constrained,
            "rationale": self.rationale,
        }


class MultiModelRouter:
    """Complexity-, token-, and SLA-aware router across AWS Bedrock coding models."""

    def __init__(
        self,
        sonnet_threshold: float = 0.34,
        opus_threshold: float = 0.70,
    ) -> None:
        self.sonnet_threshold = sonnet_threshold
        self.opus_threshold = opus_threshold
        self.history: List[RoutingDecision] = []

    def compute_complexity_score(self, req: CodingTaskRequest) -> float:
        """Computes bounded [0.0, 1.0] task complexity from structural & lexical features."""
        if req.force_architectural_review:
            return 0.95

        prompt_lower = req.prompt.lower()

        # Structural AST & repo scope signals
        file_score = min(1.0, max(0, req.files_touched - 1) / 4.0)
        hop_score = min(1.0, max(0, req.ast_hop_depth) / 3.0)
        cc_score = min(1.0, max(0, req.cyclomatic_complexity - 2) / 16.0)
        token_score = min(1.0, req.input_tokens / 6000.0)

        # Lexical task-intent score
        intent_score = 0.42
        if any(kw in prompt_lower for kw in _HEAVY_KEYWORDS):
            intent_score = 0.90
        elif any(kw in prompt_lower for kw in _LIGHT_KEYWORDS):
            intent_score = 0.08
        elif any(kw in prompt_lower for kw in _MEDIUM_KEYWORDS):
            intent_score = 0.48

        weighted = (
            0.36 * intent_score
            + 0.24 * file_score
            + 0.16 * cc_score
            + 0.14 * hop_score
            + 0.10 * token_score
        )
        return max(0.0, min(1.0, weighted))

    def route(self, req: CodingTaskRequest) -> RoutingDecision:
        score = self.compute_complexity_score(req)

        if score >= self.opus_threshold:
            ideal_idx = 2
            reasons = [f"high complexity ({score:.2f} >= {self.opus_threshold:.2f})"]
        elif score >= self.sonnet_threshold:
            ideal_idx = 1
            reasons = [f"moderate complexity ({score:.2f} in [{self.sonnet_threshold:.2f}, {self.opus_threshold:.2f}))"]
        else:
            ideal_idx = 0
            reasons = [f"low complexity ({score:.2f} < {self.sonnet_threshold:.2f})"]

        chosen_idx = ideal_idx
        sla_constrained = False
        budget_constrained = False

        # Enforce hard p95 latency SLA cap if provided
        if req.sla_max_p95_ms is not None:
            while (
                chosen_idx > 0
                and MODEL_CATALOG[_TIER_ORDER[chosen_idx]].p95_latency_ms > req.sla_max_p95_ms
            ):
                chosen_idx -= 1
                sla_constrained = True
            if sla_constrained:
                reasons.append(f"SLA cap ({req.sla_max_p95_ms:.0f}ms p95) downgraded tier")

        # Enforce hard per-request USD budget cap if provided
        if req.max_cost_usd is not None:
            while (
                chosen_idx > 0
                and MODEL_CATALOG[_TIER_ORDER[chosen_idx]].estimate_cost_usd(
                    req.input_tokens, req.expected_output_tokens
                )
                > req.max_cost_usd
            ):
                chosen_idx -= 1
                budget_constrained = True
            if budget_constrained:
                reasons.append(f"budget cap (${req.max_cost_usd:.4f}) downgraded tier")

        chosen_spec = MODEL_CATALOG[_TIER_ORDER[chosen_idx]]
        ideal_model = _TIER_ORDER[ideal_idx]
        est_cost = chosen_spec.estimate_cost_usd(req.input_tokens, req.expected_output_tokens)
        opus_cost = MODEL_CATALOG[CLAUDE_OPUS_ID].estimate_cost_usd(
            req.input_tokens, req.expected_output_tokens
        )
        sonnet_cost = MODEL_CATALOG[CLAUDE_SONNET_4_ID].estimate_cost_usd(
            req.input_tokens, req.expected_output_tokens
        )

        decision = RoutingDecision(
            task_id=req.task_id,
            selected_model=chosen_spec.model_id,
            ideal_unconstrained_model=ideal_model,
            tier_label=chosen_spec.tier_label,
            complexity_score=score,
            estimated_cost_usd=est_cost,
            opus_baseline_cost_usd=opus_cost,
            sonnet_baseline_cost_usd=sonnet_cost,
            predicted_p50_latency_ms=chosen_spec.p50_latency_ms,
            predicted_p95_latency_ms=chosen_spec.p95_latency_ms,
            sla_constrained=sla_constrained,
            budget_constrained=budget_constrained,
            rationale="; ".join(reasons),
        )
        self.history.append(decision)
        return decision

    def telemetry_summary(self) -> Dict[str, Any]:
        if not self.history:
            return {"total_requests": 0}

        n = len(self.history)
        total_routed_cost = sum(d.estimated_cost_usd for d in self.history)
        total_opus_cost = sum(d.opus_baseline_cost_usd for d in self.history)
        total_sonnet_cost = sum(d.sonnet_baseline_cost_usd for d in self.history)

        mean_p50 = sum(d.predicted_p50_latency_ms for d in self.history) / n
        mean_p95 = sum(d.predicted_p95_latency_ms for d in self.history) / n
        opus_p50 = MODEL_CATALOG[CLAUDE_OPUS_ID].p50_latency_ms

        tier_counts: Dict[str, int] = {m: 0 for m in _TIER_ORDER}
        for d in self.history:
            tier_counts[d.selected_model] = tier_counts.get(d.selected_model, 0) + 1

        cost_savings_vs_opus_pct = (
            ((total_opus_cost - total_routed_cost) / total_opus_cost) * 100.0
            if total_opus_cost > 0
            else 0.0
        )
        latency_reduction_vs_opus_pct = ((opus_p50 - mean_p50) / opus_p50) * 100.0

        return {
            "total_requests": n,
            "tier_distribution": tier_counts,
            "total_routed_cost_usd": round(total_routed_cost, 6),
            "static_opus_cost_usd": round(total_opus_cost, 6),
            "static_sonnet_cost_usd": round(total_sonnet_cost, 6),
            "cost_savings_vs_opus_pct": round(cost_savings_vs_opus_pct, 2),
            "mean_predicted_p50_latency_ms": round(mean_p50, 1),
            "mean_predicted_p95_latency_ms": round(mean_p95, 1),
            "latency_reduction_vs_opus_pct": round(latency_reduction_vs_opus_pct, 2),
            "sla_downgrade_count": sum(1 for d in self.history if d.sla_constrained),
            "budget_downgrade_count": sum(1 for d in self.history if d.budget_constrained),
        }


def build_reference_routing_workload() -> List[ Tuple[CodingTaskRequest, str] ]:
    """12 representative coding/data-lake tasks with expected optimal Bedrock model tier."""
    return [
        (
            CodingTaskRequest(
                task_id="TASK-01",
                prompt="Symbol lookup and quick explain for TenantQuotaGuard.verify_spend_ceiling",
                input_tokens=420,
                expected_output_tokens=140,
                files_touched=1,
                ast_hop_depth=0,
                cyclomatic_complexity=2,
            ),
            NOVA_LITE_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-02",
                prompt="Lint and format docstring headers on LedgerPosting dataclass",
                input_tokens=310,
                expected_output_tokens=110,
                files_touched=1,
                ast_hop_depth=0,
                cyclomatic_complexity=1,
            ),
            NOVA_LITE_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-03",
                prompt="Syntax check and rename local loop counter in FinOpsVarianceAnalyzer",
                input_tokens=500,
                expected_output_tokens=150,
                files_touched=1,
                ast_hop_depth=1,
                cyclomatic_complexity=3,
            ),
            NOVA_LITE_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-04",
                prompt="Autocomplete inline type hint on drain_audit_buffer under strict IDE SLA",
                input_tokens=600,
                expected_output_tokens=90,
                files_touched=2,
                ast_hop_depth=2,
                cyclomatic_complexity=7,
                sla_max_p95_ms=350.0,  # Hard interactive IDE SLA forces Nova Lite
            ),
            NOVA_LITE_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-05",
                prompt="Write governed Iceberg SQL query aggregating ROAS by region and partner_tier",
                input_tokens=1150,
                expected_output_tokens=380,
                files_touched=2,
                ast_hop_depth=2,
                cyclomatic_complexity=6,
            ),
            CLAUDE_SONNET_4_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-06",
                prompt="Implement bugfix patch and unit test for WebhookSignatureVerifier replay skew",
                input_tokens=1400,
                expected_output_tokens=520,
                files_touched=2,
                ast_hop_depth=2,
                cyclomatic_complexity=8,
            ),
            CLAUDE_SONNET_4_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-07",
                prompt="Author Cedar policy rule blocking unapproved prod table mutations",
                input_tokens=980,
                expected_output_tokens=320,
                files_touched=2,
                ast_hop_depth=1,
                cyclomatic_complexity=7,
            ),
            CLAUDE_SONNET_4_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-08",
                prompt="Add retry backoff validation endpoint and unit test suite for PartnerBillingGateway",
                input_tokens=1650,
                expected_output_tokens=610,
                files_touched=2,
                ast_hop_depth=2,
                cyclomatic_complexity=9,
            ),
            CLAUDE_SONNET_4_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-09",
                prompt="Cross-module architectural refactor of settlement engine for zero-downtime ledger sharding",
                input_tokens=4800,
                expected_output_tokens=1600,
                files_touched=5,
                ast_hop_depth=3,
                cyclomatic_complexity=17,
            ),
            CLAUDE_OPUS_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-10",
                prompt="Redesign security boundary and STS On-Behalf-Of transitive session tag propagation across 4 modules",
                input_tokens=4200,
                expected_output_tokens=1450,
                files_touched=4,
                ast_hop_depth=3,
                cyclomatic_complexity=15,
            ),
            CLAUDE_OPUS_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-11",
                prompt="Diagnose distributed lock race condition across multi-file refactor in async worker pool",
                input_tokens=5100,
                expected_output_tokens=1300,
                files_touched=5,
                ast_hop_depth=3,
                cyclomatic_complexity=18,
            ),
            CLAUDE_OPUS_ID,
        ),
        (
            CodingTaskRequest(
                task_id="TASK-12",
                prompt="Multi-file refactor of telemetry pipeline under 1500ms interactive SLA guardrail",
                input_tokens=3900,
                expected_output_tokens=950,
                files_touched=4,
                ast_hop_depth=3,
                cyclomatic_complexity=14,
                sla_max_p95_ms=1500.0,  # Architectural complexity downgraded from Opus -> Sonnet-4 by SLA!
            ),
            CLAUDE_SONNET_4_ID,
        ),
    ]


def run_model_router_benchmark() -> Dict[str, Any]:
    router = MultiModelRouter()
    workload = build_reference_routing_workload()
    decisions_out: List[Dict[str, Any]] = []
    exact_matches = 0

    for req, expected_model in workload:
        dec = router.route(req)
        matched = dec.selected_model == expected_model
        if matched:
            exact_matches += 1
        row = dec.to_dict()
        row["expected_model"] = expected_model
        row["tier_match"] = matched
        decisions_out.append(row)

    summary = router.telemetry_summary()
    summary["tier_routing_accuracy_pct"] = round((exact_matches / len(workload)) * 100.0, 2)
    return {
        "summary": summary,
        "decisions": decisions_out,
    }
