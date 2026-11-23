"""ForgeRuntime: Sandboxed Coding & Governed Data-Lake Agent Platform.

Core Pillars:
  1. `ast_graph`         — AST Repo Knowledge Graph & Minimal Context Packer (~5x–7x compression, 100% recall)
  2. `model_router`      — Complexity-, Token-, & SLA-Aware Multi-Model Bedrock Router
  3. `cedar_sts_gate`    — Deterministic Cedar Policy Evaluator (`forbid` wins), AWS STS OBO Minter & Warm Sandbox Pool
  4. `governed_lake_mcp` — Governed Apache Iceberg / SQLite MCP Server with Row/Column PII ACLs & Schema Pre-Validation
  5. `adapters`          — Optional `boto3` (Bedrock Converse + STS AssumeRole) & `strands-agents` tool adapters
"""

from .adapters import (
    AWSSTSAssumeRoleAdapter,
    BedrockConversePayload,
    BedrockConverseRuntimeAdapter,
    StrandsToolRegistryAdapter,
)
from .ast_graph import (
    ASTRepoGraph,
    ContextPackResult,
    GraphEdge,
    SymbolNode,
    build_reference_enterprise_repo,
    estimate_tokens,
    run_ast_graph_benchmark,
)
from .cedar_sts_gate import (
    CedarAuthorizationDecision,
    CedarPolicyEngine,
    CedarRequest,
    CedarSTSGate,
    ColdSubprocessExecutor,
    STSOnBehalfOfMinter,
    SandboxExecutionResult,
    SandboxSecurityScanner,
    SandboxSecurityViolation,
    WarmSandboxPool,
    run_cedar_sts_demo,
    run_sandbox_benchmark,
)
from .governed_lake_mcp import (
    CallerGovernanceContext,
    GovernedLakeMCPServer,
    ICEBERG_CATALOG,
    run_governed_lake_demo,
)
from .model_router import (
    CLAUDE_OPUS_ID,
    CLAUDE_SONNET_4_ID,
    CodingTaskRequest,
    MODEL_CATALOG,
    MultiModelRouter,
    NOVA_LITE_ID,
    RoutingDecision,
    run_model_router_benchmark,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ASTRepoGraph",
    "ContextPackResult",
    "GraphEdge",
    "SymbolNode",
    "build_reference_enterprise_repo",
    "estimate_tokens",
    "run_ast_graph_benchmark",
    "CodingTaskRequest",
    "MODEL_CATALOG",
    "MultiModelRouter",
    "NOVA_LITE_ID",
    "CLAUDE_SONNET_4_ID",
    "CLAUDE_OPUS_ID",
    "RoutingDecision",
    "run_model_router_benchmark",
    "CedarAuthorizationDecision",
    "CedarPolicyEngine",
    "CedarRequest",
    "CedarSTSGate",
    "STSOnBehalfOfMinter",
    "WarmSandboxPool",
    "ColdSubprocessExecutor",
    "SandboxSecurityScanner",
    "SandboxSecurityViolation",
    "SandboxExecutionResult",
    "run_cedar_sts_demo",
    "run_sandbox_benchmark",
    "CallerGovernanceContext",
    "GovernedLakeMCPServer",
    "ICEBERG_CATALOG",
    "run_governed_lake_demo",
    "BedrockConversePayload",
    "BedrockConverseRuntimeAdapter",
    "AWSSTSAssumeRoleAdapter",
    "StrandsToolRegistryAdapter",
]
