"""Optional AWS Bedrock (`boto3`) & `strands-agents` SDK adapter stubs.

ForgeRuntime executes 100% out-of-the-box on Python 3.10+ stdlib with zero
external dependencies or cloud credentials. When deployed in an AWS account
with `pip install forge-runtime[aws]`, these adapters wire:
  1. `BedrockConverseRuntimeAdapter` -> `boto3.client("bedrock-runtime").converse(...)`
  2. `AWSSTSAssumeRoleAdapter`       -> `boto3.client("sts").assume_role(...)` with `TransitiveTagKeys`
  3. `StrandsToolRegistryAdapter`    -> `strands-agents` tool specifications
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


@dataclass(frozen=True)
class BedrockConversePayload:
    """Wire-compatible AWS Bedrock `converse()` API request envelope."""

    model_id: str
    messages: List[Dict[str, Any]]
    system: List[Dict[str, str]]
    inference_config: Dict[str, Any]

    def to_boto3_kwargs(self) -> Dict[str, Any]:
        return {
            "modelId": self.model_id,
            "messages": self.messages,
            "system": self.system,
            "inferenceConfig": self.inference_config,
        }


class BedrockConverseRuntimeAdapter:
    """Bridges `MultiModelRouter` decisions to AWS Bedrock `converse()`."""

    MODEL_ID_MAP: Dict[str, str] = {
        "bedrock/amazon.nova-lite-v1": "us.amazon.nova-lite-v1:0",
        "bedrock/anthropic.claude-sonnet-4": "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "bedrock/anthropic.claude-opus": "us.anthropic.claude-opus-4-20250514-v1:0",
    }

    def __init__(self, region_name: str = "us-west-2", boto3_client: Any = None) -> None:
        self.region_name = region_name
        self._client = boto3_client

    def build_converse_request(
        self,
        routed_tier: str,
        user_prompt: str,
        system_prompt: str = "You are ForgeRuntime, a governed coding and data-lake agent.",
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> BedrockConversePayload:
        bedrock_model_id = self.MODEL_ID_MAP.get(routed_tier, routed_tier)
        return BedrockConversePayload(
            model_id=bedrock_model_id,
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            system=[{"text": system_prompt}],
            inference_config={"maxTokens": max_tokens, "temperature": temperature},
        )

    def invoke_live(self, payload: BedrockConversePayload) -> Dict[str, Any]:
        """Invokes live AWS Bedrock if `boto3` is installed and configured."""
        client = self._client
        if client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:
                raise RuntimeError(
                    "Optional dependency 'boto3' is required for live AWS Bedrock calls. "
                    "Install via: pip install 'forge-runtime[aws]'"
                ) from exc
            client = boto3.client("bedrock-runtime", region_name=self.region_name)
        return dict(client.converse(**payload.to_boto3_kwargs()))


class AWSSTSAssumeRoleAdapter:
    """Maps `STSOnBehalfOfMinter` claims into AWS STS `assume_role` API parameters."""

    @staticmethod
    def to_boto3_assume_role_kwargs(sts_bundle: Dict[str, Any]) -> Dict[str, Any]:
        claims = sts_bundle["claims"]
        principal_tags = claims["PrincipalTags"]
        return {
            "RoleArn": claims["RoleArn"],
            "RoleSessionName": claims["RoleSessionName"],
            "DurationSeconds": int(claims["DurationSeconds"]),
            "SourceIdentity": claims["SourceIdentity"],
            "Tags": [
                {"Key": key.replace("PrincipalTag:", ""), "Value": str(val)}
                for key, val in principal_tags.items()
            ],
            "TransitiveTagKeys": list(claims["TransitiveTagKeys"]),
        }


class StrandsToolRegistryAdapter:
    """Exports `GovernedLakeMCPServer` tools as `strands-agents` compatible specs."""

    @staticmethod
    def export_tool_specs(mcp_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        specs: List[Dict[str, Any]] = []
        for tool in mcp_tools:
            specs.append(
                {
                    "toolSpec": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "inputSchema": {"json": tool["inputSchema"]},
                    }
                }
            )
        return specs

    @staticmethod
    def wrap_callable(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Attaches Strands metadata onto a Python callable without requiring strands-agents."""
        setattr(fn, "__strands_tool_name__", name)
        return fn
