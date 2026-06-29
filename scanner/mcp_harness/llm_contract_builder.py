from __future__ import annotations

from .llm_client import OpenAILlmClient
from .models import Contract, ToolContract, ToolMetadata


CONTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "tools": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "declared_intent": {"type": "string"},
                    "allowed_capabilities": {"type": "array", "items": {"type": "string"}},
                    "forbidden_capabilities": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "risk_notes": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "name",
                    "declared_intent",
                    "allowed_capabilities",
                    "forbidden_capabilities",
                    "confidence",
                    "risk_notes",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["tools"],
    "additionalProperties": False,
}


CONTRACT_INSTRUCTIONS = """You derive explicit capability contracts for MCP tools.
Use only the tool name, description, and JSON schema. Do not assume hidden implementation behavior.
Allowed capabilities describe what the tool appears allowed to do for normal use.
Forbidden capabilities describe important behavior that would violate that declared intent.
Prefer concrete capabilities such as filesystem.read:user_provided_paths, filesystem.write:user_provided_paths,
network.egress:declared_api, process.spawn, secrets.read, filesystem.read:home_directory.
Return strict JSON matching the schema."""


def build_contract_with_llm(
    target_id: str,
    source: str,
    tools: list[ToolMetadata],
    client: OpenAILlmClient,
) -> Contract:
    payload = {
        "target_id": target_id,
        "source": source,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            }
            for tool in tools
        ],
    }
    result = client.structured_response(
        instructions=CONTRACT_INSTRUCTIONS,
        payload=payload,
        schema_name="mcp_contract",
        schema=CONTRACT_SCHEMA,
    )
    contracts: list[ToolContract] = []
    for item in result["tools"]:
        contracts.append(ToolContract(
            name=item["name"],
            declared_intent=item["declared_intent"],
            allowed_capabilities=item["allowed_capabilities"],
            forbidden_capabilities=item["forbidden_capabilities"],
            confidence=item["confidence"],
            evidence={
                "source": "llm_tool_metadata",
                "model": client.model,
                "risk_notes": item["risk_notes"],
            },
        ))
    return Contract(
        target_id=target_id,
        source=source,
        tools=contracts,
        notes=[
            "Contract derived by an audit LLM from MCP tool metadata.",
            "This is an intent baseline, not proof of implementation behavior.",
        ],
    )
