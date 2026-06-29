from __future__ import annotations

from .models import Contract, ToolContract, ToolMetadata


CAPABILITY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("filesystem.read", ("read file", "open file", "pdf", "document", "path", "load file")),
    ("filesystem.write", ("write file", "save", "create file", "edit file", "delete", "rename")),
    ("network.egress", ("search", "fetch", "http", "url", "api", "weather", "wikipedia", "web")),
    ("process.spawn", ("command", "shell", "terminal", "execute", "subprocess", "process")),
    ("secrets.read", ("token", "secret", "credential", "api key", "password")),
]

DEFAULT_FORBIDDEN = [
    "process.spawn",
    "secrets.read",
    "network.egress",
    "filesystem.write",
    "filesystem.read:outside_user_scope",
]


def build_contract(target_id: str, source: str, tools: list[ToolMetadata]) -> Contract:
    contracts = [build_tool_contract(tool) for tool in tools]
    return Contract(
        target_id=target_id,
        source=source,
        tools=contracts,
        notes=[
            "Initial contract is derived from tool metadata only.",
            "LLM-based intent extraction will replace or augment this deterministic baseline.",
        ],
    )


def build_tool_contract(tool: ToolMetadata) -> ToolContract:
    text = f"{tool.name} {tool.description} {_schema_text(tool.input_schema)}".lower()
    allowed: list[str] = []
    for capability, keywords in CAPABILITY_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            allowed.append(capability)
    if not allowed:
        allowed = ["pure.compute"]

    forbidden = [capability for capability in DEFAULT_FORBIDDEN if capability.split(":")[0] not in allowed]
    return ToolContract(
        name=tool.name,
        declared_intent=tool.description or f"Use the {tool.name} tool according to its schema.",
        allowed_capabilities=allowed,
        forbidden_capabilities=forbidden,
        confidence="low" if not tool.description else "medium",
        evidence={
            "source": "tool_metadata",
            "description_present": bool(tool.description),
            "schema_keys": sorted(tool.input_schema.keys()),
        },
    )


def _schema_text(schema: dict) -> str:
    parts: list[str] = []
    for key, value in schema.items():
        parts.append(str(key))
        if isinstance(value, dict):
            parts.extend(str(inner_key) for inner_key in value.keys())
            parts.extend(str(inner_value) for inner_value in value.values() if isinstance(inner_value, str))
        elif isinstance(value, str):
            parts.append(value)
    return " ".join(parts)
