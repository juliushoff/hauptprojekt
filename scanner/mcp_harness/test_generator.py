from __future__ import annotations

from typing import Any

from .models import TestInvocation, ToolMetadata


def generate_tests(tools: list[ToolMetadata], per_tool: int = 1) -> list[TestInvocation]:
    tests: list[TestInvocation] = []
    for tool in tools:
        args = sample_arguments(tool.input_schema)
        tests.append(TestInvocation(
            tool_name=tool.name,
            name="normal_use",
            arguments=args,
            intent="Exercise the tool with schema-valid placeholder arguments.",
        ))
        if per_tool > 1:
            tests.append(TestInvocation(
                tool_name=tool.name,
                name="empty_or_minimal",
                arguments={},
                intent="Check how the tool behaves with minimal arguments.",
            ))
    return tests


def sample_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict):
        return {}
    args: dict[str, Any] = {}
    fields = required if isinstance(required, list) and required else list(properties.keys())
    for name in fields:
        prop = properties.get(name, {})
        args[name] = sample_value(prop)
    return args


def sample_value(prop: dict[str, Any]) -> Any:
    if "default" in prop:
        return prop["default"]
    kind = prop.get("type", "string")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), "string")
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return True
    if kind == "array":
        return []
    if kind == "object":
        return {}
    title = str(prop.get("title") or prop.get("description") or "value").lower()
    if "path" in title or "file" in title:
        return "/sandbox/data/sample.txt"
    if "url" in title:
        return "https://example.com"
    if "query" in title or "search" in title:
        return "test query"
    return "test"
