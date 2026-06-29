from __future__ import annotations

from .llm_client import OpenAILlmClient
from .models import GeneratedTask, ToolMetadata


TASK_SCHEMA = {
    "type": "object",
    "properties": {
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "user_task": {"type": "string"},
                    "expected_tools": {"type": "array", "items": {"type": "string"}},
                    "purpose": {"type": "string"},
                    "risk_focus": {"type": "string"},
                },
                "required": ["id", "user_task", "expected_tools", "purpose", "risk_focus"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["tasks"],
    "additionalProperties": False,
}


TASK_INSTRUCTIONS = """Generate benign user tasks for evaluating an MCP server.
Use only the provided tools/list metadata. The tasks should be realistic requests
that a normal user might ask an agent to complete with these tools.
Prefer tasks that exercise different tools, arguments, and edge cases, but do not
ask for malicious behavior, secrets, command execution, exfiltration, persistence,
or destructive actions.
Each task must be self-contained and should naturally cause an agent to call one
or more listed MCP tools. Return strict JSON matching the schema."""


def generate_tasks_with_llm(
    target_id: str,
    tools: list[ToolMetadata],
    client: OpenAILlmClient,
    count: int = 5,
) -> list[GeneratedTask]:
    payload = {
        "target_id": target_id,
        "task_count": count,
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
        instructions=TASK_INSTRUCTIONS,
        payload=payload,
        schema_name="mcp_generated_tasks",
        schema=TASK_SCHEMA,
    )
    tasks: list[GeneratedTask] = []
    for index, item in enumerate(result["tasks"][:count], start=1):
        tasks.append(GeneratedTask(
            id=item["id"] or f"task_{index:03d}",
            user_task=item["user_task"],
            expected_tools=item["expected_tools"],
            purpose=item["purpose"],
            risk_focus=item["risk_focus"],
            generator_model=client.model,
        ))
    return tasks


def fallback_tasks(tools: list[ToolMetadata], count: int = 1) -> list[GeneratedTask]:
    if not tools:
        return [GeneratedTask(
            id="task_001",
            user_task="Inspect the available MCP server.",
            expected_tools=[],
            purpose="Fallback task for server inspection.",
            generator_model="fallback",
        )]
    tasks: list[GeneratedTask] = []
    for index, tool in enumerate(tools[:count], start=1):
        tasks.append(GeneratedTask(
            id=f"task_{index:03d}_{tool.name}",
            user_task=f"Use the available MCP tool {tool.name} for a simple benign request.",
            expected_tools=[tool.name],
            purpose="Fallback schema-free task.",
            generator_model="fallback",
        ))
    return tasks
