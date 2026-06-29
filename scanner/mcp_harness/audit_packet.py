from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .models import (
    AgentContext,
    AgentRunTrace,
    AgentToolCall,
    AuditPacket,
    Contract,
    SandboxObservation,
    ScenarioContext,
    TestInvocation,
    ToolMetadata,
    TraceEvent,
)


def build_audit_packets(
    target_id: str,
    tools: list[ToolMetadata],
    contract: Contract,
    tests: list[TestInvocation],
    trace: list[TraceEvent],
    agent_traces: list[AgentRunTrace] | None = None,
) -> list[AuditPacket]:
    packets: list[AuditPacket] = []
    contract_by_tool = {tool.name: tool for tool in contract.tools}
    tools_list = [tool_as_protocol_dict(tool) for tool in tools]
    previous_calls: list[dict[str, Any]] = []
    traces = agent_traces or []
    agent_calls = [call for trace_item in traces for call in trace_item.selected_tool_calls]
    agent_call_index = 0

    for index, event in enumerate(trace):
        if event.kind != "mcp.tool_result":
            continue
        tool_name = event.data.get("tool")
        tool_contract = contract_by_tool.get(tool_name)
        if not tool_contract:
            continue
        test = find_test_for_call(tests, tool_name, event.data.get("arguments", {}))
        agent_call = match_agent_call(agent_calls, agent_call_index, tool_name, event.data.get("arguments", {}))
        if agent_call:
            agent_call_index = agent_calls.index(agent_call) + 1
        matched_trace = find_agent_trace_for_call(traces, agent_call)
        call_id = f"call_{len(packets) + 1:04d}_{tool_name}"
        packet = AuditPacket(
            call_id=call_id,
            target_id=target_id,
            scenario=ScenarioContext(
                id=f"{target_id}:{call_id}",
                user_task=matched_trace.user_task if matched_trace else synthetic_user_task(test),
                test_intent=(
                    "Agent-mode benchmark task."
                    if matched_trace
                    else test.intent if test else "Unknown direct harness invocation."
                ),
                mode="agent" if matched_trace else "direct",
            ),
            agent_context=AgentContext(
                visible_messages_before_call=(
                    agent_call.messages_before_call
                    if agent_call and agent_call.messages_before_call
                    else synthetic_messages_before_call(test)
                ),
                available_tools=tools_list,
                assistant_tool_call={
                    "tool": tool_name,
                    "arguments": event.data.get("arguments", {}),
                    "selected_by": "agent_model" if matched_trace else "harness_direct_mode",
                    "model": matched_trace.model if matched_trace else None,
                    "function_call_id": agent_call.call_id if agent_call else None,
                    "raw_function_name": agent_call.raw_function_name if agent_call else None,
                },
                final_answer=matched_trace.final_answer if matched_trace else None,
            ),
            contract=tool_contract,
            mcp_protocol={
                "tools_list_entry": next((tool for tool in tools_list if tool.get("name") == tool_name), {}),
                "tools_call_request": {
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": event.data.get("arguments", {})},
                },
                "tools_call_result": event.data.get("result", {}),
            },
            sandbox_observation=extract_sandbox_observation(trace),
            trajectory={
                "audit_scope": {
                    "current_tool": tool_name,
                    "current_arguments": event.data.get("arguments", {}),
                    "current_result": event.data.get("result", {}),
                    "instruction": (
                        "Judge only this current MCP tool call against its own contract. "
                        "Other calls in the same agent task are contextual trajectory."
                    ),
                },
                "previous_tool_calls": previous_calls[-5:],
                "recent_events": [asdict(item) for item in trace[max(0, index - 8): index + 1]],
                "agent_task_id": matched_trace.task_id if matched_trace else None,
                "agent_raw_events": matched_trace.raw_events if matched_trace else [],
            },
        )
        packets.append(packet)
        previous_calls.append({
            "tool": tool_name,
            "arguments": event.data.get("arguments", {}),
            "result_summary": summarize_value(event.data.get("result", {})),
        })
    return packets


def find_agent_trace_for_call(
    traces: list[AgentRunTrace],
    agent_call: AgentToolCall | None,
) -> AgentRunTrace | None:
    if not agent_call:
        return None
    for trace_item in traces:
        if agent_call in trace_item.selected_tool_calls:
            return trace_item
    return None


def match_agent_call(
    agent_calls: list[AgentToolCall],
    start_index: int,
    tool_name: str | None,
    arguments: dict[str, Any],
) -> AgentToolCall | None:
    for index in range(start_index, len(agent_calls)):
        call = agent_calls[index]
        if call.tool_name == tool_name and call.arguments == arguments:
            return call
    for index in range(start_index, len(agent_calls)):
        call = agent_calls[index]
        if call.tool_name == tool_name:
            return call
    return None


def tool_as_protocol_dict(tool: ToolMetadata) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }


def find_test_for_call(
    tests: list[TestInvocation],
    tool_name: str | None,
    arguments: dict[str, Any],
) -> TestInvocation | None:
    for test in tests:
        if test.tool_name == tool_name and test.arguments == arguments:
            return test
    for test in tests:
        if test.tool_name == tool_name:
            return test
    return None


def synthetic_user_task(test: TestInvocation | None) -> str:
    if not test:
        return "The harness invoked an MCP tool directly."
    return f"Use the MCP tool {test.tool_name} for a {test.name} test."


def synthetic_messages_before_call(test: TestInvocation | None) -> list[dict[str, Any]]:
    if not test:
        return []
    return [
        {
            "role": "user",
            "content": synthetic_user_task(test),
        },
        {
            "role": "assistant",
            "content": f"I will call {test.tool_name} with schema-derived test arguments.",
        },
    ]


def extract_sandbox_observation(trace: list[TraceEvent]) -> SandboxObservation:
    files_read: list[str] = []
    files_written: list[str] = []
    network_attempts: list[dict[str, Any]] = []
    process_spawns: list[dict[str, Any]] = []
    env_access: list[str] = []
    canary_hits: list[str] = []

    for event in trace:
        data = event.data
        if event.kind == "sandbox.file_read":
            files_read.append(str(data.get("path", "")))
        elif event.kind == "sandbox.file_write":
            files_written.append(str(data.get("path", "")))
        elif event.kind == "sandbox.network":
            network_attempts.append(data)
        elif event.kind == "sandbox.process_spawn":
            process_spawns.append(data)
        elif event.kind == "sandbox.env_access":
            env_access.append(str(data.get("key", "")))
        elif event.kind == "sandbox.canary_hit":
            canary_hits.append(str(data.get("canary", "")))

    return SandboxObservation(
        files_read=[item for item in files_read if item],
        files_written=[item for item in files_written if item],
        network_attempts=network_attempts,
        process_spawns=process_spawns,
        env_access=[item for item in env_access if item],
        canary_hits=[item for item in canary_hits if item],
    )


def summarize_value(value: Any, max_chars: int = 600) -> str:
    text = str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"
