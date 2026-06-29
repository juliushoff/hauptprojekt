from __future__ import annotations

import os
from pathlib import Path

from .agent_runner import OpenAIAgentRunner
from .audit_packet import build_audit_packets
from .checker import check_trace
from .contract_builder import build_contract
from .llm_auditor import audit_packets_with_llm, findings_from_audit_verdicts
from .llm_client import LlmClientError, LlmUnavailable, OpenAILlmClient
from .llm_contract_builder import build_contract_with_llm
from .mcp_client import McpClientError, McpSession
from .models import AgentRunTrace, AuditPacket, AuditVerdict, Contract, GeneratedTask, ScanResult, TargetConfig, ToolMetadata, TraceEvent
from .task_generator import fallback_tasks, generate_tasks_with_llm
from .test_generator import generate_tests


def inspect_target(target: TargetConfig, cwd: str | Path | None = None) -> tuple[list[ToolMetadata], list[TraceEvent]]:
    with McpSession(target, Path(cwd) if cwd else None) as session:
        session.initialize()
        tools = session.list_tools()
        return tools, list(session.trace)


def scan_target(
    target: TargetConfig,
    cwd: str | Path | None = None,
    execute_tests: bool = True,
    contract_mode: str = "llm",
    audit_mode: str = "llm",
    llm_model: str | None = None,
    contract_model: str | None = None,
    task_model: str | None = None,
    audit_model: str | None = None,
    audit_models: list[str] | None = None,
    run_mode: str = "agent",
    user_task: str | None = None,
    agent_model: str | None = None,
    max_agent_steps: int = 3,
    task_mode: str = "llm",
    task_count: int = 5,
) -> ScanResult:
    trace: list[TraceEvent] = []
    tools: list[ToolMetadata] = []
    contract = Contract(target_id=target.id, source=target.source, tools=[])
    tests = []
    generated_tasks = []
    audit_packets: list[AuditPacket] = []
    audit_verdicts: list[AuditVerdict] = []
    agent_traces: list[AgentRunTrace] = []
    findings = []
    status = "ok"

    try:
        with McpSession(target, Path(cwd) if cwd else None) as session:
            session.initialize()
            tools = session.list_tools()
            if contract_mode == "llm":
                contract = build_contract_with_llm(
                    target.id,
                    target.source,
                    tools,
                    OpenAILlmClient(model=contract_model or llm_model, role="contract"),
                )
            else:
                contract = build_contract(target.id, target.source, tools)
            tests = generate_tests(tools)
            if run_mode == "agent":
                if user_task:
                    generated_tasks = [GeneratedTask(
                        id="manual_task",
                        user_task=user_task,
                        expected_tools=[],
                        purpose="User-provided task.",
                    )]
                elif task_mode == "llm":
                    generated_tasks = generate_tasks_with_llm(
                        target.id,
                        tools,
                        OpenAILlmClient(model=task_model or llm_model, role="task"),
                        count=task_count,
                    )
                else:
                    generated_tasks = fallback_tasks(tools, count=task_count)
                agent_runner = OpenAIAgentRunner(
                    model=agent_model or llm_model,
                    max_steps=max_agent_steps,
                )
                for task in generated_tasks:
                    agent_traces.append(agent_runner.run(task.user_task, tools, session, task_id=task.id))
            elif execute_tests:
                for test in tests:
                    session.call_tool(test.tool_name, test.arguments)
            trace = list(session.trace)
            audit_packets = build_audit_packets(target.id, tools, contract, tests, trace, agent_traces=agent_traces)
            findings = check_trace(contract, trace)
            if audit_mode in {"llm", "hybrid"}:
                for model in resolve_audit_models(audit_models, audit_model, llm_model):
                    model_verdicts = audit_packets_with_llm(
                        audit_packets,
                        OpenAILlmClient(model=model, role="audit"),
                    )
                    audit_verdicts.extend(model_verdicts)
                    findings.extend(findings_from_audit_verdicts(audit_packets, model_verdicts))
            status = "contract_violation" if findings else "ok"
    except McpClientError as exc:
        status = "mcp_error"
        trace.append(TraceEvent("harness.error", str(exc)))
    except (LlmUnavailable, LlmClientError) as exc:
        status = "llm_error"
        trace.append(TraceEvent("llm.error", str(exc)))

    return ScanResult(
        target=target,
        tools=tools,
        contract=contract,
        tests=tests,
        generated_tasks=generated_tasks,
        trace=trace,
        agent_traces=agent_traces,
        audit_packets=audit_packets,
        audit_verdicts=audit_verdicts,
        findings=findings,
        status=status,
    )


def default_agent_task(tools: list[ToolMetadata]) -> str:
    if not tools:
        return "Inspect the available MCP server."
    return f"Use the available MCP tools to complete a simple benign task with {tools[0].name}."


def resolve_audit_models(
    audit_models: list[str] | None,
    audit_model: str | None,
    llm_model: str | None,
) -> list[str | None]:
    if audit_models:
        return audit_models
    env_models = parse_model_list(os.environ.get("OPENAI_AUDIT_MODELS"))
    if env_models:
        return env_models
    if audit_model:
        return [audit_model]
    if llm_model:
        return [llm_model]
    return [None]


def parse_model_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
