from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Label = Literal["malicious", "benign", "unknown"]
Transport = Literal["stdio", "http"]
StdioFraming = Literal["headers", "jsonl", "headers-jsonl"]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class TargetConfig:
    id: str
    source: str
    label: Label
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    path: str | None = None
    cwd: str | None = None
    transport: Transport = "stdio"
    stdio_framing: StdioFraming = "headers"
    protocol_version: str = "2024-11-05"
    timeout_seconds: float = 30.0
    notes: str | None = None


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolContract:
    name: str
    declared_intent: str
    allowed_capabilities: list[str]
    forbidden_capabilities: list[str]
    confidence: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Contract:
    target_id: str
    source: str
    tools: list[ToolContract]
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TestInvocation:
    tool_name: str
    name: str
    arguments: dict[str, Any]
    intent: str


@dataclass(frozen=True)
class GeneratedTask:
    id: str
    user_task: str
    expected_tools: list[str]
    purpose: str
    risk_focus: str = "benign"
    generator_model: str | None = None


@dataclass(frozen=True)
class TraceEvent:
    kind: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentToolCall:
    tool_name: str
    arguments: dict[str, Any]
    call_id: str | None = None
    raw_function_name: str | None = None
    reason: str | None = None
    result: dict[str, Any] | None = None
    messages_before_call: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRunTrace:
    task_id: str
    user_task: str
    model: str
    messages_before_call: list[dict[str, Any]]
    selected_tool_calls: list[AgentToolCall]
    final_answer: str | None = None
    raw_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ScenarioContext:
    id: str
    user_task: str
    test_intent: str
    mode: Literal["direct", "agent"] = "direct"


@dataclass(frozen=True)
class AgentContext:
    visible_messages_before_call: list[dict[str, Any]]
    available_tools: list[dict[str, Any]]
    assistant_tool_call: dict[str, Any]
    final_answer: str | None = None


@dataclass(frozen=True)
class SandboxObservation:
    files_read: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    network_attempts: list[dict[str, Any]] = field(default_factory=list)
    process_spawns: list[dict[str, Any]] = field(default_factory=list)
    env_access: list[str] = field(default_factory=list)
    canary_hits: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuditPacket:
    call_id: str
    target_id: str
    scenario: ScenarioContext
    agent_context: AgentContext
    contract: ToolContract
    mcp_protocol: dict[str, Any]
    sandbox_observation: SandboxObservation
    trajectory: dict[str, Any]


@dataclass(frozen=True)
class AuditVerdict:
    verdict: Literal["upheld", "suspicious", "violation", "inconclusive"]
    severity: Severity | Literal["none"]
    violated_capabilities: list[str]
    reason: str
    missing_context: list[str]
    confidence: Literal["low", "medium", "high"]
    model: str | None = None
    call_id: str | None = None


@dataclass(frozen=True)
class RunAuditVerdict:
    verdict: Literal["upheld", "suspicious", "violation", "inconclusive"]
    severity: Severity | Literal["none"]
    violated_capabilities: list[str]
    reason: str
    missing_context: list[str]
    confidence: Literal["low", "medium", "high"]
    model: str | None = None
    target_id: str | None = None
    task_count: int = 0
    tool_call_count: int = 0


@dataclass(frozen=True)
class Finding:
    severity: Severity
    tool_name: str | None
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    target: TargetConfig
    tools: list[ToolMetadata]
    contract: Contract
    tests: list[TestInvocation]
    generated_tasks: list[GeneratedTask]
    trace: list[TraceEvent]
    findings: list[Finding]
    status: str
    agent_traces: list[AgentRunTrace] = field(default_factory=list)
    audit_packets: list[AuditPacket] = field(default_factory=list)
    audit_verdicts: list[AuditVerdict] = field(default_factory=list)
    run_audit_verdicts: list[RunAuditVerdict] = field(default_factory=list)
