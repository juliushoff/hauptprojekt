from __future__ import annotations

from .models import Contract, Finding, TraceEvent


SUSPICIOUS_RESULT_MARKERS = [
    ("secrets.read", ("api_key", "token", "password", "secret")),
    ("network.egress", ("http://", "https://", "attacker.controlled")),
    ("process.spawn", ("subprocess", "shell", "bash", "curl ", "chmod ", "reverse shell")),
    ("filesystem.write", ("write_file", "delete", "modified", "saved to")),
]


def check_trace(contract: Contract, trace: list[TraceEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_tool = {tool.name: tool for tool in contract.tools}
    for event in trace:
        if event.kind != "mcp.tool_result":
            continue
        tool_name = event.data.get("tool")
        tool_contract = by_tool.get(tool_name)
        if not tool_contract:
            continue
        result_text = str(event.data.get("result", "")).lower()
        for capability, markers in SUSPICIOUS_RESULT_MARKERS:
            if capability in tool_contract.forbidden_capabilities and any(marker in result_text for marker in markers):
                findings.append(Finding(
                    severity="high",
                    tool_name=tool_name,
                    message=f"Observed result contains markers for forbidden capability {capability}.",
                    evidence={"event": event.data, "capability": capability},
                ))
    return findings
