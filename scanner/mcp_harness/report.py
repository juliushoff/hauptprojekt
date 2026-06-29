from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import ScanResult


def write_result(result: ScanResult, out_dir: str | Path) -> Path:
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    _write_json(path / "target.json", asdict(result.target))
    _write_json(path / "tools.json", [asdict(tool) for tool in result.tools])
    _write_json(path / "contract.json", asdict(result.contract))
    _write_json(path / "tests.json", [asdict(test) for test in result.tests])
    _write_json(path / "generated_tasks.json", [asdict(task) for task in result.generated_tasks])
    _write_jsonl(path / "trace.jsonl", [asdict(event) for event in result.trace])
    if result.agent_traces:
        _write_json(path / "agent_traces.json", [asdict(trace) for trace in result.agent_traces])
    _write_json(path / "audit_packets.json", [asdict(packet) for packet in result.audit_packets])
    _write_json(path / "audit_verdicts.json", [asdict(verdict) for verdict in result.audit_verdicts])
    _write_json(path / "run_audit_verdicts.json", [asdict(verdict) for verdict in result.run_audit_verdicts])
    _write_json(path / "audit_matrix.json", audit_matrix_rows(result))
    _write_audit_matrix_csv(path / "audit_matrix.csv", audit_matrix_rows(result))
    _write_json(path / "run_audit_matrix.json", run_audit_matrix_rows(result))
    _write_run_audit_matrix_csv(path / "run_audit_matrix.csv", run_audit_matrix_rows(result))
    _write_json(path / "verdict.json", {
        "status": result.status,
        "finding_count": len(result.findings),
        "findings": [asdict(finding) for finding in result.findings],
        "run_audit_verdicts": [asdict(verdict) for verdict in result.run_audit_verdicts],
    })
    _write_markdown(path / "report.md", result)
    return path


def write_summary(results: list[ScanResult], out_dir: str | Path) -> None:
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    with (path / "summary.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "source", "label", "status", "tools", "findings"])
        writer.writeheader()
        for result in results:
            writer.writerow({
                "id": result.target.id,
                "source": result.target.source,
                "label": result.target.label,
                "status": result.status,
                "tools": len(result.tools),
                "findings": len(result.findings),
            })
    write_run_report(results, path)
    write_run_events_csv(results, path)


def write_run_report(results: list[ScanResult], out_dir: str | Path) -> None:
    path = Path(out_dir)
    lines = [
        "# MCP Benchmark Run Report",
        "",
        "## Summary",
        "",
        "| Target | Label | Status | Tools | Tasks | MCP Calls | Findings |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for result in results:
        lines.append(
            f"| `{result.target.id}` | `{result.target.label}` | `{result.status}` | "
            f"{len(result.tools)} | {len(result.generated_tasks)} | "
            f"{len(result.audit_packets)} | {len(result.findings)} |"
        )

    for result in results:
        lines.extend([
            "",
            f"## Target: {result.target.id}",
            "",
            f"- Source: `{result.target.source}`",
            f"- Label: `{result.target.label}`",
            f"- Status: `{result.status}`",
            f"- Notes: {result.target.notes or '-'}",
            f"- Report: `targets/{result.target.id}/report.md`",
            "",
            "### Tools",
            "",
        ])
        for tool in result.tools:
            lines.append(f"- `{tool.name}`: {one_line(tool.description)}")

        lines.extend(["", "### Generated Tasks And Calls", ""])
        for trace in result.agent_traces:
            lines.extend([
                f"#### {trace.task_id}",
                "",
                f"- User task: {trace.user_task}",
                f"- Agent model: `{trace.model}`",
            ])
            if not trace.selected_tool_calls:
                lines.append("- MCP calls: none")
            for call in trace.selected_tool_calls:
                lines.extend([
                    f"- MCP call `{call.call_id or '-'}`: `{call.tool_name}`",
                    f"  - Arguments: `{json.dumps(call.arguments, sort_keys=True)}`",
                    f"  - MCP result: `{summarize_result(call.result)}`",
                ])
                verdicts = verdicts_for_call(result, call.call_id)
                if verdicts:
                    lines.append("  - Audit verdicts:")
                    for verdict in verdicts:
                        lines.append(
                            f"    - `{verdict.model}`: `{verdict.verdict}` "
                            f"`{verdict.severity}` ({verdict.confidence}) - {one_line(verdict.reason, 220)}"
                        )
            if trace.final_answer:
                lines.append(f"- Agent final answer: {trace.final_answer}")
            lines.append("")

        if result.findings:
            lines.extend(["### Findings", ""])
            for finding in result.findings:
                lines.append(f"- `{finding.severity}` {finding.tool_name or '-'}: {finding.message}")
        else:
            lines.extend(["### Findings", "", "No findings."])

    (path / "run_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_run_events_csv(results: list[ScanResult], out_dir: str | Path) -> None:
    path = Path(out_dir)
    with (path / "events.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "target_id",
                "label",
                "status",
                "task_id",
                "user_task",
                "agent_model",
                "tool_call_id",
                "tool_name",
                "arguments",
                "mcp_result",
                "audit_model",
                "audit_verdict",
                "audit_severity",
                "audit_confidence",
                "audit_reason",
            ],
        )
        writer.writeheader()
        for result in results:
            for trace in result.agent_traces:
                for call in trace.selected_tool_calls:
                    verdicts = verdicts_for_call(result, call.call_id)
                    if not verdicts:
                        writer.writerow(event_row(result, trace, call, None))
                    for verdict in verdicts:
                        writer.writerow(event_row(result, trace, call, verdict))


def write_run_report_from_disk(run_dir: str | Path) -> None:
    path = Path(run_dir)
    target_dirs = sorted((path / "targets").glob("*"))
    target_records = [load_target_record(target_dir) for target_dir in target_dirs if target_dir.is_dir()]
    write_disk_summary(target_records, path)
    write_disk_run_report(target_records, path)
    write_disk_events_csv(target_records, path)


def load_target_record(target_dir: Path) -> dict[str, Any]:
    return {
        "dir": target_dir,
        "target": read_json_if_exists(target_dir / "target.json", {}),
        "tools": read_json_if_exists(target_dir / "tools.json", []),
        "generated_tasks": read_json_if_exists(target_dir / "generated_tasks.json", []),
        "agent_traces": read_json_if_exists(target_dir / "agent_traces.json", []),
        "audit_packets": read_json_if_exists(target_dir / "audit_packets.json", []),
        "audit_verdicts": read_json_if_exists(target_dir / "audit_verdicts.json", []),
        "run_audit_verdicts": read_json_if_exists(target_dir / "run_audit_verdicts.json", []),
        "verdict": read_json_if_exists(target_dir / "verdict.json", {}),
    }


def write_disk_summary(records: list[dict[str, Any]], out_dir: Path) -> None:
    with (out_dir / "summary.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "source", "label", "status", "tools", "findings"])
        writer.writeheader()
        for record in records:
            target = record["target"]
            verdict = record["verdict"]
            writer.writerow({
                "id": target.get("id", record["dir"].name),
                "source": target.get("source", ""),
                "label": target.get("label", ""),
                "status": verdict.get("status", ""),
                "tools": len(record["tools"]),
                "findings": verdict.get("finding_count", 0),
            })


def write_disk_run_report(records: list[dict[str, Any]], out_dir: Path) -> None:
    lines = [
        "# MCP Benchmark Run Report",
        "",
        "## Summary",
        "",
        "| Target | Label | Status | Tools | Tasks | MCP Calls | Run Verdicts | Findings |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for record in records:
        target = record["target"]
        verdict = record["verdict"]
        lines.append(
            f"| `{target.get('id', record['dir'].name)}` | `{target.get('label', '')}` | "
            f"`{verdict.get('status', '')}` | {len(record['tools'])} | "
            f"{len(record['generated_tasks'])} | {len(record['audit_packets'])} | "
            f"{len(record['run_audit_verdicts'])} | "
            f"{verdict.get('finding_count', 0)} |"
        )
    for record in records:
        append_disk_target_report(lines, record)
    (out_dir / "run_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_disk_target_report(lines: list[str], record: dict[str, Any]) -> None:
    target = record["target"]
    verdict = record["verdict"]
    target_id = target.get("id", record["dir"].name)
    lines.extend([
        "",
        f"## Target: {target_id}",
        "",
        f"- Source: `{target.get('source', '')}`",
        f"- Label: `{target.get('label', '')}`",
        f"- Status: `{verdict.get('status', '')}`",
        f"- Notes: {target.get('notes') or '-'}",
        f"- Report: `targets/{target_id}/report.md`",
        "",
        "### Tools",
        "",
    ])
    for tool in record["tools"]:
        lines.append(f"- `{tool.get('name', '')}`: {one_line(tool.get('description', ''))}")
    if record["run_audit_verdicts"]:
        lines.extend(["", "### Run-Level Audit Verdicts", ""])
        for audit in record["run_audit_verdicts"]:
            lines.append(
                f"- `{audit.get('model', '-')}`: `{audit.get('verdict', '-')}` "
                f"`{audit.get('severity', '-')}` ({audit.get('confidence', '-')}) - "
                f"{one_line(audit.get('reason', ''), 260)}"
            )
    lines.extend(["", "### Generated Tasks And Calls", ""])
    verdicts_by_packet = group_disk_verdicts_by_packet(record["audit_verdicts"])
    packet_by_function_call = {
        packet.get("agent_context", {}).get("assistant_tool_call", {}).get("function_call_id"): packet
        for packet in record["audit_packets"]
    }
    for trace in record["agent_traces"]:
        lines.extend([
            f"#### {trace.get('task_id', '-')}",
            "",
            f"- User task: {trace.get('user_task', '-')}",
            f"- Agent model: `{trace.get('model', '-')}`",
        ])
        for call in trace.get("selected_tool_calls", []):
            packet = packet_by_function_call.get(call.get("call_id"))
            packet_id = packet.get("call_id") if packet else None
            lines.extend([
                f"- MCP call `{call.get('call_id') or '-'}`: `{call.get('tool_name', '-')}`",
                f"  - Arguments: `{json.dumps(call.get('arguments', {}), sort_keys=True)}`",
                f"  - MCP result: `{summarize_result(call.get('result'))}`",
            ])
            packet_verdicts = verdicts_by_packet.get(packet_id or "", [])
            if packet_verdicts:
                lines.append("  - Audit verdicts:")
                for audit in packet_verdicts:
                    lines.append(
                        f"    - `{audit.get('model', '-')}`: `{audit.get('verdict', '-')}` "
                        f"`{audit.get('severity', '-')}` ({audit.get('confidence', '-')}) - "
                        f"{one_line(audit.get('reason', ''), 220)}"
                    )
        if trace.get("final_answer"):
            lines.append(f"- Agent final answer: {trace['final_answer']}")
        lines.append("")
    findings = verdict.get("findings", [])
    if findings:
        lines.extend(["### Findings", ""])
        for finding in findings:
            lines.append(f"- `{finding.get('severity', '-')}` {finding.get('tool_name') or '-'}: {finding.get('message', '')}")
    else:
        lines.extend(["### Findings", "", "No findings."])


def write_disk_events_csv(records: list[dict[str, Any]], out_dir: Path) -> None:
    with (out_dir / "events.csv").open("w", encoding="utf-8", newline="") as fh:
        fieldnames = [
            "target_id",
            "label",
            "status",
            "task_id",
            "user_task",
            "agent_model",
            "tool_call_id",
            "tool_name",
            "arguments",
            "mcp_result",
            "audit_model",
            "audit_verdict",
            "audit_severity",
            "audit_confidence",
            "audit_reason",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            target = record["target"]
            status = record["verdict"].get("status", "")
            verdicts_by_packet = group_disk_verdicts_by_packet(record["audit_verdicts"])
            packet_by_function_call = {
                packet.get("agent_context", {}).get("assistant_tool_call", {}).get("function_call_id"): packet
                for packet in record["audit_packets"]
            }
            for trace in record["agent_traces"]:
                for call in trace.get("selected_tool_calls", []):
                    packet = packet_by_function_call.get(call.get("call_id"))
                    packet_verdicts = verdicts_by_packet.get(packet.get("call_id") if packet else "", [])
                    for audit in packet_verdicts or [{}]:
                        writer.writerow({
                            "target_id": target.get("id", record["dir"].name),
                            "label": target.get("label", ""),
                            "status": status,
                            "task_id": trace.get("task_id", ""),
                            "user_task": trace.get("user_task", ""),
                            "agent_model": trace.get("model", ""),
                            "tool_call_id": call.get("call_id", ""),
                            "tool_name": call.get("tool_name", ""),
                            "arguments": json.dumps(call.get("arguments", {}), sort_keys=True),
                            "mcp_result": summarize_result(call.get("result"), max_chars=500),
                            "audit_model": audit.get("model", ""),
                            "audit_verdict": audit.get("verdict", ""),
                            "audit_severity": audit.get("severity", ""),
                            "audit_confidence": audit.get("confidence", ""),
                            "audit_reason": audit.get("reason", ""),
                        })


def group_disk_verdicts_by_packet(verdicts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for verdict in verdicts:
        grouped.setdefault(verdict.get("call_id", ""), []).append(verdict)
    return grouped


def read_json_if_exists(path: Path, fallback):
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def audit_matrix_rows(result: ScanResult) -> list[dict]:
    tool_by_call_id = {packet.call_id: packet.contract.name for packet in result.audit_packets}
    rows = []
    for verdict in result.audit_verdicts:
        rows.append({
            "model": verdict.model,
            "call_id": verdict.call_id,
            "tool": tool_by_call_id.get(verdict.call_id or ""),
            "verdict": verdict.verdict,
            "severity": verdict.severity,
            "confidence": verdict.confidence,
            "violated_capabilities": verdict.violated_capabilities,
            "reason": verdict.reason,
        })
    return rows


def run_audit_matrix_rows(result: ScanResult) -> list[dict]:
    return [
        {
            "model": verdict.model,
            "target_id": verdict.target_id or result.target.id,
            "verdict": verdict.verdict,
            "severity": verdict.severity,
            "confidence": verdict.confidence,
            "task_count": verdict.task_count,
            "tool_call_count": verdict.tool_call_count,
            "violated_capabilities": verdict.violated_capabilities,
            "missing_context": verdict.missing_context,
            "reason": verdict.reason,
        }
        for verdict in result.run_audit_verdicts
    ]


def verdicts_for_call(result: ScanResult, call_id: str | None):
    if not call_id:
        return []
    packet_ids = [
        packet.call_id
        for packet in result.audit_packets
        if packet.agent_context.assistant_tool_call.get("function_call_id") == call_id
    ]
    return [verdict for verdict in result.audit_verdicts if verdict.call_id in packet_ids]


def event_row(result: ScanResult, trace, call, verdict) -> dict[str, Any]:
    return {
        "target_id": result.target.id,
        "label": result.target.label,
        "status": result.status,
        "task_id": trace.task_id,
        "user_task": trace.user_task,
        "agent_model": trace.model,
        "tool_call_id": call.call_id,
        "tool_name": call.tool_name,
        "arguments": json.dumps(call.arguments, sort_keys=True),
        "mcp_result": summarize_result(call.result, max_chars=500),
        "audit_model": verdict.model if verdict else "",
        "audit_verdict": verdict.verdict if verdict else "",
        "audit_severity": verdict.severity if verdict else "",
        "audit_confidence": verdict.confidence if verdict else "",
        "audit_reason": verdict.reason if verdict else "",
    }


def summarize_result(value: Any, max_chars: int = 240) -> str:
    if value is None:
        return "-"
    text = json.dumps(value, sort_keys=True)
    return one_line(text, max_chars)


def one_line(value: str, max_chars: int = 180) -> str:
    text = " ".join(str(value).split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 14] + "...[truncated]"


def _write_audit_matrix_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "model",
                "call_id",
                "tool",
                "verdict",
                "severity",
                "confidence",
                "violated_capabilities",
                "reason",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({
                **row,
                "violated_capabilities": ";".join(row["violated_capabilities"]),
            })


def _write_run_audit_matrix_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "model",
                "target_id",
                "verdict",
                "severity",
                "confidence",
                "task_count",
                "tool_call_count",
                "violated_capabilities",
                "missing_context",
                "reason",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({
                **row,
                "violated_capabilities": ";".join(row["violated_capabilities"]),
                "missing_context": ";".join(row["missing_context"]),
            })


def _write_markdown(path: Path, result: ScanResult) -> None:
    contract_models = sorted({
        str(tool.evidence.get("model"))
        for tool in result.contract.tools
        if tool.evidence.get("model")
    })
    task_models = sorted({
        task.generator_model
        for task in result.generated_tasks
        if task.generator_model
    })
    agent_models = sorted({trace.model for trace in result.agent_traces if trace.model})
    audit_models = sorted({
        verdict.model
        for verdict in result.audit_verdicts
        if verdict.model
    })
    run_audit_models = sorted({
        verdict.model
        for verdict in result.run_audit_verdicts
        if verdict.model
    })
    lines = [
        f"# MCP Scan Report: {result.target.id}",
        "",
        f"- Source: `{result.target.source}`",
        f"- Label: `{result.target.label}`",
        f"- Status: `{result.status}`",
        f"- Tools: `{len(result.tools)}`",
        f"- Generated tasks: `{len(result.generated_tasks)}`",
        f"- Agent traces: `{len(result.agent_traces)}`",
        f"- Audit packets: `{len(result.audit_packets)}`",
        f"- LLM audit verdicts: `{len(result.audit_verdicts)}`",
        f"- Run-level LLM audit verdicts: `{len(result.run_audit_verdicts)}`",
        f"- Findings: `{len(result.findings)}`",
        f"- Contract model(s): `{', '.join(contract_models) or '-'}`",
        f"- Task model(s): `{', '.join(task_models) or '-'}`",
        f"- Agent model(s): `{', '.join(agent_models) or '-'}`",
        f"- Audit model(s): `{', '.join(audit_models) or '-'}`",
        f"- Run audit model(s): `{', '.join(run_audit_models) or '-'}`",
        "",
        "## Tools",
        "",
    ]
    for tool in result.tools:
        lines.append(f"- `{tool.name}` - {tool.description or 'no description'}")

    if result.generated_tasks:
        lines.extend(["", "## Generated Tasks", ""])
        for task in result.generated_tasks:
            expected = ", ".join(f"`{name}`" for name in task.expected_tools) or "-"
            lines.extend([
                f"### {task.id}",
                "",
                f"- User task: {task.user_task}",
                f"- Expected tools: {expected}",
                f"- Purpose: {task.purpose}",
                f"- Risk focus: {task.risk_focus}",
                f"- Generator model: `{task.generator_model or '-'}`",
                "",
            ])

    if result.agent_traces:
        lines.extend(["", "## Agent Tool Calls", ""])
        for trace in result.agent_traces:
            lines.append(f"### {trace.task_id}")
            lines.append("")
            lines.append(f"- User task: {trace.user_task}")
            lines.append(f"- Model: `{trace.model}`")
            if trace.selected_tool_calls:
                for call in trace.selected_tool_calls:
                    arguments = json.dumps(call.arguments, sort_keys=True)
                    lines.append(f"- Called `{call.tool_name}` with `{arguments}`")
            else:
                lines.append("- No MCP tool call selected.")
            if trace.final_answer:
                lines.append(f"- Final answer: {trace.final_answer}")
            lines.append("")

    lines.extend(["", "## Findings", ""])
    if result.findings:
        for finding in result.findings:
            lines.append(f"- `{finding.severity}` {finding.tool_name or '-'}: {finding.message}")
    else:
        lines.append("No findings.")
    if result.run_audit_verdicts:
        lines.extend(["", "## Run-Level LLM Audit Verdicts", ""])
        for verdict in result.run_audit_verdicts:
            lines.append(
                f"- `{verdict.model or '-'}` `{verdict.verdict}` `{verdict.severity}` "
                f"({verdict.confidence}): {verdict.reason}"
            )
    if result.audit_verdicts:
        lines.extend(["", "## LLM Audit Verdicts", ""])
        verdicts_by_model: dict[str, list] = {}
        for verdict in result.audit_verdicts:
            verdicts_by_model.setdefault(verdict.model or "unknown", []).append(verdict)
        for model, verdicts in verdicts_by_model.items():
            lines.extend([f"### {model}", ""])
            for verdict in verdicts:
                lines.append(
                    f"- `{verdict.call_id or '-'}` `{verdict.verdict}` "
                    f"`{verdict.severity}`: {verdict.reason}"
                )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
