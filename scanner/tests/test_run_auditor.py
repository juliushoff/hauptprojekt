from __future__ import annotations

import unittest

from mcp_harness.llm_auditor import audit_run_with_llm, build_run_audit_payload, findings_from_run_audit_verdicts
from mcp_harness.models import (
    AgentRunTrace,
    AgentToolCall,
    Contract,
    GeneratedTask,
    ToolContract,
    ToolMetadata,
    TraceEvent,
)


class FakeAuditClient:
    model = "fake-audit-model"

    def structured_response(self, **_kwargs):
        return {
            "verdict": "violation",
            "severity": "high",
            "violated_capabilities": ["network_exfiltration"],
            "reason": "The full run attempted behavior outside the contract.",
            "missing_context": [],
            "confidence": "high",
        }


class RunAuditorTests(unittest.TestCase):
    def test_build_run_payload_contains_full_traffic_summary(self) -> None:
        tools = [ToolMetadata(name="lookup", description="Lookup a value.")]
        contract = Contract(
            target_id="target",
            source="test",
            tools=[
                ToolContract(
                    name="lookup",
                    declared_intent="Lookup values.",
                    allowed_capabilities=["read provided lookup data"],
                    forbidden_capabilities=["network access"],
                    confidence="high",
                )
            ],
        )
        tasks = [
            GeneratedTask("task_1", "Lookup alpha.", ["lookup"], "normal lookup"),
            GeneratedTask("task_2", "Lookup beta.", ["lookup"], "second lookup"),
        ]
        agent_traces = [
            AgentRunTrace(
                task_id="task_1",
                user_task="Lookup alpha.",
                model="agent-model",
                messages_before_call=[],
                selected_tool_calls=[
                    AgentToolCall(
                        tool_name="lookup",
                        arguments={"key": "alpha"},
                        call_id="call_1",
                        result={"content": [{"type": "text", "text": "ok"}]},
                    )
                ],
                final_answer="ok",
            )
        ]
        payload = build_run_audit_payload("target", tools, contract, tasks, agent_traces, [
            TraceEvent("mcp.tool_result", "Tool call completed"),
        ])

        self.assertEqual(payload["traffic_summary"]["task_count"], 2)
        self.assertEqual(payload["traffic_summary"]["tool_call_count"], 1)
        self.assertEqual(payload["agent_runs"][0]["selected_tool_calls"][0]["tool_name"], "lookup")

    def test_run_verdict_creates_one_mcp_level_finding(self) -> None:
        verdict = audit_run_with_llm(
            "target",
            [],
            Contract(target_id="target", source="test", tools=[]),
            [],
            [],
            [],
            FakeAuditClient(),  # type: ignore[arg-type]
        )
        findings = findings_from_run_audit_verdicts([verdict])

        self.assertEqual(verdict.target_id, "target")
        self.assertEqual(verdict.model, "fake-audit-model")
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].tool_name)
        self.assertIn("Run-level LLM audit verdict violation", findings[0].message)


if __name__ == "__main__":
    unittest.main()
