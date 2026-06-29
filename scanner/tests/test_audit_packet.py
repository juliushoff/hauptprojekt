from __future__ import annotations

import unittest

from mcp_harness.audit_packet import build_audit_packets
from mcp_harness.contract_builder import build_contract
from mcp_harness.models import TestInvocation, ToolMetadata, TraceEvent


class AuditPacketTests(unittest.TestCase):
    def test_build_packet_from_tool_result(self) -> None:
        tools = [
            ToolMetadata(
                name="search",
                description="Search the web for a query.",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            )
        ]
        contract = build_contract("target", "test", tools)
        tests = [TestInvocation("search", "normal_use", {"query": "test"}, "Normal search")]
        trace = [
            TraceEvent("mcp.tool_result", "Tool call completed", {
                "tool": "search",
                "arguments": {"query": "test"},
                "result": {"content": [{"type": "text", "text": "ok"}]},
            })
        ]
        packets = build_audit_packets("target", tools, contract, tests, trace)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].contract.name, "search")
        self.assertEqual(packets[0].agent_context.assistant_tool_call["tool"], "search")


if __name__ == "__main__":
    unittest.main()
