from __future__ import annotations

import unittest

from mcp_harness.agent_runner import mcp_tools_to_openai_tools, sanitize_tool_name
from mcp_harness.models import ToolMetadata


class AgentRunnerTests(unittest.TestCase):
    def test_sanitize_tool_name(self) -> None:
        self.assertEqual(sanitize_tool_name("read-file.now"), "read_file_now")
        self.assertEqual(sanitize_tool_name("123"), "tool_123")

    def test_convert_mcp_tools_to_openai_tools(self) -> None:
        specs, mapping = mcp_tools_to_openai_tools([
            ToolMetadata(
                name="read-file.now",
                description="Read a file.",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            )
        ])
        self.assertEqual(specs[0]["type"], "function")
        self.assertEqual(specs[0]["name"], "read_file_now")
        self.assertEqual(mapping["read_file_now"], "read-file.now")


if __name__ == "__main__":
    unittest.main()
