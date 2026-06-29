from __future__ import annotations

import unittest
from pathlib import Path

from mcp_harness.models import TargetConfig
from mcp_harness.runner import scan_target


class McpClientTests(unittest.TestCase):
    def test_scan_local_echo_server(self) -> None:
        root = Path(__file__).resolve().parents[2]
        target = TargetConfig(
            id="local_echo",
            source="local",
            label="benign",
            command="python3",
            args=["scanner/examples/local_echo/server.py"],
            timeout_seconds=5,
        )
        result = scan_target(
            target,
            cwd=root,
            contract_mode="heuristic",
            audit_mode="heuristic",
            run_mode="direct",
            task_mode="single",
            task_count=1,
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual([tool.name for tool in result.tools], ["echo", "read_sample"])
        self.assertEqual(len(result.tests), 2)
        self.assertEqual(len(result.audit_packets), 2)
        self.assertEqual(result.audit_packets[0].scenario.mode, "direct")


if __name__ == "__main__":
    unittest.main()
