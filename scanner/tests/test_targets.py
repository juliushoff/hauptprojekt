from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_harness.targets import load_targets, select_target


class TargetTests(unittest.TestCase):
    def test_load_jsonl_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.jsonl"
            path.write_text(
                '{"id":"local","source":"test","label":"benign","command":"python3","args":["{cwd}/server.py"],"cwd":"servers/local"}\n',
                encoding="utf-8",
            )
            targets = load_targets(path)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].id, "local")
        self.assertEqual(select_target(targets, "local").command, "python3")
        self.assertTrue(targets[0].cwd.endswith("servers/local"))
        self.assertTrue(targets[0].args[0].endswith("servers/local/server.py"))


if __name__ == "__main__":
    unittest.main()
