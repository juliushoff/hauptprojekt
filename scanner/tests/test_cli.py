from __future__ import annotations

import unittest

from mcp_harness.cli import filter_targets
from mcp_harness.models import TargetConfig


class CliTests(unittest.TestCase):
    def test_filter_targets_by_ids_and_label(self) -> None:
        targets = [
            TargetConfig(id="a", source="test", label="benign", command="python3"),
            TargetConfig(id="b", source="test", label="malicious", command="python3"),
            TargetConfig(id="c", source="test", label="benign", command="python3"),
        ]

        selected = filter_targets(targets, ids=["a", "b"], label="benign")

        self.assertEqual([target.id for target in selected], ["a"])


if __name__ == "__main__":
    unittest.main()
