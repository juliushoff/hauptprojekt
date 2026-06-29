from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mcp_harness.env import load_dotenv


class EnvTests(unittest.TestCase):
    def test_load_dotenv_from_parent_without_overriding(self) -> None:
        old_key = os.environ.get("MCP_HARNESS_TEST_KEY")
        old_existing = os.environ.get("MCP_HARNESS_EXISTING")
        try:
            os.environ["MCP_HARNESS_EXISTING"] = "already-set"
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                child = root / "a" / "b"
                child.mkdir(parents=True)
                (root / ".env").write_text(
                    "MCP_HARNESS_TEST_KEY='loaded-value'\n"
                    "MCP_HARNESS_EXISTING=from-file\n",
                    encoding="utf-8",
                )
                loaded = load_dotenv(child)
            self.assertIsNotNone(loaded)
            self.assertEqual(os.environ.get("MCP_HARNESS_TEST_KEY"), "loaded-value")
            self.assertEqual(os.environ.get("MCP_HARNESS_EXISTING"), "already-set")
        finally:
            if old_key is None:
                os.environ.pop("MCP_HARNESS_TEST_KEY", None)
            else:
                os.environ["MCP_HARNESS_TEST_KEY"] = old_key
            if old_existing is None:
                os.environ.pop("MCP_HARNESS_EXISTING", None)
            else:
                os.environ["MCP_HARNESS_EXISTING"] = old_existing


if __name__ == "__main__":
    unittest.main()
