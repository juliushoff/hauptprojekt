from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from mcp_harness.runner import resolve_audit_models


class RunnerModelTests(unittest.TestCase):
    def test_explicit_audit_models_win(self) -> None:
        self.assertEqual(
            resolve_audit_models(["gpt-5.4-nano", "gpt-5.4-mini"], "ignored", "ignored"),
            ["gpt-5.4-nano", "gpt-5.4-mini"],
        )

    def test_env_audit_models_are_parsed(self) -> None:
        with patch.dict(os.environ, {"OPENAI_AUDIT_MODELS": "gpt-5.4-nano, gpt-5.4-mini"}, clear=False):
            self.assertEqual(
                resolve_audit_models(None, None, None),
                ["gpt-5.4-nano", "gpt-5.4-mini"],
            )


if __name__ == "__main__":
    unittest.main()
