from __future__ import annotations

import unittest

from unittest.mock import patch

from mcp_harness.llm_client import default_model_for_role, extract_output_text


class LlmClientTests(unittest.TestCase):
    def test_extract_output_text_from_responses_shape(self) -> None:
        response = {
            "output": [
                {
                    "content": [
                        {"type": "output_text", "text": "{\"verdict\":\"upheld\"}"}
                    ]
                }
            ]
        }
        self.assertEqual(extract_output_text(response), '{"verdict":"upheld"}')

    def test_default_model_is_mini(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(default_model_for_role("audit"), "gpt-5.4-mini")


if __name__ == "__main__":
    unittest.main()
