from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class LlmUnavailable(RuntimeError):
    pass


class LlmClientError(RuntimeError):
    pass


ROLE_MODEL_ENV = {
    "contract": "OPENAI_CONTRACT_MODEL",
    "task": "OPENAI_TASK_MODEL",
    "agent": "OPENAI_AGENT_MODEL",
    "audit": "OPENAI_AUDIT_MODEL",
}


class OpenAILlmClient:
    def __init__(
        self,
        model: str | None = None,
        role: str = "default",
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.role = role
        self.model = model or default_model_for_role(role)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.timeout_seconds = timeout_seconds
        if not self.api_key:
            raise LlmUnavailable("OPENAI_API_KEY is not set")

    def structured_response(
        self,
        instructions: str,
        payload: dict[str, Any],
        schema_name: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        body = {
            "model": self.model,
            "instructions": instructions,
            "input": json.dumps(payload, indent=2, sort_keys=True),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "strict": True,
                    "schema": schema,
                }
            },
        }
        raw = self._post_json("/responses", body)
        output_text = extract_output_text(raw)
        try:
            return json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise LlmClientError(f"model did not return valid JSON: {output_text[:500]}") from exc

    def create_response(self, body: dict[str, Any]) -> dict[str, Any]:
        payload = {"model": self.model, **body}
        return self._post_json("/responses", payload)

    def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise LlmClientError(f"OpenAI API HTTP {exc.code}: {details}") from exc
        except urllib.error.URLError as exc:
            raise LlmClientError(f"OpenAI API request failed: {exc}") from exc


def default_model_for_role(role: str) -> str:
    role_env = ROLE_MODEL_ENV.get(role)
    if role_env:
        role_model = os.environ.get(role_env)
        if role_model:
            return role_model
    return os.environ.get("OPENAI_MODEL") or os.environ.get("OPENAI_AUDIT_MODEL") or "gpt-5.4-mini"


def extract_output_text(response: dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str):
        return response["output_text"]
    texts: list[str] = []
    for item in response.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and isinstance(content.get("text"), str):
                texts.append(content["text"])
    if texts:
        return "".join(texts)
    raise LlmClientError("OpenAI response did not contain output text")
