from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import TargetConfig, ToolMetadata, TraceEvent


class McpClientError(RuntimeError):
    pass


@dataclass
class McpSession:
    target: TargetConfig
    cwd: Path | None = None
    process: subprocess.Popen | None = field(default=None, init=False)
    trace: list[TraceEvent] = field(default_factory=list, init=False)
    _next_id: int = field(default=1, init=False)
    _stdout_queue: queue.Queue = field(default_factory=queue.Queue, init=False)
    _stdout_thread: threading.Thread | None = field(default=None, init=False)
    _stderr_thread: threading.Thread | None = field(default=None, init=False)

    def __enter__(self) -> "McpSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if self.target.transport != "stdio":
            raise McpClientError(f"unsupported transport for this client: {self.target.transport}")
        env = os.environ.copy()
        env.update(self.target.env)
        effective_cwd = Path(self.target.cwd) if self.target.cwd else self.cwd
        self.process = subprocess.Popen(
            [self.target.command, *self.target.args],
            cwd=str(effective_cwd) if effective_cwd else None,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.trace.append(TraceEvent("process.start", "Started MCP server", {
            "command": self.target.command,
            "args": self.target.args,
            "cwd": str(effective_cwd) if effective_cwd else None,
            "pid": self.process.pid,
        }))
        self._stdout_thread = threading.Thread(target=self._collect_stdout, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread = threading.Thread(target=self._collect_stderr, daemon=True)
        self._stderr_thread.start()

    def stop(self) -> None:
        if not self.process:
            return
        docker_container_name = self._docker_container_name()
        if docker_container_name:
            self._stop_docker_container(docker_container_name)
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.trace.append(TraceEvent("process.exit", "MCP server stopped", {
            "returncode": self.process.returncode,
        }))
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream:
                stream.close()

    def _docker_container_name(self) -> str | None:
        if self.target.command != "docker":
            return None
        args = self.target.args
        for index, arg in enumerate(args):
            if arg == "--name" and index + 1 < len(args):
                return args[index + 1]
            if arg.startswith("--name="):
                return arg.split("=", 1)[1]
        return None

    def _stop_docker_container(self, name: str) -> None:
        for command in (["docker", "stop", "--time", "1", name], ["docker", "rm", "-f", name]):
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                continue

    def initialize(self) -> dict[str, Any]:
        result = self.request("initialize", {
            "protocolVersion": self.target.protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "mcp-contract-harness", "version": "0.1.0"},
        })
        self.notify("notifications/initialized", {})
        return result

    def list_tools(self) -> list[ToolMetadata]:
        result = self.request("tools/list", {})
        tools = result.get("tools", [])
        parsed: list[ToolMetadata] = []
        for tool in tools:
            parsed.append(ToolMetadata(
                name=tool.get("name", ""),
                description=tool.get("description", ""),
                input_schema=tool.get("inputSchema", tool.get("input_schema", {})),
            ))
        self.trace.append(TraceEvent("mcp.tools_list", "Listed MCP tools", {
            "tool_count": len(parsed),
            "tools": [tool.name for tool in parsed],
        }))
        return parsed

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        self.trace.append(TraceEvent("mcp.tool_result", "Tool call completed", {
            "tool": name,
            "arguments": arguments,
            "result": result,
        }))
        return result

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._write_message({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        })
        self.trace.append(TraceEvent("mcp.request", f"Sent {method}", {
            "id": request_id,
            "method": method,
            "params": params or {},
        }))
        deadline = time.monotonic() + self.target.timeout_seconds
        while time.monotonic() < deadline:
            message = self._next_message(deadline)
            if message.get("id") != request_id:
                self.trace.append(TraceEvent("mcp.message", "Received unrelated MCP message", message))
                continue
            if "error" in message:
                raise McpClientError(f"MCP request failed for {method}: {message['error']}")
            return message.get("result", {})
        raise McpClientError(f"timeout waiting for response to {method}")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._write_message({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        })
        self.trace.append(TraceEvent("mcp.notification", f"Sent {method}", {"params": params or {}}))

    def _write_message(self, payload: dict[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise McpClientError("MCP process is not running")
        body_text = json.dumps(payload, separators=(",", ":"))
        if self.target.stdio_framing == "jsonl":
            self.process.stdin.write((body_text + "\n").encode("utf-8"))
        else:
            body = body_text.encode("utf-8")
            header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            self.process.stdin.write(header + body)
        self.process.stdin.flush()

    def _next_message(self, deadline: float) -> dict[str, Any]:
        timeout = max(0.0, deadline - time.monotonic())
        try:
            item = self._stdout_queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise McpClientError("timeout while reading MCP response") from exc
        if isinstance(item, Exception):
            raise item
        return item

    def _read_message_blocking(self) -> dict[str, Any]:
        if not self.process or not self.process.stdout:
            raise McpClientError("MCP process is not running")
        if self.target.stdio_framing in {"jsonl", "headers-jsonl"}:
            while True:
                line = self.process.stdout.readline()
                if line == b"":
                    raise McpClientError("MCP process closed stdout")
                line_text = line.decode("utf-8", errors="replace")
                if not line_text.strip():
                    continue
                try:
                    return json.loads(line_text)
                except json.JSONDecodeError:
                    self.trace.append(TraceEvent("process.stdout", line_text.strip()[:1000]))
                    continue
        headers: dict[str, str] = {}
        while True:
            line = self.process.stdout.readline()
            if line == b"":
                raise McpClientError("MCP process closed stdout")
            line_text = line.decode("ascii", errors="replace").strip()
            if not line_text:
                break
            if ":" in line_text:
                key, value = line_text.split(":", 1)
                headers[key.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        if length <= 0:
            raise McpClientError("MCP message missing Content-Length")
        body = self.process.stdout.read(length)
        if len(body) != length:
            raise McpClientError("MCP process closed before full body was read")
        return json.loads(body.decode("utf-8"))

    def _collect_stdout(self) -> None:
        while True:
            try:
                self._stdout_queue.put(self._read_message_blocking())
            except Exception as exc:
                self._stdout_queue.put(exc)
                return

    def _collect_stderr(self) -> None:
        if not self.process or not self.process.stderr:
            return
        for raw_line in self.process.stderr:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if line:
                self.trace.append(TraceEvent("process.stderr", line))
