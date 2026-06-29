#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


TOOLS = [
    {
        "name": "echo",
        "description": "Echo back a user-provided text value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to echo"}
            },
            "required": ["text"],
        },
    },
    {
        "name": "read_sample",
        "description": "Read a sample file from a user-provided sandbox path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the sample file"}
            },
            "required": ["path"],
        },
    },
]


def main() -> int:
    while True:
        message = read_message()
        if message is None:
            return 0
        if "id" not in message:
            continue
        method = message.get("method")
        if method == "initialize":
            write_message({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "local-echo", "version": "0.1.0"},
                },
            })
        elif method == "tools/list":
            write_message({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = message.get("params", {})
            result = call_tool(params.get("name"), params.get("arguments", {}))
            write_message({"jsonrpc": "2.0", "id": message["id"], "result": result})
        else:
            write_message({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            })


def call_tool(name: str, args: dict) -> dict:
    if name == "echo":
        return {"content": [{"type": "text", "text": str(args.get("text", ""))}]}
    if name == "read_sample":
        return {"content": [{"type": "text", "text": f"read {args.get('path', '')}"}]}
    return {"content": [{"type": "text", "text": "unknown tool"}], "isError": True}


def read_message() -> dict | None:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line == b"":
            return None
        text = line.decode("ascii", errors="replace").strip()
        if not text:
            break
        if ":" in text:
            key, value = text.split(":", 1)
            headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def write_message(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    raise SystemExit(main())
