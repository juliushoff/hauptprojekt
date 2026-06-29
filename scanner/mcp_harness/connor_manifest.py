from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


DOCKER_RUN_PREFIX = [
    "run",
    "--rm",
    "-i",
    "--network",
    "none",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
]


def build_connor_benign_docker_manifest(
    servers_dir: str | Path,
    image: str,
    output_path: str | Path,
    limit: int | None = None,
) -> int:
    root = Path(servers_dir)
    rows: list[dict[str, Any]] = []
    for mcp_json in sorted(root.glob("*/mcp.json")):
        target_dir = mcp_json.parent
        config = json.loads(mcp_json.read_text(encoding="utf-8"))
        servers = config.get("mcpServers", {})
        if not isinstance(servers, dict) or not servers:
            continue
        server_name, server_config = next(iter(servers.items()))
        command = server_config.get("command")
        args = server_config.get("args", [])
        if not isinstance(command, str) or not isinstance(args, list):
            continue
        container_args = rewrite_app_paths([command, *[str(arg) for arg in args]])
        rows.append({
            "id": "connor_benign_" + slugify(target_dir.name),
            "source": "connor-benign",
            "label": "benign",
            "transport": "stdio",
            "stdio_framing": "jsonl",
            "protocol_version": "2024-11-05",
            "command": "docker",
            "args": DOCKER_RUN_PREFIX + [image, *container_args],
            "timeout_seconds": 45,
            "notes": f"Connor benign `{target_dir.name}` / MCP server `{server_name}` in Docker.",
        })
        if limit and len(rows) >= limit:
            break
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    return len(rows)


def rewrite_app_paths(values: list[str]) -> list[str]:
    return [value.replace("/app/", "/app/bengin_servers/") for value in values]


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return slug or "target"
