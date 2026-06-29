from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

from .models import TargetConfig


class TargetError(ValueError):
    pass


def load_targets(path: str | Path) -> list[TargetConfig]:
    target_path = Path(path)
    targets: list[TargetConfig] = []
    with target_path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TargetError(f"{target_path}:{line_no}: invalid JSONL: {exc}") from exc
            targets.append(_target_from_dict(payload, target_path, line_no))
    return targets


def select_target(targets: Iterable[TargetConfig], target_id: str) -> TargetConfig:
    for target in targets:
        if target.id == target_id:
            return target
    raise TargetError(f"target not found: {target_id}")


def _target_from_dict(payload: dict, target_path: Path, line_no: int) -> TargetConfig:
    required = ["id", "source", "label", "command"]
    missing = [key for key in required if key not in payload]
    if missing:
        raise TargetError(f"{target_path}:{line_no}: missing required keys: {', '.join(missing)}")

    args = payload.get("args", [])
    env = payload.get("env", {})
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise TargetError(f"{target_path}:{line_no}: args must be a list of strings")
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise TargetError(f"{target_path}:{line_no}: env must be an object of strings")

    base_dir = target_path.resolve().parent
    resolved_path = _resolve_optional_path(payload.get("path"), base_dir)
    resolved_cwd = _resolve_optional_path(payload.get("cwd"), base_dir)
    replacements = {
        "path": resolved_path or "",
        "cwd": resolved_cwd or "",
        "target_dir": resolved_cwd or resolved_path or "",
    }

    return TargetConfig(
        id=str(payload["id"]),
        source=str(payload["source"]),
        label=payload["label"],
        command=_replace_placeholders(str(payload["command"]), replacements),
        args=[_replace_placeholders(arg, replacements) for arg in args],
        env={key: _replace_placeholders(value, replacements) for key, value in env.items()},
        path=resolved_path,
        cwd=resolved_cwd,
        transport=payload.get("transport", "stdio"),
        stdio_framing=payload.get("stdio_framing", "headers"),
        protocol_version=str(payload.get("protocol_version", "2024-11-05")),
        timeout_seconds=float(payload.get("timeout_seconds", 30.0)),
        notes=payload.get("notes"),
    )


def _resolve_optional_path(value: str | None, base_dir: Path) -> str | None:
    if not value:
        return None
    expanded = Path(os.path.expandvars(os.path.expanduser(value)))
    if not expanded.is_absolute():
        expanded = base_dir / expanded
    return str(expanded.resolve())


def _replace_placeholders(value: str, replacements: dict[str, str]) -> str:
    result = value
    for key, replacement in replacements.items():
        result = result.replace("{" + key + "}", replacement)
    return result
