from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(start: str | Path | None = None, filename: str = ".env") -> Path | None:
    """Load key=value pairs from the nearest .env file without overriding env vars."""
    start_path = Path(start or os.getcwd()).resolve()
    if start_path.is_file():
        start_path = start_path.parent
    for directory in [start_path, *start_path.parents]:
        candidate = directory / filename
        if candidate.exists():
            _load_env_file(candidate)
            return candidate
    return None


def _load_env_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = _clean_value(value.strip())
        if key and key not in os.environ:
            os.environ[key] = value


def _clean_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
