from __future__ import annotations

import csv
import hashlib
import http.server
import ast
import json
import os
import re
import shlex
import shutil
import socketserver
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Literal

from .agent_runner import OpenAIAgentRunner
from .audit_packet import build_audit_packets
from .contract_builder import build_contract
from .llm_auditor import audit_run_with_llm, findings_from_run_audit_verdicts
from .llm_client import LlmClientError, LlmUnavailable, OpenAILlmClient
from .llm_contract_builder import build_contract_with_llm
from .mcp_client import McpClientError, McpSession
from .models import (
    AuditPacket,
    Contract,
    Finding,
    GeneratedTask,
    RunAuditVerdict,
    ScanResult,
    TargetConfig,
    TestInvocation,
    ToolMetadata,
    TraceEvent,
)
from .report import write_result
from .runner import resolve_audit_models
from .task_generator import generate_tasks_with_llm
from .test_generator import generate_tests


StartType = Literal[
    "uv-directory",
    "uv-with-mcp-run",
    "uvx",
    "bash-wrapper",
    "direct-python",
    "package-entrypoint",
    "unsupported",
]
SandboxProfile = Literal["preflight-strict", "toolcall-strict", "production-observed"]
ConnorStage = Literal["preflight", "toolcall", "production"]
ExecutionMode = Literal["original-command", "normalized-command"]


@dataclass(frozen=True)
class ConnorInventoryItem:
    id: str
    group: str
    label: str
    source: str
    target_dir: str
    container_dir: str
    mcp_json: str
    server_name: str
    original_command: str
    original_args: list[str]
    original_env: dict[str, str] = field(default_factory=dict)
    start_type: StartType = "unsupported"
    path_status: str = "unknown"
    dependency_status: str = "unknown"
    risk_hints: list[str] = field(default_factory=list)
    normalized: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnorBuildResult:
    target_id: str
    image: str
    build_status: str
    dockerfile: str
    context_dir: str
    reason: str = ""
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class ConnorRunResult:
    target_id: str
    group: str
    label: str
    stage: str
    sandbox_profile: str
    execution_mode: str
    image: str
    startup_status: str
    build_status: str
    classification: str
    tools_listed: int
    tool_calls_attempted: int
    tool_calls_completed: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    run_audit_verdicts: list[dict[str, Any]] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration_seconds: float = 0.0


def build_connor_inventory(
    connor_root: str | Path,
    benign_dir: str | Path,
    out_path: str | Path,
) -> list[ConnorInventoryItem]:
    items = discover_connor_inventory(connor_root, benign_dir)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(out, [asdict(item) for item in items])
    write_inventory_summary(out.with_suffix(".summary.csv"), items)
    return items


def discover_connor_inventory(
    connor_root: str | Path,
    benign_dir: str | Path,
) -> list[ConnorInventoryItem]:
    connor = Path(connor_root)
    benign = Path(benign_dir)
    items: list[ConnorInventoryItem] = []
    if benign.exists():
        items.extend(inventory_from_root(
            root=benign,
            group="benign",
            source="connor-benign",
            label="benign",
            mcp_pattern="*/mcp.json",
            id_prefix="connor_benign",
        ))
    malicious = connor / "Dataset" / "Malicious"
    if malicious.exists():
        items.extend(inventory_from_root(
            root=malicious,
            group="malicious_curated",
            source="connor-malicious-curated",
            label="malicious",
            mcp_pattern="*/mcp.json",
            id_prefix="connor_malicious",
        ))
    poc_root = connor / "PoCs"
    if poc_root.exists():
        for family in sorted(poc_root.glob("*_PoC")):
            family_slug = slugify(family.name.replace("_PoC", ""))
            items.extend(inventory_from_root(
                root=family,
                group=f"poc_{family_slug}",
                source=f"connor-poc-{family_slug}",
                label="malicious",
                mcp_pattern="p*/mcp.json",
                id_prefix=f"connor_poc_{family_slug}",
            ))
    return sorted(ensure_unique_inventory_ids(items), key=lambda item: item.id)


def inventory_from_root(
    root: Path,
    group: str,
    source: str,
    label: str,
    mcp_pattern: str,
    id_prefix: str,
) -> list[ConnorInventoryItem]:
    root = root.resolve()
    items: list[ConnorInventoryItem] = []
    for mcp_json in sorted(root.glob(mcp_pattern)):
        mcp_json = mcp_json.resolve()
        config = read_json(mcp_json)
        servers = config.get("mcpServers", {})
        if not isinstance(servers, dict):
            continue
        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue
            command = str(server_config.get("command", ""))
            args = [str(arg) for arg in server_config.get("args", [])]
            env = {
                str(key): str(value)
                for key, value in server_config.get("env", {}).items()
            } if isinstance(server_config.get("env", {}), dict) else {}
            target_dir = mcp_json.parent
            start_type = classify_start_type(command, args)
            normalized = build_normalized_command(root, target_dir, command, args, start_type)
            risk_hints = infer_risk_hints(target_dir, command, args)
            path_status = "resolved" if normalized.get("project_local_dir") else "unresolved"
            dependency_status = dependency_status_for(normalized)
            target_id = f"{id_prefix}_{slugify(target_dir.name)}"
            items.append(ConnorInventoryItem(
                id=target_id,
                group=group,
                label=label,
                source=source,
                target_dir=str(target_dir.resolve()),
                container_dir=target_dir.name,
                mcp_json=str(mcp_json.resolve()),
                server_name=str(server_name),
                original_command=command,
                original_args=args,
                original_env=env,
                start_type=start_type,
                path_status=path_status,
                dependency_status=dependency_status,
                risk_hints=risk_hints,
                normalized=normalized,
            ))
    return items


def classify_start_type(command: str, args: list[str]) -> StartType:
    executable = Path(command).name
    if executable == "bash":
        return "bash-wrapper"
    if executable == "uvx":
        return "uvx"
    if executable in {"python", "python3"} or executable.startswith("python"):
        return "direct-python"
    if executable == "uv":
        if "--directory" in args:
            return "uv-directory"
        if "--with" in args and "mcp" in args and "run" in args:
            return "uv-with-mcp-run"
        if any(arg.endswith(".py") for arg in args):
            return "direct-python"
        return "package-entrypoint"
    if executable in {"node", "npm", "npx", "pnpm", "bun", "bunx"}:
        return "package-entrypoint"
    return "unsupported"


def build_normalized_command(
    root: Path,
    target_dir: Path,
    command: str,
    args: list[str],
    start_type: StartType,
) -> dict[str, Any]:
    extracted = extract_uv_from_bash(args) if start_type == "bash-wrapper" else (command, args)
    source_command, source_args = extracted
    project_dir = resolve_project_dir(root, target_dir, source_args)
    script_file = resolve_script_file(root, target_dir, project_dir, source_args)
    with_packages = extract_uv_with_packages(source_args)
    uvx_package = extract_uvx_package(source_command, source_args)
    project_container = container_path_for(target_dir, project_dir) if project_dir else None
    script_container = container_path_for(target_dir, script_file) if script_file else None
    has_pyproject = bool(project_dir and (project_dir / "pyproject.toml").exists())
    run_intent = extract_uv_run_intent(source_command, source_args)
    entrypoint = resolve_python_entrypoint(target_dir, project_dir, script_file, run_intent)
    python_path_dirs = python_path_container_dirs(target_dir, project_dir, script_file)
    python_bin = ".venv/bin/python" if has_pyproject else "/opt/runner-venv/bin/python"
    mcp_bin = ".venv/bin/mcp" if has_pyproject else "/opt/runner-venv/bin/mcp"
    run_args: list[str]
    run_workdir = project_container or f"/app/{target_dir.name}"
    if uvx_package:
        run_args = [f"/opt/uv-home/.local/bin/{uvx_package}"]
    elif entrypoint.get("kind") == "mcp-run" and script_container:
        run_args = [mcp_bin, "run", script_container]
    elif entrypoint.get("kind") == "function":
        run_args = python_function_runtime_args(
            python_bin,
            str(entrypoint["module"]),
            str(entrypoint["function"]),
            python_path_dirs,
            rewrite_app_paths_for_target([str(arg) for arg in entrypoint.get("argv", [])], target_dir),
        )
    elif entrypoint.get("kind") == "fastmcp-object":
        run_args = python_object_method_runtime_args(
            python_bin,
            str(entrypoint["module"]),
            str(entrypoint["object"]),
            "run",
            python_path_dirs,
        )
    elif entrypoint.get("kind") == "object-method":
        run_args = python_object_method_runtime_args(
            python_bin,
            str(entrypoint["module"]),
            str(entrypoint["object"]),
            str(entrypoint["method"]),
            python_path_dirs,
        )
    elif entrypoint.get("kind") == "module":
        run_args = [python_bin, "-u", "-m", str(entrypoint["module"]), *rewrite_app_paths_for_target([str(arg) for arg in entrypoint.get("argv", [])], target_dir)]
    elif has_pyproject and script_file and project_dir and script_file.is_relative_to(project_dir):
        run_args = [python_bin, "-u", str(script_file.relative_to(project_dir)), *rewrite_app_paths_for_target([str(arg) for arg in run_intent.get("args", [])], target_dir)]
    elif script_container:
        run_args = [python_bin, "-u", script_container, *rewrite_app_paths_for_target([str(arg) for arg in run_intent.get("args", [])], target_dir)]
    else:
        run_args = rewrite_app_paths_for_target([source_command, *source_args], target_dir)
    return {
        "source_command": source_command,
        "source_args": source_args,
        "project_local_dir": str(project_dir) if project_dir else None,
        "project_container_dir": project_container,
        "script_local_path": str(script_file) if script_file else None,
        "script_container_path": script_container,
        "runtime_workdir": run_workdir,
        "runtime_args": run_args,
        "run_intent": run_intent,
        "entrypoint": entrypoint,
        "python_path_container_dirs": python_path_dirs,
        "with_packages": with_packages,
        "uvx_package": uvx_package,
        "has_pyproject": has_pyproject,
        "has_uv_lock": bool(project_dir and (project_dir / "uv.lock").exists()),
    }


def resolve_project_dir(root: Path, target_dir: Path, args: list[str]) -> Path | None:
    if "--directory" in args:
        raw = args[args.index("--directory") + 1]
        mapped = map_app_path_to_local(raw, root, target_dir)
        if mapped.exists():
            return nearest_parent_with(mapped, "pyproject.toml") or python_import_root_for(mapped, target_dir)
        fallback = fallback_project_dir_for(raw, target_dir)
        if fallback:
            return nearest_parent_with(fallback, "pyproject.toml") or python_import_root_for(fallback, target_dir)
    script = resolve_script_file(root, target_dir, None, args)
    if script:
        found = nearest_parent_with(script, "pyproject.toml")
        if found:
            return found
    pyprojects = [
        path.parent
        for path in target_dir.rglob("pyproject.toml")
        if ".venv" not in path.parts and "__pycache__" not in path.parts
    ]
    if pyprojects:
        return sorted(pyprojects, key=lambda path: (len(path.relative_to(target_dir).parts), str(path)))[0]
    source_root = likely_source_root(target_dir)
    if source_root:
        return source_root
    return target_dir if target_dir.exists() else None


def resolve_script_file(
    root: Path,
    target_dir: Path,
    project_dir: Path | None,
    args: list[str],
) -> Path | None:
    candidates: list[str] = []
    for index, arg in enumerate(args):
        if arg.endswith(".py"):
            candidates.append(arg)
        if arg == "run" and index + 1 < len(args) and args[index + 1].endswith(".py"):
            candidates.append(args[index + 1])
    for candidate in candidates:
        mapped = map_app_path_to_local(candidate, root, target_dir)
        if mapped.exists():
            return mapped
        base = Path(candidate).name
        search_roots = [project_dir, target_dir] if project_dir else [target_dir]
        for search_root in [root for root in search_roots if root]:
            matches = [
                path
                for path in search_root.rglob(base)
                if ".venv" not in path.parts and "__pycache__" not in path.parts
            ]
            if matches:
                return sorted(matches, key=lambda path: (len(path.parts), str(path)))[0]
    run_intent = extract_uv_run_intent("uv", args)
    entrypoint_file = resolve_entrypoint_file(target_dir, project_dir, run_intent)
    if entrypoint_file:
        return entrypoint_file
    if project_dir:
        for name in ("__main__.py", "server.py", "main.py", "cli.py"):
            candidate = project_dir / name
            if candidate.exists():
                return candidate
    return None


def fallback_project_dir_for(raw_directory: str, target_dir: Path) -> Path | None:
    raw_parts = [part for part in Path(raw_directory).parts if part not in {"/", "app", target_dir.name}]
    wanted_tail = [part for part in raw_parts if part]
    if wanted_tail:
        for tail_length in range(len(wanted_tail), 0, -1):
            tail = wanted_tail[-tail_length:]
            candidate = target_dir.joinpath(*tail)
            if candidate.exists():
                return candidate
    basenames = [part for part in reversed(wanted_tail) if part not in {".", ""}]
    for basename in basenames:
        matches = [
            path
            for path in target_dir.rglob(basename)
            if path.is_dir() and ".venv" not in path.parts and "__pycache__" not in path.parts
        ]
        if matches:
            return sorted(matches, key=lambda path: (len(path.relative_to(target_dir).parts), str(path)))[0]
    source_root = likely_source_root(target_dir)
    if source_root:
        return source_root
    return None


def python_import_root_for(path: Path, target_dir: Path) -> Path:
    current = path if path.is_dir() else path.parent
    if (current / "__init__.py").exists():
        while (current / "__init__.py").exists() and current.parent != current:
            current = current.parent
        return current
    source_root = likely_source_root(current)
    if source_root:
        return source_root
    if current.name == "src":
        return current
    return current if current.exists() else target_dir


def likely_source_root(target_dir: Path) -> Path | None:
    src = target_dir / "src"
    if src.exists() and any((child / "__init__.py").exists() for child in src.iterdir() if child.is_dir()):
        return src
    package_roots = [
        path.parent
        for path in target_dir.rglob("__init__.py")
        if ".venv" not in path.parts and "__pycache__" not in path.parts and ".egg-info" not in path.parts
    ]
    if not package_roots:
        return None
    return sorted(package_roots, key=lambda path: (len(path.relative_to(target_dir).parts), str(path)))[0].parent


def map_app_path_to_local(value: str, root: Path, target_dir: Path) -> Path:
    path = Path(value)
    if path.is_absolute() and value.startswith("/app/"):
        parts = Path(value).parts[2:]
        if parts and parts[0] == target_dir.name:
            return target_dir.joinpath(*parts[1:])
        return root.joinpath(*parts)
    if path.is_absolute():
        return path
    return (target_dir / path).resolve()


def container_path_for(target_dir: Path, local_path: Path | None) -> str | None:
    if not local_path:
        return None
    try:
        relative = local_path.relative_to(target_dir)
    except ValueError:
        return None
    if relative.as_posix() == ".":
        return f"/app/{target_dir.name}"
    return f"/app/{target_dir.name}/{relative.as_posix()}".rstrip("/")


def rewrite_app_paths_for_target(values: list[str], target_dir: Path) -> list[str]:
    rewritten: list[str] = []
    for value in values:
        if value.startswith("/app/"):
            path = Path(value)
            parts = path.parts[2:]
            if parts and parts[0] == target_dir.name:
                rewritten.append(value)
            else:
                rewritten.append(f"/app/{target_dir.name}/" + "/".join(parts))
        else:
            rewritten.append(value)
    return rewritten


def extract_uv_from_bash(args: list[str]) -> tuple[str, list[str]]:
    if "-c" not in args:
        return "bash", args
    script = args[args.index("-c") + 1]
    match = re.search(r"uv\s+(--directory\s+\S+\s+run\s+[^;&]+)", script)
    if not match:
        return "bash", args
    return "uv", shlex.split(match.group(1))


def extract_uv_with_packages(args: list[str]) -> list[str]:
    packages: list[str] = []
    index = 0
    while index < len(args):
        if args[index] == "--with" and index + 1 < len(args):
            packages.extend(split_package_list(args[index + 1]))
            index += 2
            continue
        index += 1
    return packages


def extract_uvx_package(command: str, args: list[str]) -> str | None:
    if Path(command).name != "uvx":
        return None
    package = None
    skip_next = False
    options_with_value = {"--from", "--python", "-p"}
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in options_with_value:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        package = arg
    return package


def split_package_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def extract_uv_run_intent(command: str, args: list[str]) -> dict[str, Any]:
    executable = Path(command).name
    if executable == "uvx":
        package = extract_uvx_package(command, args)
        return {"kind": "uvx", "program": package, "args": args}
    if executable != "uv" or "run" not in args:
        return {"kind": "raw", "program": executable, "args": args}
    index = args.index("run") + 1
    program: str | None = None
    program_args: list[str] = []
    options_with_value = {"--directory", "--with", "--python", "--project", "--from", "-p"}
    while index < len(args):
        arg = args[index]
        if arg in options_with_value:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        program = arg
        program_args = args[index + 1:]
        break
    if program == "mcp" and program_args[:1] == ["run"]:
        script = next((arg for arg in program_args[1:] if arg.endswith(".py")), None)
        return {"kind": "mcp-run", "program": "mcp", "script": script, "args": program_args}
    if program in {"python", "python3"} and "-m" in program_args:
        module_index = program_args.index("-m") + 1
        module = program_args[module_index] if module_index < len(program_args) else None
        return {"kind": "python-module", "program": program, "module": module, "args": program_args}
    if program in {"python", "python3"} and program_args and program_args[0].endswith(".py"):
        return {"kind": "python-script", "program": program_args[0], "script": program_args[0], "args": program_args[1:]}
    if program and program.endswith(".py"):
        return {"kind": "python-script", "program": program, "script": program, "args": program_args}
    return {"kind": "console-script", "program": program, "args": program_args}


def resolve_entrypoint_file(
    target_dir: Path,
    project_dir: Path | None,
    run_intent: dict[str, Any],
) -> Path | None:
    program = run_intent.get("program")
    if not program:
        return None
    if run_intent.get("kind") == "python-module" and run_intent.get("module"):
        return module_to_file(target_dir, str(run_intent["module"]))
    entrypoint = console_entrypoints(target_dir).get(str(program))
    if entrypoint:
        module, _function = entrypoint
        found = module_to_file(target_dir, module)
        if found:
            return found
    if str(program).endswith(".py"):
        mapped = map_app_path_to_local(str(program), target_dir.parent, target_dir)
        if mapped.exists():
            return mapped
        entrypoints = console_entrypoints(target_dir)
        if len(entrypoints) == 1:
            module, _function = next(iter(entrypoints.values()))
            found = module_to_file(target_dir, module)
            if found:
                return found
    if str(program).isidentifier():
        function_file = find_function_file(target_dir, str(program))
        if function_file:
            return function_file
    package_dir = best_package_for_program(target_dir, project_dir, str(program))
    if package_dir:
        for name in ("__main__.py", "main.py", "server.py", "cli.py", "__init__.py"):
            candidate = package_dir / name
            if candidate.exists():
                return candidate
    return None


def resolve_python_entrypoint(
    target_dir: Path,
    project_dir: Path | None,
    script_file: Path | None,
    run_intent: dict[str, Any],
) -> dict[str, Any]:
    if run_intent.get("kind") == "python-module" and run_intent.get("module"):
        return {"kind": "module", "module": run_intent["module"], "argv": run_intent.get("args", [])}
    if not script_file:
        return {}
    if run_intent.get("kind") == "mcp-run":
        return {"kind": "mcp-run"}
    program = str(run_intent.get("program") or "")
    entrypoints = console_entrypoints(target_dir)
    entrypoint = entrypoints.get(program)
    if not entrypoint and run_intent.get("kind") == "python-script" and len(entrypoints) == 1:
        entrypoint = next(iter(entrypoints.values()))
    if entrypoint:
        module, function = entrypoint
        if "." in function:
            object_name, method = function.split(".", 1)
            return {
                "kind": "object-method",
                "module": module,
                "object": object_name,
                "method": method,
                "argv": run_intent.get("args", []),
            }
        entrypoint_file = module_to_file(target_dir, module)
        if entrypoint_file and function_name_in_file(entrypoint_file, function):
            return {"kind": "function", "module": module, "function": function, "argv": run_intent.get("args", [])}
    module = module_name_for_script(target_dir, project_dir, script_file)
    if not module:
        return {}
    if program and program.isidentifier():
        function = function_name_in_file(script_file, program)
        if function:
            return {"kind": "function", "module": module, "function": function}
    text = script_file.read_text(encoding="utf-8", errors="replace")
    if "if __name__" in text or script_file.name == "__main__.py":
        return {"kind": "module", "module": module, "argv": run_intent.get("args", [])}
    for function in ("main", "serve"):
        if function_name_in_file(script_file, function):
            return {"kind": "function", "module": module, "function": function}
    if "FastMCP" in text and re.search(r"\bmcp\s*=", text):
        return {"kind": "fastmcp-object", "module": module, "object": "mcp"}
    return {}


def python_function_runtime_args(
    python_bin: str,
    module: str,
    function: str,
    python_path_dirs: list[str],
    argv: list[str] | None = None,
) -> list[str]:
    code = (
        "import asyncio, importlib, inspect, sys; "
        f"sys.path[:0] = {json.dumps(python_path_dirs)}; "
        f"sys.argv = {[f'{module}:{function}', *(argv or [])]!r}; "
        f"fn = getattr(importlib.import_module({module!r}), {function!r}); "
        "result = fn(); "
        "asyncio.run(result) if inspect.isawaitable(result) else None"
    )
    return [python_bin, "-u", "-c", code]


def python_object_method_runtime_args(
    python_bin: str,
    module: str,
    object_name: str,
    method: str,
    python_path_dirs: list[str],
) -> list[str]:
    code = (
        "import importlib, sys; "
        f"sys.path[:0] = {json.dumps(python_path_dirs)}; "
        f"obj = getattr(importlib.import_module({module!r}), {object_name!r}); "
        f"getattr(obj, {method!r})()"
    )
    return [python_bin, "-u", "-c", code]


def python_path_container_dirs(target_dir: Path, project_dir: Path | None, script_file: Path | None) -> list[str]:
    dirs: list[str] = []
    safe_script_parent = None
    if script_file and needs_script_parent_pythonpath(script_file):
        safe_script_parent = script_file.parent
    for local in [project_dir, likely_source_root(target_dir), safe_script_parent, target_dir]:
        container = container_path_for(target_dir, local) if local else None
        if container and container not in dirs:
            dirs.append(container)
    return dirs


SHADOW_PRONE_MODULES = {
    "asyncio",
    "concurrent",
    "email",
    "http",
    "json",
    "logging",
    "mcp",
    "os",
    "pathlib",
    "re",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "time",
    "types",
    "typing",
    "urllib",
}


def needs_script_parent_pythonpath(script_file: Path) -> bool:
    parent = script_file.parent
    for module in SHADOW_PRONE_MODULES:
        if (parent / f"{module}.py").exists() or (parent / module / "__init__.py").exists():
            return False
    roots = import_roots_in_file(script_file)
    for root in roots:
        if (parent / f"{root}.py").exists() or (parent / root / "__init__.py").exists():
            return True
    return False


def import_roots_in_file(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    roots: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return import_roots_from_text(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def import_roots_from_text(text: str) -> set[str]:
    roots: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("import "):
            for name in line.removeprefix("import ").split(","):
                roots.add(name.strip().split(" ", 1)[0].split(".", 1)[0])
        elif line.startswith("from ") and not line.startswith("from ."):
            parts = line.split()
            if len(parts) >= 2:
                roots.add(parts[1].split(".", 1)[0])
    return {root for root in roots if root}


def console_entrypoints(target_dir: Path) -> dict[str, tuple[str, str]]:
    entrypoints: dict[str, tuple[str, str]] = pyproject_script_entrypoints(target_dir)
    for path in sorted(target_dir.rglob("entry_points.txt")):
        if ".egg-info" not in path.parts:
            continue
        section = None
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section == "console_scripts" and "=" in line and ":" in line:
                name, value = [part.strip() for part in line.split("=", 1)]
                module, function = [part.strip() for part in value.split(":", 1)]
                entrypoints[name] = (module, function)
    return entrypoints


def pyproject_script_entrypoints(target_dir: Path) -> dict[str, tuple[str, str]]:
    entrypoints: dict[str, tuple[str, str]] = {}
    for path in sorted(target_dir.rglob("pyproject.toml")):
        if ".venv" in path.parts:
            continue
        in_scripts = False
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                in_scripts = line == "[project.scripts]"
                continue
            if not in_scripts:
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*=\s*[\"']([^:\"']+):([^\"']+)[\"']", line)
            if match:
                entrypoints[match.group(1)] = (match.group(2), match.group(3))
    return entrypoints


def module_to_file(target_dir: Path, module: str) -> Path | None:
    parts = module.split(".")
    for base in [likely_source_root(target_dir), target_dir]:
        if not base:
            continue
        candidate = base.joinpath(*parts).with_suffix(".py")
        if candidate.exists():
            return candidate
        package_main = base.joinpath(*parts, "__main__.py")
        if package_main.exists():
            return package_main
        package_init = base.joinpath(*parts, "__init__.py")
        if package_init.exists():
            return package_init
    return None


def module_name_for_script(target_dir: Path, project_dir: Path | None, script_file: Path) -> str | None:
    roots = [likely_source_root(target_dir), project_dir, target_dir]
    for root in [root for root in roots if root]:
        try:
            relative = script_file.relative_to(root)
        except ValueError:
            continue
        if relative.suffix != ".py":
            continue
        parts = list(relative.with_suffix("").parts)
        if not all(part.isidentifier() for part in parts):
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)
    return None


def best_package_for_program(target_dir: Path, project_dir: Path | None, program: str) -> Path | None:
    packages = [
        path.parent
        for path in target_dir.rglob("__init__.py")
        if ".venv" not in path.parts and "__pycache__" not in path.parts and ".egg-info" not in path.parts
    ]
    if not packages:
        return None
    program_tokens = token_set(program)
    exact_name = slugify(program).replace("_", "-")
    ranked: list[tuple[int, int, str, Path]] = []
    for package in packages:
        name = package.name
        name_tokens = token_set(name)
        overlap = len(program_tokens & name_tokens)
        score = overlap * 10
        if slugify(name) == slugify(program):
            score += 100
        if exact_name and exact_name in name.replace("_", "-"):
            score += 30
        if project_dir and package.is_relative_to(project_dir):
            score += 5
        if score > 0:
            ranked.append((-score, len(package.relative_to(target_dir).parts), str(package), package))
    if not ranked:
        return None
    return sorted(ranked)[0][3]


def token_set(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-zA-Z0-9]+", value.lower()) if token and token not in {"mcp", "server"}}


def function_name_in_file(path: Path, function: str) -> str | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return function if re.search(rf"^\s*(async\s+def|def)\s+{re.escape(function)}\s*\(", text, re.MULTILINE) else None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function:
            return function
    return None


def find_function_file(target_dir: Path, function: str) -> Path | None:
    matches = []
    for path in target_dir.rglob("*.py"):
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        if function_name_in_file(path, function):
            matches.append(path)
    if not matches:
        return None
    return sorted(matches, key=lambda path: (len(path.relative_to(target_dir).parts), str(path)))[0]


def dependency_status_for(normalized: dict[str, Any]) -> str:
    if normalized.get("has_uv_lock"):
        return "uv-lock"
    if normalized.get("has_pyproject"):
        return "pyproject"
    if normalized.get("with_packages"):
        return "uv-with"
    return "unknown"


def infer_risk_hints(target_dir: Path, command: str, args: list[str]) -> list[str]:
    hints: set[str] = set()
    joined = " ".join([command, *args]).lower()
    if command == "bash":
        hints.add("prestart-shell")
    for marker, hint in [
        ("curl ", "network-egress"),
        ("nc ", "network-egress"),
        ("/dev/tcp", "reverse-shell"),
        ("rm -rf", "destructive-filesystem"),
        ("authorized_keys", "persistence"),
        ("openssl cms", "sensitive-file-read"),
        ("docker", "docker-related"),
        ("kubectl", "kubernetes-related"),
    ]:
        if marker in joined:
            hints.add(hint)
    sample = "\n".join(
        path.read_text(errors="replace")[:5000]
        for path in sorted(target_dir.glob("*.py"))[:3]
    ).lower()
    if "os.getenv" in sample or "os.environ" in sample:
        hints.add("env-access")
    if "subprocess" in sample or "os.system" in sample:
        hints.add("process-spawn")
    if "httpx" in sample or "requests" in sample or "urllib" in sample:
        hints.add("network-code")
    return sorted(hints)


def write_connor_build_contexts(
    inventory_path: str | Path,
    out_dir: str | Path,
    ids: list[str] | None = None,
    groups: list[str] | None = None,
) -> list[dict[str, Any]]:
    items = filter_inventory(load_inventory(inventory_path), ids=ids, groups=groups)
    out = Path(out_dir)
    records: list[dict[str, Any]] = []
    for item in items:
        item_dir = out / item.id
        item_dir.mkdir(parents=True, exist_ok=True)
        context_dir = item_dir / "context"
        sync_build_context(Path(item.target_dir), context_dir)
        apply_build_context_shims(context_dir)
        dockerfile = item_dir / "Dockerfile"
        dockerfile.write_text(render_dockerfile(item), encoding="utf-8")
        metadata = {
            "target_id": item.id,
            "context_dir": str(context_dir),
            "dockerfile": str(dockerfile),
            "image": image_name_for(item.id),
        }
        (item_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        records.append(metadata)
    write_jsonl(out / "build_contexts.jsonl", records)
    return records


def run_connor_builds(
    inventory_path: str | Path,
    out_dir: str | Path,
    jobs: int = 1,
    ids: list[str] | None = None,
    groups: list[str] | None = None,
    build_timeout_seconds: int = 900,
) -> list[ConnorBuildResult]:
    records = write_connor_build_contexts(inventory_path, out_dir, ids=ids, groups=groups)
    out = Path(out_dir)
    results: list[ConnorBuildResult] = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        futures = [executor.submit(build_one_context, record, build_timeout_seconds) for record in records]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            write_json(out / result.target_id / "build_result.json", asdict(result))
            print(f"{result.target_id}: {result.build_status}", flush=True)
    results.sort(key=lambda result: result.target_id)
    write_build_summary(out / "build_summary.csv", results)
    return results


def build_one_context(record: dict[str, Any], timeout_seconds: int) -> ConnorBuildResult:
    started = time.monotonic()
    status, reason = run_docker_build(record, timeout_seconds)
    if status != "built" and should_retry_amd64(reason):
        retry_status, retry_reason = run_docker_build(record, timeout_seconds, platform="linux/amd64")
        status = retry_status
        reason = "" if retry_status == "built" else retry_reason
    return ConnorBuildResult(
        target_id=record["target_id"],
        image=record["image"],
        build_status=status,
        dockerfile=record["dockerfile"],
        context_dir=record["context_dir"],
        reason=reason,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def run_docker_build(record: dict[str, Any], timeout_seconds: int, platform: str | None = None) -> tuple[str, str]:
    cmd = [
        "docker",
        "build",
    ]
    if platform:
        cmd.extend(["--platform", platform])
    cmd.extend([
        "-f",
        record["dockerfile"],
        "-t",
        record["image"],
        record["context_dir"],
    ])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        reason = "" if proc.returncode == 0 else (proc.stderr or proc.stdout)[-4000:]
        status = "built" if proc.returncode == 0 else classify_build_failure(reason)
    except subprocess.TimeoutExpired as exc:
        status = "build_timeout"
        output = "\n".join(part for part in [exc.stdout or "", exc.stderr or ""] if part)
        reason = (output or f"docker build exceeded {timeout_seconds}s")[-4000:]
    return status, reason


def should_retry_amd64(reason: str) -> bool:
    lowered = reason.lower()
    if "aarch64" not in lowered:
        return False
    return "doesn't have a source distribution or wheel" in lowered or "only has wheels" in lowered


def classify_build_failure(reason: str) -> str:
    lowered = reason.lower()
    if "docker desktop is unable to start" in lowered:
        return "docker_unavailable"
    if "failed to connect to the docker api" in lowered:
        return "docker_unavailable"
    if "cannot connect to the docker daemon" in lowered:
        return "docker_unavailable"
    if "docker.sock" in lowered and "no such file" in lowered:
        return "docker_unavailable"
    return "dependency_error"


def sync_build_context(source_dir: Path, context_dir: Path) -> None:
    if context_dir.exists():
        shutil.rmtree(context_dir)
    ignore = shutil.ignore_patterns(
        ".venv",
        ".uv-cache",
        "__pycache__",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        "*.pyc",
        ".DS_Store",
    )
    shutil.copytree(source_dir, context_dir, ignore=ignore)
    (context_dir / ".dockerignore").write_text(
        "\n".join([
            ".venv",
            ".uv-cache",
            "__pycache__",
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            "*.pyc",
            ".DS_Store",
            "",
        ]),
        encoding="utf-8",
    )


def apply_build_context_shims(context_dir: Path) -> None:
    apply_storyscan_gas_utils_shim(context_dir)


def apply_storyscan_gas_utils_shim(context_dir: Path) -> None:
    for service in context_dir.rglob("storyscan_service.py"):
        text = service.read_text(encoding="utf-8", errors="replace")
        if "utils.gas_utils" not in text:
            continue
        project_root = service.parent.parent
        gas_utils = project_root / "utils" / "gas_utils.py"
        if gas_utils.exists():
            continue
        gas_utils.parent.mkdir(parents=True, exist_ok=True)
        (gas_utils.parent / "__init__.py").write_text("", encoding="utf-8")
        gas_utils.write_text(STORYSCAN_GAS_UTILS_SHIM, encoding="utf-8")


STORYSCAN_GAS_UTILS_SHIM = '''"""Generated compatibility shim for incomplete Connor Storyscan fixtures."""

WEI_PER_ETH = 10**18
WEI_PER_GWEI = 10**9


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def wei_to_gwei(value):
    return _as_float(value) / WEI_PER_GWEI


def gwei_to_wei(value):
    return _as_float(value) * WEI_PER_GWEI


def wei_to_eth(value):
    return _as_float(value) / WEI_PER_ETH


def eth_to_wei(value):
    return _as_float(value) * WEI_PER_ETH


def gwei_to_eth(value):
    return wei_to_eth(gwei_to_wei(value))


def format_token_balance(value, decimals=18, precision=6):
    amount = _as_float(value) / (10 ** int(decimals))
    return f"{amount:.{precision}f}".rstrip("0").rstrip(".")


def format_gas_prices(prices):
    if isinstance(prices, dict):
        return ", ".join(f"{key}: {value}" for key, value in prices.items())
    return str(prices)


def format_gas_amount(value):
    return f"{wei_to_gwei(value):.6f} gwei"
'''


IMPORT_PACKAGE_MAP = {
    "akshare": "akshare",
    "akshare_one": "akshare-one",
    "aiohttp": "aiohttp",
    "bs4": "beautifulsoup4",
    "boto3": "boto3",
    "click": "click",
    "deep_translator": "deep-translator",
    "dotenv": "python-dotenv",
    "fastapi": "fastapi",
    "fastmcp": "fastmcp",
    "feedparser": "feedparser",
    "ffmpeg": "ffmpeg-python",
    "github": "PyGithub",
    "gtrending": "gtrending",
    "html2text": "html2text",
    "httpx": "httpx",
    "langdetect": "langdetect",
    "lxml": "lxml",
    "markdownify": "markdownify",
    "mcp": "mcp[cli]",
    "numpy": "numpy",
    "openpyxl": "openpyxl",
    "opml": "opml",
    "pandas": "pandas",
    "patchright": "patchright",
    "pdf2image": "pdf2image",
    "PIL": "pillow",
    "pptx": "python-pptx",
    "pydantic": "pydantic",
    "pyarrow": "pyarrow",
    "pythonjsonlogger": "python-json-logger",
    "requests": "requests",
    "selenium": "selenium",
    "sqlalchemy": "sqlalchemy",
    "starlette": "starlette",
    "tabulate": "tabulate",
    "tika": "tika",
    "tree_sitter": "tree-sitter",
    "tree_sitter_c_sharp": "tree-sitter-c-sharp",
    "tree_sitter_java": "tree-sitter-java",
    "tree_sitter_javascript": "tree-sitter-javascript",
    "tree_sitter_python": "tree-sitter-python",
    "typer": "typer",
    "uvicorn": "uvicorn",
    "whisper": "openai-whisper",
    "yaml": "PyYAML",
}


def inferred_runner_packages(item: ConnorInventoryItem) -> list[str]:
    target_dir = Path(item.target_dir)
    packages = ["mcp[cli]", "fastmcp"]
    packages.extend(str(pkg) for pkg in item.normalized.get("with_packages", []))
    packages.extend(read_egg_requires(target_dir))
    packages.extend(scan_import_requirements(target_dir))
    packages.extend(scan_fastmcp_dependency_hints(target_dir))
    return dedupe_packages(packages)


def read_egg_requires(target_dir: Path) -> list[str]:
    packages: list[str] = []
    for path in sorted(target_dir.rglob("requires.txt")):
        if ".egg-info" not in path.parts:
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("[") or line.startswith("#"):
                continue
            packages.append(line.split(";", 1)[0].strip())
    return packages


def scan_import_requirements(target_dir: Path) -> list[str]:
    packages: set[str] = set()
    for path in sorted(target_dir.rglob("*.py"))[:300]:
        if ".venv" in path.parts or "__pycache__" in path.parts or ".egg-info" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            packages.update(import_requirements_from_text(text))
            continue
        for node in ast.walk(tree):
            root: str | None = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in IMPORT_PACKAGE_MAP:
                        packages.add(IMPORT_PACKAGE_MAP[root])
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".", 1)[0]
                if root in IMPORT_PACKAGE_MAP:
                    packages.add(IMPORT_PACKAGE_MAP[root])
    return sorted(packages)


def import_requirements_from_text(text: str) -> set[str]:
    packages: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("import "):
            names = line.removeprefix("import ").split(",")
            for name in names:
                root = name.strip().split(" ", 1)[0].split(".", 1)[0]
                if root in IMPORT_PACKAGE_MAP:
                    packages.add(IMPORT_PACKAGE_MAP[root])
        elif line.startswith("from "):
            parts = line.split()
            if len(parts) >= 2:
                root = parts[1].split(".", 1)[0]
                if root in IMPORT_PACKAGE_MAP:
                    packages.add(IMPORT_PACKAGE_MAP[root])
    return packages


def scan_fastmcp_dependency_hints(target_dir: Path) -> list[str]:
    packages: set[str] = set()
    for path in sorted(target_dir.rglob("*.py"))[:300]:
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"dependencies\s*=\s*(\[[^\]]*\])", text):
            try:
                parsed = ast.literal_eval(match.group(1))
            except (SyntaxError, ValueError):
                continue
            if isinstance(parsed, list):
                packages.update(str(item) for item in parsed if isinstance(item, str))
    return sorted(packages)


def dedupe_packages(packages: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for package in packages:
        package = package.strip()
        if not package:
            continue
        key = canonical_package_key(package)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(package)
    return deduped


def canonical_package_key(package: str) -> str:
    return re.split(r"[<>=!~;\[]", package, maxsplit=1)[0].strip().lower().replace("_", "-")


def shell_package_list(packages: list[str]) -> str:
    return " ".join(shell_quote(pkg) for pkg in packages)


def render_dockerfile(item: ConnorInventoryItem) -> str:
    target = f"/app/{item.container_dir}"
    normalized = item.normalized
    project = normalized.get("project_container_dir") or target
    with_packages = normalized.get("with_packages") or []
    uvx_package = normalized.get("uvx_package")
    runner_packages = inferred_runner_packages(item)
    warmup_lines = docker_warmup_lines(item, project)
    install_lines: list[str] = []
    if uvx_package:
        install_lines.append(f"uv tool install {shell_quote(str(uvx_package))}")
    elif normalized.get("has_pyproject"):
        install_lines.append(
            f"(uv --directory {shell_quote(project)} sync --locked || "
            f"uv --directory {shell_quote(project)} sync)"
        )
        extra_packages = dedupe_packages(
            list(with_packages)
            + (["mcp[cli]"] if normalized.get("entrypoint", {}).get("kind") == "mcp-run" else [])
        )
        if extra_packages:
            install_lines.append(f"uv --directory {shell_quote(project)} pip install {shell_package_list(extra_packages)}")
    elif with_packages:
        install_lines.append(
            "python -m venv /opt/runner-venv && "
            "/opt/runner-venv/bin/pip install --upgrade pip && "
            f"/opt/runner-venv/bin/pip install {shell_package_list(runner_packages)}"
        )
    else:
        required = ["mcp[cli]", "fastmcp"]
        optional = [pkg for pkg in runner_packages if canonical_package_key(pkg) not in {canonical_package_key(item) for item in required}]
        optional_install = ""
        if optional:
            optional_install = (
                " && for pkg in " + " ".join(shell_quote(pkg) for pkg in optional) + "; do "
                "/opt/runner-venv/bin/pip install \"$pkg\" || echo \"warning: optional dependency failed: $pkg\"; "
                "done"
            )
        install_lines.append(
            "python -m venv /opt/runner-venv && "
            f"/opt/runner-venv/bin/pip install --upgrade pip {shell_package_list(required)}"
            f"{optional_install}"
        )
    install_lines.extend(warmup_lines)
    install = " \\\n    && ".join(install_lines)
    return f"""FROM python:3.13-slim

RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        bash ca-certificates curl dnsutils ffmpeg git iproute2 libgl1 libglib2.0-0 libsm6 libxext6 libxrender1 netcat-openbsd openssl poppler-utils procps \\
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

ENV PYTHONUNBUFFERED=1 \\
    PYTHONDONTWRITEBYTECODE=1 \\
    UV_CACHE_DIR=/opt/uv-cache \\
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \\
    HOME=/opt/uv-home \\
    XDG_CACHE_HOME=/opt/uv-cache \\
    HF_HOME=/opt/uv-home/.cache/huggingface \\
    SENTENCE_TRANSFORMERS_HOME=/opt/uv-home/.cache/torch/sentence_transformers

WORKDIR {dockerfile_escape_path(target)}
COPY [".", {json.dumps(target)}]

RUN find {shell_quote(target)} -type d \\( -name .venv -o -name .uv-cache -o -name __pycache__ \\) -prune -exec rm -rf {{}} + \\
    && mkdir -p /opt/uv-cache /opt/uv-home /opt/uv-python /tmp/uv-cache /tmp/home /tmp/cache /sandbox/data /sandbox/output /canary \\
    && {install}

ENTRYPOINT []
"""


def docker_warmup_lines(item: ConnorInventoryItem, project_container_dir: str) -> list[str]:
    text = target_text_sample(Path(item.target_dir))
    lines: list[str] = []
    if "whisper.load_model" in text:
        lines.append("/opt/runner-venv/bin/python -c 'import whisper; whisper.load_model(\"base\")'")
    model = "sentence-transformers/multi-qa-MiniLM-L6-cos-v1"
    if model in text:
        python_bin = f"{project_container_dir}/.venv/bin/python" if item.normalized.get("has_pyproject") else "/opt/runner-venv/bin/python"
        lines.append(
            "HF_HOME=/opt/uv-home/.cache/huggingface "
            "SENTENCE_TRANSFORMERS_HOME=/opt/uv-home/.cache/torch/sentence_transformers "
            f"{shell_quote(python_bin)} -c 'from sentence_transformers import SentenceTransformer; SentenceTransformer(\"{model}\")'"
        )
    return lines


def target_text_sample(target_dir: Path) -> str:
    chunks: list[str] = []
    for path in sorted(target_dir.rglob("*.py"))[:500]:
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    for path in sorted(target_dir.rglob("*.json"))[:200]:
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def run_connor_targets(
    inventory_path: str | Path,
    stage: ConnorStage,
    profile: SandboxProfile,
    out_dir: str | Path,
    resume: bool = False,
    ids: list[str] | None = None,
    execution_mode: ExecutionMode = "normalized-command",
    task_count: int = 5,
    audit_models: list[str] | None = None,
    agent_model: str | None = None,
    groups: list[str] | None = None,
) -> list[ConnorRunResult]:
    items = filter_inventory(load_inventory(inventory_path), ids=ids, groups=groups)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    proxy: EgressProxy | None = None
    if profile == "production-observed":
        proxy = EgressProxy(out / "egress_log.jsonl")
        proxy.start()
    results: list[ConnorRunResult] = []
    try:
        for item in items:
            target_out = out / "targets" / item.id
            result_path = target_out / "connor_result.json"
            if resume and result_path.exists():
                print(f"{item.id}: skipped", flush=True)
                continue
            target_out.mkdir(parents=True, exist_ok=True)
            result = run_one_connor_target(
                item=item,
                stage=stage,
                profile=profile,
                execution_mode=execution_mode,
                target_out=target_out,
                task_count=task_count,
                audit_models=audit_models,
                agent_model=agent_model,
            )
            write_json(result_path, asdict(result))
            results.append(result)
            print(f"{item.id}: {result.classification} ({result.startup_status}, tools={result.tools_listed}, calls={result.tool_calls_completed}/{result.tool_calls_attempted})", flush=True)
    finally:
        if proxy:
            proxy.stop()
    write_connor_run_summary(out, load_connor_results_from_run(out))
    return results


def run_one_connor_target(
    item: ConnorInventoryItem,
    stage: ConnorStage,
    profile: SandboxProfile,
    execution_mode: ExecutionMode,
    target_out: Path,
    task_count: int,
    audit_models: list[str] | None,
    agent_model: str | None,
) -> ConnorRunResult:
    started = time.monotonic()
    image = image_name_for(item.id)
    build_status = "built" if docker_image_exists(image) else "missing"
    if build_status != "built":
        result = ConnorRunResult(
            target_id=item.id,
            group=item.group,
            label=item.label,
            stage=stage,
            sandbox_profile=profile,
            execution_mode=execution_mode,
            image=image,
            startup_status="failed",
            build_status=build_status,
            classification="unsupported_runtime",
            tools_listed=0,
            tool_calls_attempted=0,
            tool_calls_completed=0,
            error=f"Docker image not found: {image}",
            duration_seconds=round(time.monotonic() - started, 3),
        )
        write_json(target_out / "inventory_item.json", asdict(item))
        return result
    target = target_config_for_item(item, image, profile, execution_mode)
    trace: list[TraceEvent] = []
    tools: list[ToolMetadata] = []
    findings: list[Finding] = []
    run_audit_verdicts: list[dict[str, Any]] = []
    attempted = 0
    completed = 0
    startup_status = "failed"
    error = ""
    session: McpSession | None = None
    try:
        if stage == "production":
            scan = run_production_scan(target, item, task_count, audit_models, agent_model)
            write_result(scan, target_out / "scan")
            tools = scan.tools
            trace = scan.trace
            findings = scan.findings
            attempted = sum(len(agent_trace.selected_tool_calls) for agent_trace in scan.agent_traces)
            completed = sum(
                1
                for agent_trace in scan.agent_traces
                for call in agent_trace.selected_tool_calls
                if call.result is not None
            )
            startup_status = "started" if scan.status in {"ok", "contract_violation"} or scan.tools else "failed"
            classification = classify_scan_result(scan.status, trace, findings, item)
            run_audit_verdicts = [asdict(verdict) for verdict in scan.run_audit_verdicts]
        else:
            session = McpSession(target, Path("."))
            with session:
                startup_status = "started"
                session.initialize()
                tools = session.list_tools()
                if stage == "toolcall" and tools:
                    for test in generate_tests(tools)[: max(1, min(3, len(tools)))]:
                        attempted += 1
                        try:
                            session.call_tool(test.tool_name, test.arguments)
                            completed += 1
                        except McpClientError as exc:
                            error = str(exc)
                            session.trace.append(TraceEvent("harness.tool_error", str(exc), {
                                "tool": test.tool_name,
                                "arguments": test.arguments,
                            }))
                            break
                trace = list(session.trace)
            findings = []
            classification = classify_direct_result(stage, tools, attempted, completed, trace, error, item)
    except McpClientError as exc:
        error = str(exc)
        if session:
            trace = list(session.trace)
        startup_status = classify_startup_status(error)
        classification = classify_error(f"{diagnostic_text(trace)}\n{error}", item)
        trace.append(TraceEvent("harness.error", error))
    except Exception as exc:  # Keep all-target runs moving and classify the harness failure.
        error = f"{type(exc).__name__}: {exc}"
        if session:
            trace = list(session.trace)
        startup_status = "failed"
        classification = "harness_bug"
        trace.append(TraceEvent("harness.error", error))
    write_json(target_out / "target.json", asdict(target))
    write_json(target_out / "inventory_item.json", asdict(item))
    write_json(target_out / "tools.json", [asdict(tool) for tool in tools])
    write_jsonl(target_out / "trace.jsonl", [asdict(event) for event in trace])
    observations = observations_from_trace(trace)
    return ConnorRunResult(
        target_id=item.id,
        group=item.group,
        label=item.label,
        stage=stage,
        sandbox_profile=profile,
        execution_mode=execution_mode,
        image=image,
        startup_status=startup_status,
        build_status=build_status,
        classification=classification,
        tools_listed=len(tools),
        tool_calls_attempted=attempted,
        tool_calls_completed=completed,
        findings=[asdict(finding) for finding in findings],
        run_audit_verdicts=run_audit_verdicts,
        observations=observations,
        error=error,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def run_production_scan(
    target: TargetConfig,
    item: ConnorInventoryItem,
    task_count: int,
    audit_models: list[str] | None,
    agent_model: str | None,
) -> ScanResult:
    trace: list[TraceEvent] = []
    tools: list[ToolMetadata] = []
    contract = Contract(target_id=item.id, source=item.source, tools=[])
    tests: list[TestInvocation] = []
    generated_tasks: list[GeneratedTask] = []
    packets: list[AuditPacket] = []
    run_verdicts: list[RunAuditVerdict] = []
    findings: list[Finding] = []
    agent_traces = []
    status = "ok"
    try:
        with McpSession(target, Path(".")) as session:
            session.initialize()
            tools = session.list_tools()
            contract = build_contract_with_llm(item.id, item.source, tools, OpenAILlmClient(role="contract"))
            tests = generate_tests(tools)
            generated_tasks = generate_tasks_with_llm(item.id, tools, OpenAILlmClient(role="task"), count=task_count)
            agent_runner = OpenAIAgentRunner(model=agent_model, max_steps=3)
            for task in generated_tasks:
                agent_traces.append(agent_runner.run(task.user_task, tools, session, task_id=task.id))
            trace = list(session.trace)
            packets = build_audit_packets(item.id, tools, contract, tests, trace, agent_traces=agent_traces)
            for model in resolve_audit_models(audit_models, None, None):
                run_verdicts.append(
                    audit_run_with_llm(
                        item.id,
                        tools,
                        contract,
                        generated_tasks,
                        agent_traces,
                        trace,
                        OpenAILlmClient(model=model, role="audit"),
                    )
                )
            findings.extend(findings_from_run_audit_verdicts(run_verdicts))
            status = "contract_violation" if findings else "ok"
    except McpClientError as exc:
        status = "mcp_error"
        trace.append(TraceEvent("harness.error", str(exc)))
    except (LlmUnavailable, LlmClientError) as exc:
        status = "llm_error"
        trace.append(TraceEvent("llm.error", str(exc)))
    return ScanResult(
        target=target,
        tools=tools,
        contract=contract,
        tests=tests,
        generated_tasks=generated_tasks,
        trace=trace,
        findings=findings,
        status=status,
        agent_traces=agent_traces,
        audit_packets=packets,
        audit_verdicts=[],
        run_audit_verdicts=run_verdicts,
    )


def target_config_for_item(
    item: ConnorInventoryItem,
    image: str,
    profile: SandboxProfile,
    execution_mode: ExecutionMode,
) -> TargetConfig:
    docker_args = docker_run_prefix(profile, container_name=docker_container_name_for(item.id))
    docker_args.extend(env_flags_for_profile(profile, item))
    if execution_mode == "original-command":
        runtime_args = rewrite_app_paths_for_target([item.original_command, *item.original_args], Path(item.target_dir))
        workdir = f"/app/{item.container_dir}"
    else:
        runtime_args = [str(arg) for arg in item.normalized.get("runtime_args", [])]
        workdir = item.normalized.get("runtime_workdir") or f"/app/{item.container_dir}"
    docker_args.extend(["-w", workdir, image, *runtime_args])
    timeout = 60 if profile == "production-observed" else 30
    return TargetConfig(
        id=item.id,
        source=item.source,
        label=item.label,  # type: ignore[arg-type]
        command="docker",
        args=docker_args,
        env={},
        transport="stdio",
        stdio_framing="jsonl",
        protocol_version="2024-11-05",
        timeout_seconds=timeout,
        notes=f"{item.source} via {execution_mode}/{profile}",
    )


def docker_run_prefix(profile: SandboxProfile, container_name: str | None = None) -> list[str]:
    args = [
        "run", "--rm", "-i",
    ]
    if container_name:
        args.extend(["--name", container_name])
    args.extend([
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "1g",
        "--cpus", "1.0",
    ])
    if profile in {"preflight-strict", "toolcall-strict"}:
        args.extend([
            "--network", "none",
            "--tmpfs", "/tmp:rw,nosuid,size=256m",
            "--tmpfs", "/home:rw,nosuid,size=64m",
            "--tmpfs", "/sandbox:rw,nosuid,size=128m",
        ])
    else:
        args.extend([
            "--network", "bridge",
            "--add-host", "host.docker.internal:host-gateway",
            "--tmpfs", "/tmp:rw,nosuid,size=512m",
            "--tmpfs", "/sandbox:rw,nosuid,size=256m",
        ])
    return args


def env_flags_for_profile(profile: SandboxProfile, item: ConnorInventoryItem) -> list[str]:
    env = {
        "PYTHONUNBUFFERED": "1",
        "UV_CACHE_DIR": "/opt/uv-cache",
        "UV_PYTHON_INSTALL_DIR": "/opt/uv-python",
        "HOME": "/opt/uv-home",
        "XDG_CACHE_HOME": "/opt/uv-cache",
        "HF_HOME": "/opt/uv-home/.cache/huggingface",
        "SENTENCE_TRANSFORMERS_HOME": "/opt/uv-home/.cache/torch/sentence_transformers",
        "MCP_HARNESS_CANARY_SECRET": f"CANARY_SECRET_{item.id}",
        "OPENAI_API_KEY": f"CANARY_OPENAI_{item.id}",
        "GITHUB_TOKEN": f"CANARY_GITHUB_{item.id}",
        "AWS_SECRET_ACCESS_KEY": f"CANARY_AWS_{item.id}",
    }
    python_path = item.normalized.get("python_path_container_dirs", [])
    if python_path:
        env["PYTHONPATH"] = ":".join(str(path) for path in python_path)
    if profile == "production-observed":
        env.update({
            "HTTP_PROXY": "http://host.docker.internal:8787",
            "HTTPS_PROXY": "http://host.docker.internal:8787",
            "ALL_PROXY": "http://host.docker.internal:8787",
            "NO_PROXY": "localhost,127.0.0.1",
        })
    flags: list[str] = []
    for key, value in {**env, **item.original_env}.items():
        flags.extend(["-e", f"{key}={value}"])
    return flags


def classify_startup_status(error: str) -> str:
    lowered = error.lower()
    if "timeout" in lowered:
        return "timeout"
    if "closed stdout" in lowered or "no such file or directory" in lowered:
        return "failed"
    if "json" in lowered or "content-length" in lowered or "protocol" in lowered:
        return "protocol_error"
    return "failed"


def classify_direct_result(
    stage: str,
    tools: list[ToolMetadata],
    attempted: int,
    completed: int,
    trace: list[TraceEvent],
    error: str,
    item: ConnorInventoryItem,
) -> str:
    text = trace_text(trace) + " " + error
    if not tools:
        return classify_error(text, item)
    if stage == "preflight":
        return "tested_ok"
    if completed > 0:
        if '"isError": true' in text or "'isError': True" in text:
            return "tool_returned_error"
        return "tested_ok"
    return classify_error(text, item)


def classify_scan_result(status: str, trace: list[TraceEvent], findings: list[Finding], item: ConnorInventoryItem) -> str:
    if status == "ok":
        return "tested_ok"
    if status == "contract_violation":
        return "tested_ok" if findings else "tool_returned_error"
    return classify_error(trace_text(trace), item)


def classify_error(text: str, item: ConnorInventoryItem) -> str:
    lowered = text.lower()
    if "api key" in lowered or "token" in lowered or "credential" in lowered or "unauthorized" in lowered:
        return "needs_key"
    if "network" in lowered or "name resolution" in lowered or "connection" in lowered or "dns" in lowered:
        return "needs_network"
    if "prestart-shell" in item.risk_hints:
        return "startup_payload_observed"
    if "unsupported" in lowered:
        return "unsupported_runtime"
    if "no such file or directory" in lowered or "closed stdout" in lowered:
        return "unsupported_runtime"
    if "timeout" in lowered:
        return "timeout"
    return "harness_bug"


def observations_from_trace(trace: list[TraceEvent]) -> dict[str, Any]:
    text = trace_text(trace).lower()
    return {
        "network_markers": find_markers(text, ["http://", "https://", "curl ", "nc ", "/dev/tcp"]),
        "process_markers": find_markers(text, ["subprocess", "bash", "shell", "chmod ", "openssl "]),
        "filesystem_markers": find_markers(text, ["saved to", "write", "delete", "rm -rf", "authorized_keys"]),
        "canary_markers": find_markers(text, ["canary_secret_", "canary_openai_", "canary_github_", "canary_aws_"]),
    }


def find_markers(text: str, markers: list[str]) -> list[str]:
    return [marker for marker in markers if marker in text]


def trace_text(trace: list[TraceEvent]) -> str:
    return "\n".join(json.dumps(asdict(event), sort_keys=True) for event in trace)


def diagnostic_text(trace: list[TraceEvent]) -> str:
    useful_kinds = {"process.stderr", "process.stdout", "harness.error", "harness.tool_error", "mcp.message"}
    return "\n".join(
        json.dumps(asdict(event), sort_keys=True)
        for event in trace
        if event.kind in useful_kinds
    )


def write_connor_run_summary(out_dir: Path, results: list[ConnorRunResult]) -> None:
    with (out_dir / "summary.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "target_id", "group", "label", "stage", "profile", "execution_mode",
                "startup_status", "classification", "tools_listed",
                "tool_calls_attempted", "tool_calls_completed", "run_audit_verdicts",
                "run_audit_models", "run_audit_statuses", "duration_seconds",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow({
                "target_id": result.target_id,
                "group": result.group,
                "label": result.label,
                "stage": result.stage,
                "profile": result.sandbox_profile,
                "execution_mode": result.execution_mode,
                "startup_status": result.startup_status,
                "classification": result.classification,
                "tools_listed": result.tools_listed,
                "tool_calls_attempted": result.tool_calls_attempted,
                "tool_calls_completed": result.tool_calls_completed,
                "run_audit_verdicts": len(result.run_audit_verdicts),
                "run_audit_models": ";".join(
                    str(verdict.get("model", ""))
                    for verdict in result.run_audit_verdicts
                    if verdict.get("model")
                ),
                "run_audit_statuses": ";".join(
                    str(verdict.get("verdict", ""))
                    for verdict in result.run_audit_verdicts
                    if verdict.get("verdict")
                ),
                "duration_seconds": result.duration_seconds,
            })
    lines = [
        "# Connor Run Report",
        "",
        "| Target | Group | Stage | Profile | Startup | Classification | Tools | Calls | Run Verdicts |",
        "|---|---|---|---|---|---|---:|---:|---:|",
    ]
    for result in results:
        lines.append(
            f"| `{result.target_id}` | `{result.group}` | `{result.stage}` | "
            f"`{result.sandbox_profile}` | `{result.startup_status}` | "
            f"`{result.classification}` | {result.tools_listed} | "
            f"{result.tool_calls_completed}/{result.tool_calls_attempted} | "
            f"{len(result.run_audit_verdicts)} |"
        )
    (out_dir / "run_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_connor_events_csv(out_dir, results)


def write_connor_events_csv(out_dir: Path, results: list[ConnorRunResult]) -> None:
    with (out_dir / "events.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "target_id",
                "group",
                "label",
                "stage",
                "sandbox_profile",
                "execution_mode",
                "startup_status",
                "classification",
                "event_index",
                "kind",
                "message",
                "tool_name",
                "arguments",
                "result",
                "data",
            ],
        )
        writer.writeheader()
        for result in results:
            trace_path = out_dir / "targets" / result.target_id / "trace.jsonl"
            if not trace_path.exists():
                continue
            for index, event in enumerate(read_jsonl(trace_path), start=1):
                writer.writerow(connor_event_row(result, index, event))


def connor_event_row(result: ConnorRunResult, index: int, event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data", {}) if isinstance(event.get("data", {}), dict) else {}
    params = data.get("params", {}) if isinstance(data.get("params", {}), dict) else {}
    result_payload = data.get("result")
    tool_name = str(data.get("tool") or params.get("name") or "")
    arguments = data.get("arguments", params.get("arguments", {}))
    return {
        "target_id": result.target_id,
        "group": result.group,
        "label": result.label,
        "stage": result.stage,
        "sandbox_profile": result.sandbox_profile,
        "execution_mode": result.execution_mode,
        "startup_status": result.startup_status,
        "classification": result.classification,
        "event_index": index,
        "kind": event.get("kind", ""),
        "message": event.get("message", ""),
        "tool_name": tool_name,
        "arguments": json.dumps(arguments, sort_keys=True) if arguments else "",
        "result": json.dumps(result_payload, sort_keys=True) if result_payload is not None else "",
        "data": json.dumps(data, sort_keys=True),
    }


def summarize_connor_run(run_dir: str | Path) -> None:
    path = Path(run_dir)
    write_connor_run_summary(path, load_connor_results_from_run(path))


def load_connor_results_from_run(run_dir: str | Path) -> list[ConnorRunResult]:
    path = Path(run_dir)
    results: list[ConnorRunResult] = []
    for result_path in sorted((path / "targets").glob("*/connor_result.json")):
        data = read_json(result_path)
        results.append(ConnorRunResult(**data))
    return results


class EgressProxy:
    def __init__(self, log_path: Path, http_port: int = 8787, tcp_port: int = 8080) -> None:
        self.log_path = log_path
        self.http_port = http_port
        self.tcp_port = tcp_port
        self._httpd: socketserver.ThreadingTCPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._tcp_server: socketserver.ThreadingTCPServer | None = None
        self._tcp_thread: threading.Thread | None = None

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path = self.log_path

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self) -> None:  # noqa: N802
                append_jsonl(log_path, [{"kind": "http_connect", "target": self.path, "client": self.client_address[0]}])
                self.send_response(502)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                self._log_and_block()

            def do_POST(self) -> None:  # noqa: N802
                self._log_and_block()

            def do_PUT(self) -> None:  # noqa: N802
                self._log_and_block()

            def do_DELETE(self) -> None:  # noqa: N802
                self._log_and_block()

            def _log_and_block(self) -> None:
                append_jsonl(log_path, [{
                    "kind": "http_request",
                    "method": self.command,
                    "target": self.path,
                    "client": self.client_address[0],
                }])
                self.send_response(502)
                self.end_headers()
                self.wfile.write(b"egress blocked by mcp harness\n")

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        class TcpHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    data = self.request.recv(256)
                except OSError:
                    data = b""
                append_jsonl(log_path, [{
                    "kind": "tcp_connect",
                    "client": self.client_address[0],
                    "port": self.server.server_address[1],
                    "sample": data.decode("utf-8", errors="replace"),
                }])

        self._httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.http_port), Handler)
        self._httpd.daemon_threads = True
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()
        self._tcp_server = socketserver.ThreadingTCPServer(("127.0.0.1", self.tcp_port), TcpHandler)
        self._tcp_server.daemon_threads = True
        self._tcp_thread = threading.Thread(target=self._tcp_server.serve_forever, daemon=True)
        self._tcp_thread.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._tcp_server:
            self._tcp_server.shutdown()
            self._tcp_server.server_close()


def load_inventory(path: str | Path) -> list[ConnorInventoryItem]:
    items = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            items.append(ConnorInventoryItem(**json.loads(raw)))
    return items


def ensure_unique_inventory_ids(items: list[ConnorInventoryItem]) -> list[ConnorInventoryItem]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.id] = counts.get(item.id, 0) + 1
    unique: list[ConnorInventoryItem] = []
    for item in items:
        if counts[item.id] == 1:
            unique.append(item)
            continue
        digest = hashlib.sha1(item.target_dir.encode("utf-8")).hexdigest()[:8]
        unique.append(replace(item, id=f"{item.id}_{digest}"))
    return unique


def filter_inventory(
    items: list[ConnorInventoryItem],
    ids: list[str] | None = None,
    groups: list[str] | None = None,
) -> list[ConnorInventoryItem]:
    wanted_ids = set(ids or [])
    wanted_groups = set(groups or [])
    if wanted_ids:
        items = [item for item in items if item.id in wanted_ids]
    if wanted_groups:
        items = [item for item in items if item.group in wanted_groups]
    return items


def write_inventory_summary(path: Path, items: list[ConnorInventoryItem]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["group", "count", "label"])
        writer.writeheader()
        groups: dict[tuple[str, str], int] = {}
        for item in items:
            groups[(item.group, item.label)] = groups.get((item.group, item.label), 0) + 1
        for (group, label), count in sorted(groups.items()):
            writer.writerow({"group": group, "label": label, "count": count})


def write_build_summary(path: Path, results: list[ConnorBuildResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["target_id", "image", "build_status", "duration_seconds", "reason"])
        writer.writeheader()
        for result in results:
            writer.writerow({
                "target_id": result.target_id,
                "image": result.image,
                "build_status": result.build_status,
                "duration_seconds": result.duration_seconds,
                "reason": result.reason[:500],
            })


def image_name_for(target_id: str) -> str:
    return f"mcp-connor-{target_id}:local"


def docker_container_name_for(target_id: str) -> str:
    timestamp = int(time.time() * 1000)
    return f"mcp-harness-{target_id}-{os.getpid()}-{timestamp}"[:240]


def docker_image_exists(image: str) -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def nearest_parent_with(path: Path, filename: str) -> Path | None:
    current = path if path.is_dir() else path.parent
    for parent in [current, *current.parents]:
        if (parent / filename).exists():
            return parent
    return None


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def dockerfile_escape_path(value: str) -> str:
    return value.replace("\\", "\\\\").replace(" ", "\\ ")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return slug or "target"


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for raw in fh:
            if raw.strip():
                rows.append(json.loads(raw))
    return rows


def write_json(path: str | Path, payload: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def append_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
