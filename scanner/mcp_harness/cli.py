from __future__ import annotations

import argparse
from pathlib import Path

from .connor_manifest import build_connor_benign_docker_manifest
from .connor_pipeline import (
    build_connor_inventory,
    run_connor_builds,
    run_connor_targets,
    summarize_connor_run,
)
from .env import load_dotenv
from .report import write_result, write_run_report_from_disk, write_summary
from .runner import inspect_target, scan_target
from .targets import load_targets, select_target


FULL_PIPELINE_DEFAULTS = {
    "contract_mode": "llm",
    "audit_mode": "llm",
    "run_mode": "agent",
    "task_mode": "llm",
    "task_count": 5,
    "max_agent_steps": 3,
}

OFFLINE_DEFAULTS = {
    "contract_mode": "heuristic",
    "audit_mode": "heuristic",
    "run_mode": "direct",
    "task_mode": "single",
    "task_count": 1,
    "max_agent_steps": 4,
}


def main(argv: list[str] | None = None) -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(prog="mcp-harness")
    sub = parser.add_subparsers(dest="command", required=True)

    list_cmd = sub.add_parser("list-targets", help="List target IDs from a JSONL target file")
    list_cmd.add_argument("--targets", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Start one MCP target and print its tools")
    inspect_cmd.add_argument("--targets", required=True)
    inspect_cmd.add_argument("--id", required=True)
    inspect_cmd.add_argument("--cwd", default=".")

    summarize_cmd = sub.add_parser("summarize-run", help="Rebuild run_report.md and events.csv from saved target results")
    summarize_cmd.add_argument("--run", required=True)

    connor_cmd = sub.add_parser("make-connor-benign-manifest", help="Build a Docker target manifest from Connor benign mcp.json files")
    connor_cmd.add_argument("--servers-dir", required=True)
    connor_cmd.add_argument("--image", default="mcp-connor-benign:local")
    connor_cmd.add_argument("--out", required=True)
    connor_cmd.add_argument("--limit", type=int)

    connor_inventory_cmd = sub.add_parser("connor-inventory", help="Inventory all Connor benign, curated malicious, and PoC MCP targets")
    connor_inventory_cmd.add_argument("--connor-root", required=True)
    connor_inventory_cmd.add_argument("--benign-dir", required=True)
    connor_inventory_cmd.add_argument("--out", required=True)

    connor_build_cmd = sub.add_parser("connor-build", help="Generate per-target Docker contexts and build Connor target images")
    connor_build_cmd.add_argument("--inventory", required=True)
    connor_build_cmd.add_argument("--out", required=True)
    connor_build_cmd.add_argument("--jobs", type=int, default=1)
    connor_build_cmd.add_argument("--id", action="append", help="Build only this target id; repeat for multiple targets")
    connor_build_cmd.add_argument("--group", action="append", help="Build only this inventory group; repeat for multiple groups")
    connor_build_cmd.add_argument("--build-timeout-seconds", type=int, default=900)

    connor_run_cmd = sub.add_parser("connor-run", help="Run Connor targets through preflight, toolcall, or production stages")
    connor_run_cmd.add_argument("--inventory", required=True)
    connor_run_cmd.add_argument("--stage", required=True, choices=["preflight", "toolcall", "production"])
    connor_run_cmd.add_argument("--profile", required=True, choices=["preflight-strict", "toolcall-strict", "production-observed"])
    connor_run_cmd.add_argument("--out", required=True)
    connor_run_cmd.add_argument("--resume", action="store_true")
    connor_run_cmd.add_argument("--id", action="append", help="Run only this target id; repeat for multiple targets")
    connor_run_cmd.add_argument("--group", action="append", help="Run only this inventory group; repeat for multiple groups")
    connor_run_cmd.add_argument("--execution-mode", choices=["original-command", "normalized-command"], default="normalized-command")
    connor_run_cmd.add_argument("--task-count", type=int, default=5)
    connor_run_cmd.add_argument("--audit-model", action="append")
    connor_run_cmd.add_argument("--agent-model")

    connor_summarize_cmd = sub.add_parser("connor-summarize", help="Rebuild Connor run summary files from saved target results")
    connor_summarize_cmd.add_argument("--run", required=True)

    scan_cmd = sub.add_parser("scan", help="Run the standard LLM-agent MCP contract audit for one target")
    scan_cmd.add_argument("--targets", required=True)
    scan_cmd.add_argument("--id", required=True)
    scan_cmd.add_argument("--cwd", default=".")
    scan_cmd.add_argument("--out", required=True)
    scan_cmd.add_argument("--offline", action="store_true", help="Run the deterministic no-LLM smoke path")
    scan_cmd.add_argument("--user-task")
    scan_cmd.add_argument(
        "--audit-model",
        action="append",
        help="Audit model to run after the agent trace is collected; repeat for a model comparison",
    )
    scan_cmd.add_argument("--agent-model", help="Override the LLM used as the tool-calling agent")
    add_advanced_scan_options(scan_cmd)

    benchmark_cmd = sub.add_parser("benchmark", help="Run the standard LLM-agent MCP contract audit for every target")
    benchmark_cmd.add_argument("--targets", required=True)
    benchmark_cmd.add_argument("--cwd", default=".")
    benchmark_cmd.add_argument("--out", required=True)
    benchmark_cmd.add_argument("--id", action="append", help="Run only this target id; repeat for multiple targets")
    benchmark_cmd.add_argument("--label", choices=["benign", "malicious", "unknown"], help="Run only targets with this label")
    benchmark_cmd.add_argument("--resume", action="store_true", help="Skip targets that already have a verdict.json")
    benchmark_cmd.add_argument("--offline", action="store_true", help="Run the deterministic no-LLM smoke path")
    benchmark_cmd.add_argument("--user-task")
    benchmark_cmd.add_argument(
        "--audit-model",
        action="append",
        help="Audit model to run after each agent trace is collected; repeat for a model comparison",
    )
    benchmark_cmd.add_argument("--agent-model", help="Override the LLM used as the tool-calling agent")
    add_advanced_scan_options(benchmark_cmd)

    args = parser.parse_args(argv)

    if args.command == "list-targets":
        for target in load_targets(args.targets):
            print(f"{target.id}\t{target.label}\t{target.source}")
        return 0

    if args.command == "inspect":
        target = select_target(load_targets(args.targets), args.id)
        tools, _trace = inspect_target(target, args.cwd)
        for tool in tools:
            print(f"{tool.name}\t{tool.description}")
        return 0

    if args.command == "summarize-run":
        write_run_report_from_disk(args.run)
        print(f"summarized run: {args.run}")
        return 0

    if args.command == "make-connor-benign-manifest":
        count = build_connor_benign_docker_manifest(
            servers_dir=args.servers_dir,
            image=args.image,
            output_path=args.out,
            limit=args.limit,
        )
        print(f"wrote {count} targets to {args.out}")
        return 0

    if args.command == "connor-inventory":
        items = build_connor_inventory(args.connor_root, args.benign_dir, args.out)
        print(f"wrote {len(items)} Connor targets to {args.out}")
        return 0

    if args.command == "connor-build":
        results = run_connor_builds(
            args.inventory,
            args.out,
            jobs=args.jobs,
            ids=args.id,
            groups=args.group,
            build_timeout_seconds=args.build_timeout_seconds,
        )
        failed = [result for result in results if result.build_status != "built"]
        print(f"built {len(results) - len(failed)}/{len(results)} Connor targets")
        return 1 if failed else 0

    if args.command == "connor-run":
        run_connor_targets(
            inventory_path=args.inventory,
            stage=args.stage,
            profile=args.profile,
            out_dir=args.out,
            resume=args.resume,
            ids=args.id,
            execution_mode=args.execution_mode,
            task_count=args.task_count,
            audit_models=args.audit_model,
            agent_model=args.agent_model,
            groups=args.group,
        )
        return 0

    if args.command == "connor-summarize":
        summarize_connor_run(args.run)
        print(f"summarized Connor run: {args.run}")
        return 0

    if args.command == "scan":
        target = select_target(load_targets(args.targets), args.id)
        config = resolve_scan_config(args)
        result = scan_target(
            target,
            args.cwd,
            execute_tests=config["execute_tests"],
            contract_mode=config["contract_mode"],
            audit_mode=config["audit_mode"],
            llm_model=args.llm_model,
            contract_model=args.contract_model,
            task_model=args.task_model,
            audit_models=args.audit_model,
            run_mode=config["run_mode"],
            user_task=args.user_task,
            agent_model=args.agent_model,
            max_agent_steps=config["max_agent_steps"],
            task_mode=config["task_mode"],
            task_count=config["task_count"],
        )
        write_result(result, args.out)
        print(f"{result.target.id}: {result.status} ({len(result.findings)} findings)")
        return 0 if result.status in {"ok", "contract_violation"} else 1

    if args.command == "benchmark":
        out = Path(args.out)
        results = []
        config = resolve_scan_config(args)
        targets = filter_targets(load_targets(args.targets), ids=args.id, label=args.label)
        for target in targets:
            target_out = out / "targets" / target.id
            if args.resume and (target_out / "verdict.json").exists():
                print(f"{target.id}: skipped (existing verdict)")
                continue
            result = scan_target(
                target,
                args.cwd,
                execute_tests=config["execute_tests"],
                contract_mode=config["contract_mode"],
                audit_mode=config["audit_mode"],
                llm_model=args.llm_model,
                contract_model=args.contract_model,
                task_model=args.task_model,
                audit_models=args.audit_model,
                run_mode=config["run_mode"],
                user_task=args.user_task,
                agent_model=args.agent_model,
                max_agent_steps=config["max_agent_steps"],
                task_mode=config["task_mode"],
                task_count=config["task_count"],
            )
            write_result(result, target_out)
            results.append(result)
            print(f"{target.id}: {result.status} ({len(result.findings)} findings)")
        if results or not args.resume:
            write_summary(results, out)
        return 0

    return 1


def add_advanced_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-execute-tests", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--contract-mode", choices=["heuristic", "llm"], help=argparse.SUPPRESS)
    parser.add_argument("--audit-mode", choices=["heuristic", "llm", "hybrid"], help=argparse.SUPPRESS)
    parser.add_argument("--run-mode", choices=["direct", "agent"], help=argparse.SUPPRESS)
    parser.add_argument("--task-mode", choices=["single", "llm"], help=argparse.SUPPRESS)
    parser.add_argument("--task-count", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--llm-model", help=argparse.SUPPRESS)
    parser.add_argument("--contract-model", help=argparse.SUPPRESS)
    parser.add_argument("--task-model", help=argparse.SUPPRESS)
    parser.add_argument("--max-agent-steps", type=int, help=argparse.SUPPRESS)


def resolve_scan_config(args: argparse.Namespace) -> dict[str, object]:
    defaults = OFFLINE_DEFAULTS if args.offline else FULL_PIPELINE_DEFAULTS
    return {
        "execute_tests": not args.no_execute_tests,
        "contract_mode": args.contract_mode or defaults["contract_mode"],
        "audit_mode": args.audit_mode or defaults["audit_mode"],
        "run_mode": args.run_mode or defaults["run_mode"],
        "task_mode": args.task_mode or defaults["task_mode"],
        "task_count": args.task_count if args.task_count is not None else defaults["task_count"],
        "max_agent_steps": (
            args.max_agent_steps
            if args.max_agent_steps is not None
            else defaults["max_agent_steps"]
        ),
    }


def filter_targets(targets, ids: list[str] | None = None, label: str | None = None):
    selected = list(targets)
    if ids:
        wanted = set(ids)
        selected = [target for target in selected if target.id in wanted]
    if label:
        selected = [target for target in selected if target.label == label]
    return selected
