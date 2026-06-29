# VPS Docker Runbook

This is the intended setup for running many MCP targets on a disposable remote
machine.

## Server Setup

Use a fresh VPS. Install:

- Git
- Python 3.11 or newer
- Docker Engine
- `uv`, when running Python MCP projects that use it

For Docker Engine installation, follow the official Docker instructions for the
server OS. For Ubuntu, see:

```text
https://docs.docker.com/engine/install/ubuntu/
```

Clone the project and add a `.env` in the repo root:

```bash
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-5.4-mini
OPENAI_AGENT_MODEL=gpt-5.4-mini
OPENAI_AUDIT_MODEL=gpt-5.4-mini
OPENAI_AUDIT_MODELS=gpt-5.4-nano,gpt-5.4-mini
```

Keep `gpt-5.4` and `gpt-5.5` out of routine runs until we explicitly decide to
use them for a small follow-up sample.

## Harmless Docker Smoke

Build the local benign MCP image:

```bash
docker build \
  -f docker/benign-suite/Dockerfile \
  -t mcp-benign-suite:local \
  .
```

Run the Docker-backed harmless queue:

```bash
PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/docker_benign_suite.jsonl \
  --out results/docker-benign-suite-offline \
  --offline
```

Run the LLM path with cheap auditors only:

```bash
PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/docker_benign_suite.jsonl \
  --out results/docker-benign-suite-llm \
  --task-count 3 \
  --audit-model gpt-5.4-nano \
  --audit-model gpt-5.4-mini
```

Regenerate consolidated reports without spending API tokens:

```bash
PYTHONPATH=scanner python3 -m mcp_harness summarize-run \
  --run results/docker-benign-suite-llm
```

Read:

- `results/<run>/summary.csv`
- `results/<run>/run_report.md`
- `results/<run>/events.csv`

## Connor-All Target Pipeline

Use this pipeline for the reproducible Connor run. It is staged so a failed
target gets a useful status and does not block the whole benchmark.

Create the inventory:

```bash
PYTHONPATH=scanner python3 -m mcp_harness connor-inventory \
  --connor-root /private/tmp/Connor \
  --benign-dir external_datasets/connor-benign/bengin_servers \
  --out generated/connor/inventory.jsonl
```

Expected local inventory size:

- 129 benign Connor servers
- 20 curated malicious Connor servers
- 114 PoC servers

Build images per target. Start with benign IDs locally; run malicious and PoC
builds on a disposable VPS:

```bash
PYTHONPATH=scanner python3 -m mcp_harness connor-build \
  --inventory generated/connor/inventory.jsonl \
  --out generated/connor/build \
  --jobs 4
```

Run strict preflight first. This starts the container, initializes MCP, and
lists tools without network:

```bash
PYTHONPATH=scanner python3 -m mcp_harness connor-run \
  --inventory generated/connor/inventory.jsonl \
  --stage preflight \
  --profile preflight-strict \
  --out results/connor-preflight \
  --execution-mode normalized-command \
  --resume
```

Run strict tool calls next. This attempts sampled deterministic `tools/call`
requests:

```bash
PYTHONPATH=scanner python3 -m mcp_harness connor-run \
  --inventory generated/connor/inventory.jsonl \
  --stage toolcall \
  --profile toolcall-strict \
  --out results/connor-toolcall \
  --execution-mode normalized-command \
  --resume
```

Run production only after build, preflight, and toolcall are stable. Keep routine
audits on cheap models:

```bash
PYTHONPATH=scanner python3 -m mcp_harness connor-run \
  --inventory generated/connor/inventory.jsonl \
  --stage production \
  --profile production-observed \
  --out results/connor-production \
  --execution-mode normalized-command \
  --task-count 5 \
  --audit-model gpt-5.4-nano \
  --audit-model gpt-5.4-mini \
  --resume
```

Every Connor run writes:

- `summary.csv`
- `run_report.md`
- `events.csv`
- `targets/<target_id>/trace.jsonl`
- `targets/<target_id>/connor_result.json`

Use `original-command` only when you explicitly want to preserve Connor's exact
startup command, including prestart payloads. Use `normalized-command` for the
MCP interaction pass when the original command prevents a clean server startup.

## Legacy Connor Benign Benchmark

This section is the old benign-only path. For the Hauptprojekt, prefer the
Connor-all pipeline above because it inventories benign, curated malicious, and
PoC targets with separate per-target images.

The first real benchmark target is Connor benign, because the archive contains
129 real benign MCP server directories with `mcp.json` startup configs.

Prepare the dataset:

```bash
unzip -q -n /path/to/benign_servers.zip -d external_datasets/connor-benign
```

Build the generic Connor benign image:

```bash
docker build \
  -f docker/connor-benign/Dockerfile \
  -t mcp-connor-benign:local \
  .
```

Generate manifests from the extracted `mcp.json` files:

```bash
PYTHONPATH=scanner python3 -m mcp_harness make-connor-benign-manifest \
  --servers-dir external_datasets/connor-benign/bengin_servers \
  --image mcp-connor-benign:local \
  --out benchmarks/targets/connor_benign_docker_full.jsonl
```

Use the curated starter queue before running all 129:

```bash
PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/connor_benign_docker_starter.jsonl \
  --out results/connor-benign-starter-offline \
  --offline \
  --resume
```

Then run the cheap LLM path:

```bash
PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/connor_benign_docker_starter.jsonl \
  --out results/connor-benign-starter-llm \
  --task-count 3 \
  --audit-model gpt-5.4-nano \
  --audit-model gpt-5.4-mini \
  --resume
```

Only after that should we try the full generated queue:

```bash
PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/connor_benign_docker_full.jsonl \
  --out results/connor-benign-full-offline \
  --offline \
  --resume
```

## Real MCP Target Requirements

Each real MCP target needs a manifest entry that can start the MCP over stdio.
For Docker-backed targets, the manifest currently uses `command: docker` and
`args: ["run", ...]`.

Minimum requirements:

- The MCP starts without manual interaction.
- The MCP speaks stdio MCP using either Content-Length headers or JSONL framing.
- Dependencies are installed before runtime, preferably at image build time.
- Runtime should not need network unless the target is explicitly about network
  access.
- The target has a stable `id`, `source`, `label`, and `notes`.
- The target gets one fresh container per scan.

Recommended Docker flags for unknown or malicious targets:

```bash
docker run --rm -i \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  <image> <command>
```

Use network only for deliberately network-dependent benign controls. For
malicious/unknown targets, keep network disabled first.

## What We Have Today

Ready:

- Target manifests as queues.
- Sequential benchmark execution.
- Resume and target filters.
- One result folder per target.
- Consolidated `run_report.md` and `events.csv`.
- Docker-backed stdio execution through the manifest.
- Connor inventory for benign, curated malicious, and PoC targets.
- Per-target Connor Docker build contexts and images.
- Strict preflight and deterministic toolcall stages.
- Fake secret canaries and profile-specific Docker runtime flags.
- Cheap audit matrix with `gpt-5.4-nano` and `gpt-5.4-mini`.

Not yet complete for serious malicious evaluation:

- System-level sandbox observations are still shallow.
- Docker prevents/isolates many actions, but the harness does not yet record all
  filesystem, process, and network attempts.
- Logged egress is proxy-based and does not yet capture arbitrary raw packet
  attempts outside configured proxy/sink paths.
- The generic builder is Connor-oriented; arbitrary non-Connor MCP repositories
  may still need adapter work.

So the next realistic step is to run the full benign Connor set in stages. After
that, run curated malicious and PoC production stages only on a disposable VPS
and then iterate on richer Docker observations.
