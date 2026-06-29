# Target Manifests

Targets are managed as JSONL queues. Each non-comment line describes one MCP
server target. `mcp_harness benchmark` processes the selected targets one after
another and writes one result directory per target:

```text
results/<run-id>/
  summary.csv
  run_report.md
  events.csv
  targets/
    <target-id>/
      target.json
      tools.json
      contract.json
      generated_tasks.json
      agent_traces.json
      audit_packets.json
      audit_matrix.csv
      verdict.json
      report.md
```

`run_report.md` is the verbose reading view for a whole benchmark run. It lists
each generated user task, every MCP tool call, the MCP response, and each audit
model's judgement. `events.csv` is the same idea as a flat table for filtering
or later plotting.

Current local targets run as host subprocesses. Future Docker targets should use
the same queue model, but each target should start in a fresh isolated container:

```text
for target in manifest:
  prepare target workspace/image
  start one fresh container for this target
  attach MCP stdio
  initialize, tools/list, agent tool calls
  collect sandbox observations
  audit saved packets with one or more judge models
  write result bundle
  stop/remove container
```

Use one container per target rather than one long-lived shared container. This
keeps filesystem, process, network, and canary observations isolated between
targets.

Docker smoke test:

```bash
docker build \
  -f docker/benign-suite/Dockerfile \
  -t mcp-benign-suite:local \
  .

PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/docker_benign_suite.jsonl \
  --out results/docker-benign-suite-offline \
  --offline
```

The Docker targets use `docker run --rm -i --network none --read-only` with a
small `/tmp` tmpfs, dropped capabilities, and `no-new-privileges`. The harness
still communicates with the MCP server over stdio, exactly like local mode.

Useful queue commands:

```bash
PYTHONPATH=scanner python3 -m mcp_harness list-targets \
  --targets benchmarks/targets/local_benign_suite.jsonl

PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/local_benign_suite.jsonl \
  --out results/local-benign-suite-offline \
  --offline

PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/local_benign_suite.jsonl \
  --out results/local-benign-suite-offline \
  --offline \
  --resume

PYTHONPATH=scanner python3 -m mcp_harness benchmark \
  --targets benchmarks/targets/local_benign_suite.jsonl \
  --id local_calculator \
  --id local_catalog \
  --out results/selected-benign \
  --offline

PYTHONPATH=scanner python3 -m mcp_harness summarize-run \
  --run results/selected-benign
```

Core fields used today:

- `id`: stable unique target id.
- `source`: dataset/source group, for example `local` or `connor`.
- `label`: `benign`, `malicious`, or `unknown`.
- `transport`: currently `stdio`.
- `stdio_framing`: `headers` for Content-Length framing, `jsonl`, or `headers-jsonl` for servers that read Content-Length requests but emit JSON-line responses.
- `command` and `args`: process command for local mode.
- `path` and `cwd`: resolved relative to the manifest file.
- `env`: target-specific environment variables.
- `timeout_seconds`: MCP request timeout.
- `notes`: human-readable setup notes.

Likely Docker fields later:

- `runner`: `local` or `docker`.
- `image`: prebuilt image name, if available.
- `dockerfile`: build recipe, if the harness should build locally.
- `network`: normally `none` for malicious/unknown targets.
- `readonly_rootfs`: normally `true`.
- `mounts`: explicit temporary mounts only.
- `canaries`: files/env vars inserted for observation.
