# MCP Contract Harness

Hauptprojekt prototype for a Connor-like contract checking pipeline:

1. start an MCP server from a target config
2. call `initialize` and `tools/list`
3. derive an initial capability contract from tool metadata
4. ask an LLM to generate benign user tasks from the tool metadata
5. run an agent LLM that can choose MCP tools for those tasks
6. collect the MCP and agent trace
7. audit the trace against the contract
8. write contract, trace, verdict, generated tasks, and summary files

This first slice intentionally runs only harmless local targets. Unknown MCP
servers should be executed only after the Docker sandbox runner is implemented.

## Quick Start

The standard scan path uses the OpenAI API for contract derivation, generated
tasks, agent execution, and audit judgement. Provide the key through the
environment or a local `.env` file in the repo root. Do not commit `.env`.

```bash
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-5.4-mini
OPENAI_AGENT_MODEL=gpt-5.4-mini
OPENAI_AUDIT_MODEL=gpt-5.4-mini
OPENAI_AUDIT_MODELS=gpt-5.4-nano,gpt-5.4-mini
```

The CLI loads the nearest `.env` from the current directory or any parent
directory without overriding already exported environment variables.

```bash
PYTHONPATH=scanner python3 -m mcp_harness scan \
  --targets benchmarks/targets/connor_benign_smoke.jsonl \
  --id connor_benign_time \
  --out results/connor-time-generated-tasks-llm-scan
```

To compare auditors while keeping the generated traffic stable, keep
`OPENAI_AGENT_MODEL` fixed and repeat `--audit-model`. The MCP server and agent
run once; the saved audit packets are judged once per listed model.

```bash
PYTHONPATH=scanner python3 -m mcp_harness scan \
  --targets benchmarks/targets/connor_benign_smoke.jsonl \
  --id connor_benign_time \
  --out results/connor-time-audit-matrix \
  --audit-model gpt-5.4-nano \
  --audit-model gpt-5.4-mini
```

Use `--agent-model` only for a separate experiment, because changing the agent
also changes which MCP calls are produced. The audit comparison is written to
`audit_matrix.csv` and `audit_matrix.json`.

For a no-LLM local smoke test, use `--offline`:

```bash
PYTHONPATH=scanner python3 -m mcp_harness scan \
  --targets benchmarks/targets/local_smoke.jsonl \
  --id local_echo \
  --out results/local-echo-offline-smoke \
  --offline
```

Run the smoke tests:

```bash
PYTHONPATH=scanner python3 -m unittest discover scanner/tests
```

## Current Boundary

Implemented:

- JSONL target loading
- stdio MCP framing
- `initialize`, `tools/list`, and `tools/call`
- deterministic metadata-to-contract baseline
- schema-based test generation
- audit packet generation per tool call
- real agent mode where prompts cause a model to select MCP tools
- LLM-generated benign task prompts from MCP tool metadata
- structured result output
- OpenAI-backed LLM contract derivation and audit
- deterministic offline smoke mode

Next:

- Docker sandbox runner
- install/start isolation for Connor samples
- syscall/network/process observation
