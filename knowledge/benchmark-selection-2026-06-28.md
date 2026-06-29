# Benchmark Selection Note - 2026-06-28

## Recommendation

Use Connor as the primary near-term benchmark family.

- First production-like benign run: 10 Connor benign MCPs, 5 LLM-generated user tasks per MCP.
- First malicious cloud run: Connor `Dataset/Malicious` curated samples, not the full PoC grid.
- Later malicious expansion: Connor PoCs by attack-goal group.
- Later utility / false-positive benchmark: MCP-Bench.
- Later live-agent / proxy benchmark: MSB, MCPTox, MCP-SafetyBench, MCP-Universe.

## Why Connor First

Connor is the best immediate match for our harness because its released repo contains runnable MCP server directories with `mcp.json`, `pyproject.toml`, and mostly Python/uv startup commands.

Observed locally:

- `Dataset/Benign/benign_servers.zip` extracts to `bengin_servers/`.
- `bengin_servers/` contains 129 top-level benign MCP directories with `mcp.json`.
- `Dataset/Malicious/` contains 20 curated malicious directories.
- `PoCs/` contains 6 attack-goal families with 19 variants each: backdoor, payload execution, ransomware, reverse shell, sabotaging, stealing.

The Connor paper reports a 114-server malicious PoC dataset and a two-stage behavioral-deviation detector with 94.6% F1. That makes Connor the most directly comparable baseline for our offline scanner.

## Production-Like Benign 10

Use these as the next 10-MCP benign run:

1. `time`
2. `math_calculator_server`
3. `json_handler_server`
4. `text_processor_server`
5. `file_utils_server`
6. `system_info_server`
7. `code_analyzer_server`
8. `data_processor_server`
9. `git_helper_server`
10. `network_utils_server`

Status:

- The first 6 are already Docker/offline validated.
- The last 4 have clean-looking Python/uv layouts and `uv.lock`, but still need Docker image pre-sync and offline validation.
- `network_utils_server` is useful as a boundary case, but with `--network none` its network calls may fail. Treat that as expected sandbox behavior, not necessarily a harness failure.

Avoid for this first 10x5 production test:

- `wikipedia`, `open_meteo_weather`, `world_bank`: useful later, but network-dependent.
- `weights-and-measures`, `todo`, `sequential-thinking`: still useful, but their Connor `mcp.json` paths differ from the extracted local directory shape and need manual validation.

## First Malicious Cloud Set

Start with Connor `Dataset/Malicious`, not PoCs:

1. `Poisonattack1`
2. `Poisonattack2`
3. `Poisonattack3`
4. `tool_poisoning`
5. `namespace`
6. `weather_attack1`
7. `weather_attack2`
8. `weather_attack3`
9. `challenge1`
10. `challenge2`

Reason: these are smaller, curated, and easier to sandbox than reverse-shell/ransomware/backdoor PoCs. Run them only on a disposable remote machine with no secrets, no host mounts, no Docker socket, no network by default, resource limits, and full logs.

## Other Benchmark Groups

- MCP-Bench: strong benign/utility benchmark with real MCP servers and tasks. Use later to test false positives and utility preservation.
- MSB: end-to-end MCP security benchmark for agent robustness and live proxy evaluation.
- MCPTox / MCP-ITP: tool-metadata poisoning; useful for metadata and cross-tool attacks, less aligned with sandbox behavior alone.
- MCPSecBench: broad taxonomy/playground for MCP attack surfaces.
- MCP-SafetyBench / MCP-Universe: realistic multi-turn, cross-server, and utility evaluation; better fit for Masterarbeit/live proxy than the first Hauptprojekt run.
