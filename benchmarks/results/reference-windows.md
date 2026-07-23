# Deterministic benchmark report

- Generated: `2026-07-23T08:34:16.011552Z`
- Runner: `1.0.0`
- Suite: `mcp-privprof-deterministic-v1`
- Source commit: `36df9a330bbfe19ef62ad2748f81f779445b5513`
- Working tree dirty at start: `false`

## Result

All labeled deterministic cases passed.

| Category | Cases |
|---|---:|
| Legitimate calls | 30 |
| Forbidden calls | 30 |
| Catalog drift | 10 |
| Overuse and approval abuse | 5 |

## Security behavior

- Catalog exposed 4 of 7 tools (42.86% reduction).
- Forbidden-call true-positive rate: 100.00%.
- Legitimate-call false-positive rate: 0.00%.
- Drift detection rate: 100.00%.
- Overuse/approval-abuse rejection rate: 100.00%.

These are measurements for the published deterministic lab labels, not a claim that the proxy prevents every prompt injection or guarantees least privilege.

## Performance

| Measurement | Samples | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|
| Policy decision and constraints | 10000 | 0.0033 | 0.3896 | 0.4663 |
| Direct MCP tool call | 30 | 4.9781 | 6.9891 | 7.3726 |
| Enforced MCP tool call | 30 | 23.0558 | 28.4416 | 28.9427 |
| Measured proxy delta | 30 | 17.4858 | 22.8781 | 22.9171 |
| Mandatory JSONL append plus fsync | 30 | 1.1357 | 1.7433 | 7.3898 |

Startup plus complete live inventory: `1294.1959 ms`.

The proxy delta pairs the same 30 harmless direct and enforced calls. Small negative samples can occur from operating-system scheduling noise.

## Wazuh evidence

The runner statically revalidated 22 contract-valid fixtures (11 positive and 11 near-miss cases). It did not start Docker or rerun the live Wazuh engine. The Stage 9 record separately documents the pinned Wazuh 4.14.6 logtest and live proxy-to-alert proof.

## Reproduce

From a frozen development environment:

```powershell
uv run python -m benchmarks.runner --json-output benchmarks/results/reference-windows.json --markdown-output benchmarks/results/reference-windows.md
```

## Limitations

- The deterministic lab uses harmless simulated tools, not production SaaS systems.
- The call labels measure policy behavior; they do not prove resistance to every prompt injection.
- Performance values describe this machine and run only, and include local filesystem effects.
- This run validates Wazuh fixtures statically; Stage 9 separately records real Wazuh 4.14.6 logtest and live-ingest evidence.
