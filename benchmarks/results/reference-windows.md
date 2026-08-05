# Deterministic benchmark report

- Generated: `2026-08-05T11:48:51.494937Z`
- Runner: `1.0.0`
- Suite: `mcp-privprof-deterministic-v1`
- Source commit: `3f7ba2ae2132bd34c645529a971648e2dfa2f2e6`
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
| Policy decision and constraints | 10000 | 0.0023 | 0.2794 | 0.3498 |
| Direct MCP tool call | 30 | 3.8008 | 4.8037 | 9.7789 |
| Enforced MCP tool call | 30 | 20.8414 | 24.3417 | 27.7502 |
| Measured proxy delta | 30 | 17.5613 | 20.3704 | 20.6581 |
| Mandatory JSONL append plus fsync | 30 | 1.0448 | 1.5915 | 3.0472 |

Startup plus complete live inventory: `2158.6716 ms`.

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
