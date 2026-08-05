# Deterministic benchmark report

- Generated: `2026-08-05T07:21:33.273327Z`
- Runner: `1.0.0`
- Suite: `mcp-privprof-deterministic-v1`
- Source commit: `51cfe43dc21632a4fc790dd4d7c9b8a2a170600b`
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
| Policy decision and constraints | 10000 | 0.0037 | 0.4499 | 0.5196 |
| Direct MCP tool call | 30 | 3.1182 | 4.9001 | 9.7694 |
| Enforced MCP tool call | 30 | 26.4407 | 33.5494 | 38.0857 |
| Measured proxy delta | 30 | 22.9489 | 29.5335 | 29.9775 |
| Mandatory JSONL append plus fsync | 30 | 1.25 | 1.5489 | 1.8467 |

Startup plus complete live inventory: `1803.712 ms`.

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
