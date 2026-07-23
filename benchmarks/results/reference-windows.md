# Deterministic benchmark report

Generated: `2026-07-23T08:31:57.976756Z`  
Runner: `1.0.0`  
Suite: `mcp-privprof-deterministic-v1`  
Source commit: `c7ebad9fa2d729fdc29d73f97e419f3f341b0a1a`  
Working tree dirty at start: `false`

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
| Policy decision and constraints | 10000 | 0.0034 | 0.3808 | 0.429 |
| Direct MCP tool call | 30 | 5.6185 | 7.9483 | 7.9495 |
| Enforced MCP tool call | 30 | 21.6491 | 34.881 | 37.7219 |
| Measured proxy delta | 30 | 16.1923 | 28.4832 | 31.3815 |
| Mandatory JSONL append plus fsync | 30 | 1.449 | 1.9112 | 2.2695 |

Startup plus complete live inventory: `1425.4781 ms`.

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
