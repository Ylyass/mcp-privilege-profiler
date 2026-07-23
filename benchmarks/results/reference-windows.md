# Deterministic benchmark report

Generated: `2026-07-23T08:27:23.884482Z`  
Runner: `1.0.0`  
Suite: `mcp-privprof-deterministic-v1`  
Source commit: `0f4176895f34e57935f24452cf288e66284b325d`  
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
| Policy decision and constraints | 10000 | 0.0023 | 0.2663 | 0.3544 |
| Direct MCP tool call | 30 | 5.2407 | 6.7723 | 7.3698 |
| Enforced MCP tool call | 30 | 20.4278 | 23.0652 | 24.4418 |
| Measured proxy delta | 30 | 14.4353 | 17.6069 | 17.9787 |
| Mandatory JSONL append plus fsync | 30 | 0.9347 | 1.0781 | 1.26 |

Startup plus complete live inventory: `1421.0733 ms`.

The proxy delta pairs the same 30 harmless direct and enforced calls. Small negative samples can occur from operating-system scheduling noise.

## Wazuh evidence

The runner statically revalidated 22 contract-valid fixtures (11 positive and 11 near-miss cases). It did not start Docker or rerun the live Wazuh engine. The Stage 9 record separately documents the pinned Wazuh 4.14.6 logtest and live proxy-to-alert proof.

## Reproduce

From a frozen development environment:

```powershell
uv run python -m benchmarks.runner --json-output benchmarks/results/reference.json --markdown-output benchmarks/results/reference.md
```

## Limitations

- The deterministic lab uses harmless simulated tools, not production SaaS systems.
- The call labels measure policy behavior; they do not prove resistance to every prompt injection.
- Performance values describe this machine and run only, and include local filesystem effects.
- This run validates Wazuh fixtures statically; Stage 9 separately records real Wazuh 4.14.6 logtest and live-ingest evidence.
