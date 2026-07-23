# Deterministic benchmark

The Stage 10 benchmark measures the implemented v0.1 security boundary against
fixed, harmless local scenarios. It is evidence about this suite, not evidence
that every AI agent, MCP server, prompt injection, or production environment is
safe.

## What runs

The runner uses the same code paths as the product:

1. it launches the real local MCP lab server over stdio;
2. it inventories the complete live tool catalog and creates its normal RFC
   8785/SHA-256 fingerprint;
3. it launches the installed `mcp-privprof enforce` proxy with an exact policy;
4. it sends 30 labeled legitimate and 30 labeled forbidden calls through the
   real MCP client-to-proxy-to-server path;
5. it applies 10 deterministic catalog mutations to the production
   fingerprint and drift comparator;
6. it runs five limit or approval-abuse cases against the production SQLite,
   limit, and permit services;
7. it statically revalidates all 22 Wazuh positive and near-miss fixtures; and
8. it measures policy evaluation, direct calls, enforced calls, mandatory
   JSONL append-plus-fsync, and startup inventory.

No benchmark scenario opens an external network connection, reads a real
credential, launches a shell command, or writes outside a disposable test
area.

## Fixed scenario minimums

The tracked `benchmarks/scenarios-v1.json` manifest contains:

| Category | Minimum | Meaning |
|---|---:|---|
| Legitimate | 30 | Reviewed calls that should reach the lab server |
| Forbidden | 30 | DENY calls that must stop before the lab server |
| Drift | 10 | Added, removed, or modified tool definitions |
| Overuse/approval abuse | 5 | Task, rate, concurrency, replay, and changed-argument cases |

The runner refuses undersized manifests, duplicate case IDs, unsupported
labels, or output that violates `benchmark-result-v1.schema.json`.

## Metrics

Catalog reduction is:

```text
(available tools - exposed tools) / available tools
```

A forbidden call blocked by policy is a true positive. A legitimate call
blocked by policy is a false positive. Precision, recall, true-positive rate,
and false-positive rate use only the declared deterministic labels.

Timing uses `time.perf_counter_ns` and nearest-rank p50, p95, and p99 values.
The proxy delta pairs each legitimate enforced-call sample with the matching
direct-call sample:

```text
enforced duration - direct duration
```

Operating-system scheduling can make individual delta samples negative. Do not
generalize one machine's timings to another filesystem, endpoint protection
configuration, or downstream server.

## Run it

Keep the Wazuh Docker lab stopped; the Stage 10 runner does not require Docker:

```powershell
uv run python -m benchmarks.runner `
  --json-output benchmarks/results/reference-windows.json `
  --markdown-output benchmarks/results/reference-windows.md
```

The JSON file contains the exact cases, environment, metrics, runner version,
suite fingerprint, source commit, and dirty-worktree flag. The Markdown file is
rendered from that JSON result.

For release evidence, run from a clean committed tree so
`source_revision.dirty` is `false`, then review and commit both outputs without
manually changing the measured values.

## Interpretation limits

- Passing forbidden fixtures does not mean the proxy identifies every malicious
  intent; the policy blocks the exact actions already classified by a reviewer.
- Passing legitimate fixtures does not prove every real MCP server is
  compatible.
- Drift detection proves exact definition changes are noticed; it does not
  interpret arbitrary server source-code changes.
- Static Wazuh fixture validation is not a replacement for the pinned
  `wazuh-logtest` and live-ingest checks documented in the
  [Wazuh bridge guide](wazuh-bridge.md).
- Benchmark data must never be described as a guarantee of prompt-injection
  prevention or universal least privilege.
