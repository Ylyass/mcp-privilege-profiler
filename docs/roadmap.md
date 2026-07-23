# Implementation roadmap

The project follows the corrected master plan. Work proceeds in dependency
order so later security decisions are built on verified lower layers.

| Stage | Current status | Verified result or exit dependency |
|---|---|---|
| 0. Correctness and provisional name | Partial | Stable MCP v1 baseline chosen; final publication name clearance remains |
| 1. Repository and quality foundation | Local foundation verified; CI defined | Locked environment and local gates work; first hosted run remains |
| 2. Threat model, contracts, and core domain | Foundation verified | Default-deny policy and privacy event contracts exist; profile state was added in Stage 6 |
| 3. Safe MCP lab | Verified | Deterministic tools and harmless compromised-agent scenarios |
| 4. Transparent stdio proxy | Verified | Real client to proxy to server flow, failures, pagination, cancellation, and shutdown |
| 5. Inventory, fingerprints, and drift | Verified | Persistence, reports, live refresh component, and conservative comparison work |
| 6. Profiling and human review | Verified | Launch-bound scenarios, privacy-safe evidence, exact review gate, and policy artifacts work |
| 7. Enforcement and catalog minimization | Verified | Reviewed policy, filtered catalog, exact constraints, stable errors, and fail-closed drift work |
| 8. Limits, audit, and permits | Verified | Persistent rate/task limits, in-process concurrency, fsynced privacy audit, and exact single-use approvals work |
| 9. Wazuh bridge | Verified | Static validation, 22 real logtest cases, and live proxy-to-agent-to-manager-to-indexer delivery pass |
| 10. Benchmark and complete test matrix | Verified | 75 deterministic security cases, raw schema-valid results, p50/p95/p99 measurements, and 159 passing tests |
| 11. Documentation, external review, release | In progress | CI, issue forms, PR template, Dependabot, and release process are defined; name clearance, hosted runs, clean clones, external reviews, and publication remain |

Stage 8 enforce mode keeps the Stage 7 exact catalog and constraint gates, then
reserves reviewed per-tool limits, consumes an exact single-use approval when
required, and appends plus fsyncs a privacy-minimized decision before
forwarding. Persistent rate/task counters survive restart, concurrency is
bounded inside the v0.1 proxy process, audit failure prevents downstream
execution, and raw argument/result values remain absent from JSONL and SQLite.

Stage 9 now has a pinned Wazuh 4.14.6 local-only deployment overlay, a
read-only JSONL agent input, 11 custom alert rules, 22 positive/near-miss
fixtures, automated static contract validation, and a collision-safe prefixed
JSON decoder. All 22 fixture cases now pass the real Wazuh 4.14.6 analysis
engine. The bounded live probe also proved that a real proxy denial was
collected by the active `mcp-privprof-lab` Wazuh agent, became rule `100103` at
level 10, and was searchable in the green single-node indexer under the same trace ID. This
closes Stage 9.

Stage 10 now has a versioned deterministic suite with 30 legitimate calls, 30
forbidden calls, 10 catalog-drift changes, and 5 overuse/approval-abuse cases.
The runner uses the real local MCP server and installed enforcement proxy,
production drift/limit/permit services, and all 22 Wazuh fixtures. The committed
clean-tree Windows reference passed all 75 cases, reduced the exposed catalog
from 7 to 4 tools (42.86%), blocked all labeled forbidden calls with no labeled
legitimate-call false positives, and detected every labeled drift and overuse
case. It publishes schema-valid raw results and p50/p95/p99 timings with explicit
machine and claim limitations.

Stage 11 has started with a read-only GitHub Actions workflow, full-SHA action
pins, a Linux/Windows and Python 3.13/3.14 test matrix, build smoke tests,
Dependabot configuration, structured issue forms, a security-aware pull-request
template, and an explicit release process. These files are locally validated
configuration until a GitHub remote exists and the hosted checks actually pass.
