# Implementation roadmap

The project follows the corrected master plan. Work proceeds in dependency
order so later security decisions are built on verified lower layers.

| Stage | Current status | Verified result or exit dependency |
|---|---|---|
| 0. Correctness and provisional name | Partial | Stable MCP v1 baseline chosen; final publication name clearance remains |
| 1. Repository and quality foundation | Local foundation verified | Locked environment and local gates work; hosted CI and release automation remain |
| 2. Threat model, contracts, and core domain | Foundation verified | Default-deny policy and privacy event contracts exist; profile state was added in Stage 6 |
| 3. Safe MCP lab | Verified | Deterministic tools and harmless compromised-agent scenarios |
| 4. Transparent stdio proxy | Verified | Real client to proxy to server flow, failures, pagination, cancellation, and shutdown |
| 5. Inventory, fingerprints, and drift | Verified | Persistence, reports, live refresh component, and conservative comparison work |
| 6. Profiling and human review | Verified | Launch-bound scenarios, privacy-safe evidence, exact review gate, and policy artifacts work |
| 7. Enforcement and catalog minimization | Verified | Reviewed policy, filtered catalog, exact constraints, stable errors, and fail-closed drift work |
| 8. Limits, audit, and permits | Verified | Persistent rate/task limits, in-process concurrency, fsynced privacy audit, and exact single-use approvals work |
| 9. Wazuh bridge | In progress | Static pack and local lab are verified; real Wazuh analysis and live JSONL ingestion require Docker Desktop and WSL 2 |
| 10. Benchmark and complete test matrix | Not started | Reproducible measured security and performance evidence |
| 11. Documentation, external review, release | Not started | Clean-clone reviews and open-source release artifacts |

Stage 8 enforce mode keeps the Stage 7 exact catalog and constraint gates, then
reserves reviewed per-tool limits, consumes an exact single-use approval when
required, and appends plus fsyncs a privacy-minimized decision before
forwarding. Persistent rate/task counters survive restart, concurrency is
bounded inside the v0.1 proxy process, audit failure prevents downstream
execution, and raw argument/result values remain absent from JSONL and SQLite.

Stage 9 now has a pinned Wazuh 4.14.6 local-only deployment overlay, a
read-only JSONL agent input, 11 custom alert rules, 22 positive/near-miss
fixtures, and automated static contract validation. The helper also automates
real `wazuh-logtest` execution and the full local lab, but those two runtime
checks have not run on this computer because Docker Desktop and WSL 2 are not
installed. Stage 9 closes only after the real analysis engine and live
agent-to-manager path both pass.
