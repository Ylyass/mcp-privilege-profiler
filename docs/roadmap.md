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
| 7. Enforcement and catalog minimization | Current verified milestone | Reviewed policy, filtered catalog, exact constraints, stable errors, and fail-closed drift work |
| 8. Limits, audit, and permits | Next | Privacy-minimized mandatory audit, call limits, and single-use approvals |
| 9. Wazuh bridge | Not started | Tested rules, fixtures, and live JSONL ingestion |
| 10. Benchmark and complete test matrix | Not started | Reproducible measured security and performance evidence |
| 11. Documentation, external review, release | Not started | Clean-clone reviews and open-source release artifacts |

Stage 7 enforce mode verifies the exact complete catalog before startup, hides
DENY entries, blocks unknown and denied calls before forwarding, evaluates
reviewed path/URL/enum/byte constraints, and invalidates immediately on a live
catalog-change notification.

The next implementation stage is Stage 8: add privacy-minimized mandatory
audit-before-forward, per-tool rate limits, task and concurrency budgets, and a
separate single-use permit workflow for `REQUIRE_APPROVAL`.
