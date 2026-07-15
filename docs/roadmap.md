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
| 6. Profiling and human review | Current verified milestone | Launch-bound scenarios, privacy-safe evidence, exact review gate, and policy artifacts work |
| 7. Enforcement and catalog minimization | Next | Enforce reviewed policy, filter catalog, validate constraints, and fail closed on drift |
| 8. Limits, audit, and permits | Not started | Privacy-minimized mandatory audit and bounded execution |
| 9. Wazuh bridge | Not started | Tested rules, fixtures, and live JSONL ingestion |
| 10. Benchmark and complete test matrix | Not started | Reproducible measured security and performance evidence |
| 11. Documentation, external review, release | Not started | Clean-clone reviews and open-source release artifacts |

Stage 6 profile mode fails closed if the exact catalog changes while evidence is
being collected. It does not enforce the generated policy; that final
authorization connection is deliberately made in Stage 7.

The next implementation stage is Stage 7: load the completed-review policy,
expose only permitted tools, reject denied and unknown calls before forwarding,
apply constraint semantics, and block enforcement on unreviewed catalog drift.
