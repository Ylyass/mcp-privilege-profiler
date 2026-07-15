# Implementation roadmap

The project follows the corrected master plan. Work proceeds in dependency
order so later security decisions are built on verified lower layers.

| Stage | Current status | Verified result or exit dependency |
|---|---|---|
| 0. Correctness and provisional name | Partial | Stable MCP v1 baseline chosen; final publication name clearance remains |
| 1. Repository and quality foundation | Local foundation verified | Locked environment and local gates work; hosted CI and release automation remain |
| 2. Threat model, contracts, and core domain | Foundation verified | Default-deny policy and privacy event contracts exist; later profile state belongs to Stage 6 |
| 3. Safe MCP lab | Verified | Deterministic tools and harmless compromised-agent scenarios |
| 4. Transparent stdio proxy | Verified | Real client to proxy to server flow, failures, pagination, cancellation, and shutdown |
| 5. Inventory, fingerprints, and drift | Current verified milestone | Persistence, reports, live refresh component, and conservative comparison work |
| 6. Profiling and human review | Next | Labeled evidence without claiming observation proves necessity |
| 7. Enforcement and catalog minimization | Not started | Exact reviewed policy, filtered catalog, constraints, and fail-closed drift |
| 8. Limits, audit, and permits | Not started | Privacy-minimized mandatory audit and bounded execution |
| 9. Wazuh bridge | Not started | Tested rules, fixtures, and live JSONL ingestion |
| 10. Benchmark and complete test matrix | Not started | Reproducible measured security and performance evidence |
| 11. Documentation, external review, release | Not started | Clean-clone reviews and open-source release artifacts |

Stage 5 classification cannot yet block a call because enforce mode does not
exist. That final connection is deliberately made in Stage 7, after profiling
and human review are implemented.

The next implementation stage is Stage 6: trusted launch-bound profile context,
labeled scenarios, attempted and successful call evidence, candidate
recommendations, and an explicit human review gate.
