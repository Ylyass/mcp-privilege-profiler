# Implementation roadmap

The project follows the corrected master plan. Work proceeds in dependency
order so later security decisions are built on verified lower layers.

| Stage | Current status | Verified result or exit dependency |
|---|---|---|
| 0. Correctness and repository name | Partial | Stable MCP SDK v2 baseline and `mcp-privilege-profiler` repository identifier selected; final package trademark/confusion rechecks remain |
| 1. Repository and quality foundation | Verified locally and in hosted CI | Locked environment, full-SHA workflow pins, and Linux/Windows Python 3.13/3.14 gates pass on commit `beaa6e9` |
| 2. Threat model, contracts, and core domain | Foundation verified | Default-deny policy and privacy event contracts exist; profile state was added in Stage 6 |
| 3. Safe MCP lab | Verified | Deterministic tools and harmless compromised-agent scenarios |
| 4. Transparent stdio proxy | SDK v2 verified | Current-protocol and legacy client flows, failures, pagination, cancellation, and shutdown |
| 5. Inventory, fingerprints, and drift | Verified | Persistence, reports, live refresh component, and conservative comparison work |
| 6. Profiling and human review | Post-SDK2 real-agent acceptance verified | Two explicitly completed runs, sealed evidence, privacy scan, and seven human decisions passed |
| 7. Enforcement and catalog minimization | Post-SDK2 direct and real-agent paths verified | Generated policy exposed three tools; direct negative probes and the three-call Claude task passed |
| 8. Limits, audit, and permits | Verified | Persistent rate/task limits, in-process concurrency, fsynced privacy audit, and exact single-use approvals work |
| 9. Wazuh bridge | Static SDK v2 tests pass; live rerun pending | Decoder/rule contracts pass; earlier 22-engine-case and live delivery proof is historical |
| 10. Benchmark and complete test matrix | Current SDK v2 suite and clean benchmark pass | 75/75 cases pass from commit `3f7ba2a` after lifecycle corrections |
| 11. Documentation, external review, release | Public pre-alpha source published | Hosted CI and current benchmark pass; Wazuh refresh, independent review, name clearance, artifacts, and a versioned release remain |

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
level 10, and was searchable in the green single-node indexer under the same trace ID.
This closes the Stage 9 implementation, but the live path must be repeated on
the exact SDK v2 release candidate before a versioned release.

Stage 10 now has a versioned deterministic suite with 30 legitimate calls, 30
forbidden calls, 10 catalog-drift changes, and 5 overuse/approval-abuse cases.
The runner uses the real local MCP server and installed enforcement proxy,
production drift/limit/permit services, and all 22 Wazuh fixtures. The latest
clean post-lifecycle-correction Windows reference at commit `3f7ba2a` passed all 75 cases and
reduced the exposed catalog
from 7 to 4 tools (42.86%), blocked all labeled forbidden calls with no labeled
legitimate-call false positives, and detected every labeled drift and overuse
case. It publishes schema-valid raw results and p50/p95/p99 timings with explicit
machine and claim limitations. It must be rerun only if the final candidate's
executable code or locked dependencies change.

Stage 11 has started with a read-only GitHub Actions workflow, full-SHA action
pins, a Linux/Windows and Python 3.13/3.14 test matrix, build smoke tests,
Dependabot configuration, structured issue forms, a security-aware pull-request
template, an explicit release process, and a source-checkout safe demo. The demo
uses the real enforcement proxy, exposes three tools from a seven-tool lab,
passes three exact read-only calls, rejects a direct hidden write-tool call
before forwarding, and validates seven privacy-minimized events. The source
repository is public as a pre-alpha project, and hosted CI passed on Linux and
Windows with Python 3.13 and 3.14 at publication commit `e4f54a8`. A post-migration source build produced a 56-entry wheel
and 198-entry source archive, both passed isolated installation smoke tests,
and a fresh 197-file clean-tree copy passed locked installation, CLI startup,
and the safe demo.

The SDK v2 publication audit also detected CVE-2026-69247 in transitive
`cryptography 49.0.0`. The lock and runtime floor now use patched 50.0.0; a
second scan of all 39 locked runtime packages reported zero known
vulnerability matches. Licence metadata for the runtime graph is compatible
with Apache-2.0. These checks must be repeated on the exact release candidate.

The post-SDK2 controlled real-Claude profiling phase also passed: two explicitly
completed runs made
exactly six successful calls to the three expected read-only lab tools, no unused
tool was called, and the sealed evidence passed a raw-value and personal-identifier
scan. Its evidence fingerprint is
`sha256:5b93f87eb9ea1c232bc51ecfca1f4f9aa03170835e76f8c63df017ae2fe46f98`.
The operator then explicitly reviewed all seven tools. The generated
deny-by-default policy passed a direct enforcement preflight with three visible
tools, four direct denials, exact argument and task-limit rejection, downstream
non-forwarding, and privacy-safe JSONL/SQLite evidence. The final enforced Claude
run also passed: the model saw only three tools, called each exactly once, and
produced six schema-valid privacy-minimized audit events. The current gates are
the post-SDK2 Wazuh live refresh, independent clean-clone and security review,
final name clearance, release artifacts, and a versioned release. The refreshed clean
benchmark passes all 75 cases at commit `3f7ba2a`.
