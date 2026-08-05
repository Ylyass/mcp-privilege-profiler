# Changelog

All notable changes are documented here.

## Unreleased

- Repeated the controlled real-Claude acceptance after the SDK 2.0.0 migration:
  two explicitly completed profile runs produced six successful read-only calls,
  sealed evidence fingerprint
  `sha256:5b93f87eb9ea1c232bc51ecfca1f4f9aa03170835e76f8c63df017ae2fe46f98`,
  and zero unused-tool calls.
- Completed the post-SDK2 seven-tool review and generated policy
  `claude-dependency-review-sdk2-rc1-policy-001`, then passed a fresh direct
  enforcement preflight with three visible tools, four hidden-tool denials,
  three argument-boundary denials, one task-limit denial, downstream
  non-forwarding, and 14 privacy-checked events.
- Completed a real Claude Code 2.1.222 enforcement run through the generated
  policy: exactly three approved calls succeeded, persistent counters recorded
  one call per tool, six `event-v1` records validated, and JSONL/SQLite scans
  found none of the prohibited raw or personal values.
- Passed the first hosted GitHub Actions run on Linux and Windows with Python
  3.13 and 3.14, including quality/security contracts, the full test matrix,
  and wheel/source-distribution smoke tests.
- Require explicit operator confirmation before a successful profile run can
  strengthen least-privilege evidence, with atomic rejection when any tool call
  is unfinished.
- Migrated the complete proxy, lab, tests, and locked environment to the stable
  MCP Python SDK 2.0.0 and its 2026-07-28 protocol types.
- Switched downstream connections to SDK v2 auto negotiation, disabled the
  SDK response cache for security-relevant catalogs, and added a verified
  current-protocol client-to-proxy-to-server integration path.
- Separated downstream handshake deadlines from catalog and tool-call deadlines
  so automatic negotiation cannot shorten later authorized operations.
- Added serialized full-catalog revalidation before each upstream
  `tools/list` and `tools/call`. This preserves fail-closed drift enforcement
  even when a 2026-era connection does not deliver legacy list-change
  notifications.
- Removed a second unvalidated catalog fetch from profile `tools/list`; the
  host now receives the exact complete snapshot that passed revalidation.
- Raised the transitive cryptography floor to 50.0.0 after the release audit
  detected CVE-2026-69247 in 49.0.0, then re-scanned the locked 39-package
  runtime graph with zero known vulnerability matches.
- Added public project metadata for the selected GitHub repository and a
  private-vulnerability-reporting workflow that avoids publishing a personal
  email address.
- Added a tested, one-command, non-Docker safe demo that runs the real
  enforcement proxy, exposes three of seven fixture tools, completes three
  exact allowed calls, denies a direct hidden write-tool bypass before
  forwarding, validates seven `event-v1` records, checks raw-value absence, and
  removes its temporary policy, audit, and database.
- Removed Windows-only `.venv/Scripts/mcp-privprof.exe` assumptions from
  integration tests so the declared Linux CI matrix can resolve the installed
  console script portably.
- Added source-checkout prerequisites, expected demo output, cleanup behavior,
  honest claim limits, and the current core-wheel versus repository-asset
  package boundary.
- Documented that POSIX owner-only mode does not establish Windows NTFS ACLs
  and that Windows operators must protect the trusted state directory.
- Revalidated the MCP baseline on the 2026-07-28 protocol-transition date,
  temporarily retained v1 while v2 stabilized, and later superseded that
  boundary through the tested SDK v2 migration recorded in ADR 0010.
- Removed a Windows subprocess-cleanup race from the hanging-startup integration
  test while retaining the proxy's 0.1-second security timeout and a finite
  outer test deadline.
- Added a documented real-Claude profiling acceptance with two controlled runs,
  six expected read-only MCP calls, a sealed evidence fingerprint, and a privacy
  scan.
- Recorded the explicit seven-tool human review, generated its evidence-bound
  deny-by-default policy, and passed a direct enforcement preflight covering
  catalog minimization, all four hidden-tool denials, exact constraints, limits,
  downstream non-forwarding, and JSONL/SQLite privacy.
- Completed the controlled enforced Claude run through the reviewed three-tool
  catalog with three exact successful calls, six schema-valid audit events, and
  no raw values in JSONL or SQLite.
- Added a beginner-focused visual explanation connecting the model, host, proxy,
  MCP server, evidence, policy, Docker lab, and Wazuh bridge.
- Added a minimal-permission, full-SHA-pinned GitHub Actions workflow covering
  Linux and Windows on Python 3.13 and 3.14, deterministic benchmark
  verification, and distribution smoke tests.
- Added Dependabot configuration, structured issue forms, a security-aware
  pull-request template, and an explicit pre-release publication process.
- Added repository-owned pre-commit and pre-push gates without downloading
  additional hook repositories.
- Added a cross-platform pytest launcher that avoids shared user temp roots
  while preserving tests that require the real operating-system temp boundary.
- Added a dated, primary-source competitive analysis that records substantial
  vendor overlap and narrows public positioning to the verified workflow.
- Recorded dated, exact GitHub, PyPI, and npm namespace checks while retaining
  the provisional-name warning until broader clearance is complete.
- Established the pre-alpha repository, reproducible Python baseline, initial
  default-deny policy domain, and versioned policy/event contracts.
- Added a deterministic local MCP lab whose credential, command, and network
  tools are non-destructive simulations.
- Added a transparent one-to-one stdio proxy and real client-to-proxy-to-lab
  integration tests.
- Added bounded startup and call timeouts, cancellation recovery, stable
  downstream failure codes, and disposable crash-injection tests.
- Verified two-page tool catalog forwarding and bounded cleanup of a downstream
  process that never completes MCP initialization.
- Added strict downstream message parsing so malformed JSON-RPC fails closed
  with a stable, non-sensitive error.
- Added complete paginated tool inventory, RFC 8785/SHA-256 fingerprints, and
  conservative drift classification.
- Added append-only SQLite inventory history with explicit migration and
  integrity checks.
- Added versioned JSON and escaped Markdown inventory reports plus the public
  `mcp-privprof inventory` command.
- Added non-blocking `notifications/tools/list_changed` refresh handling and a
  real MCP catalog-change integration fixture.
- Added launch-bound profiles, labeled scenario runs, and SQLite schema
  migration 2 with privacy-safe call facts.
- Added sealed `profile-evidence-v1` reports, deterministic candidate evidence
  tiers, and explicitly non-authorizing Markdown guidance.
- Added deny-by-default `review-decisions-v1` templates and exact human review
  coverage bound to the sealed evidence and toolset fingerprints.
- Added public profile, review, recovery, and policy-generation CLI workflows;
  policy generation has no path around a completed review.
- Added real MCP integration proof for successful observation, cancellation,
  fail-closed live catalog drift, argument non-persistence, and review gating.
- Added reviewed path-root, exact URL host, strict enum, and UTF-8 byte-length
  policy constraints with public JSON Schemas and SQLite schema migration 3.
- Added the public `mcp-privprof enforce` command with exact startup
  fingerprint validation and complete policy-rule coverage.
- Added catalog minimization for DENY tools and pre-forward rejection of
  denied, unknown, constraint-violating, and not-yet-approved calls using
  stable structured reason codes.
- Added immediate enforcement invalidation on `tools/list_changed`, exact
  background revalidation, adversarial constraint properties, and real MCP
  proof that blocked calls never mutate downstream state.
- Added reviewed per-tool rate, task, and concurrency limits with persistent
  SQLite reservations and rollback when a call is not forwarded.
- Added allowlist-built `event-v1` JSONL audit records, append-plus-fsync
  pre-forward decisions, exact audit-file identity checks, and fail-closed
  behavior when mandatory audit is unavailable.
- Added in-memory pending approval requests, an authenticated local loopback
  control channel, and the public `mcp-privprof permit create` workflow.
- Added expiring HMAC-SHA256 permits over exact RFC 8785 argument digests with
  atomic single-use persistence and replay, expiry, changed-argument, tamper,
  and clock-skew rejection.
- Added SQLite schema migration 4 for reviewed limit/risk metadata,
  restart-resistant enforcement counters, and privacy-minimized permit state.
- Added property, unit, and real MCP integration proof that raw arguments and
  results remain absent from JSONL/SQLite, changed arguments do not consume an
  exact approval, and audit failure prevents downstream execution.
- Added a pinned, local-only Wazuh 4.14.6 lab overlay with read-only JSONL
  ingestion and verified official source hashes.
- Added 11 custom Wazuh alert rules, 22 positive/near-miss fixture cases,
  static contract validation, and an opt-in pinned `wazuh-logtest` runner.
- Added collision-safe prefixed Wazuh transport and a dedicated decoder after
  real-engine testing exposed built-in Suricata rule precedence over generic
  JSON, then passed all 22 cases against Wazuh 4.14.6.
- Added a bounded live probe and verified a real MCP proxy denial reached the
  active named Wazuh lab agent, manager rule `100103`, and the green single-node
  indexer under the same trace ID. The probe discovers the manager-assigned
  agent ID because registration IDs may change when the lab is recreated.
- Added a schema-validated deterministic benchmark that executes the real stdio
  enforcement path for 30 legitimate and 30 forbidden calls, applies 10 tool
  drift mutations, tests five limit/permit abuse cases, revalidates all 22
  Wazuh fixtures, and publishes raw p50/p95/p99 evidence with explicit claim
  limits.
