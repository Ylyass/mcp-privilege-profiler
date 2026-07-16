# Changelog

All notable changes are documented here.

## Unreleased

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
