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
