# ADR 0010: Migrate the pre-alpha implementation to MCP Python SDK v2

Status: accepted

Date: 2026-08-05

Supersedes: [ADR 0002](0002-stable-mcp-v1-only.md)

## Context

The first implementation and controlled acceptance evidence used MCP Python
SDK 1.28.1 and the 2025-11-25 protocol behavior. SDK 2.0.0 became the stable
major line on 2026-07-28 and added the current protocol lifecycle, stricter
types, renamed APIs, and an optional client response cache.

Releasing on the older maintenance line without a continuing compatibility
need would create avoidable technical debt. Migrating silently would be worse:
it would make the existing tests, benchmark, real-agent run, and live Wazuh run
look current when they were produced against different protocol code.

The 2026-07-28 protocol also changes catalog-change delivery. Legacy
`notifications/tools/list_changed` messages are replaced by subscription
streams on a modern connection, so notification delivery alone cannot be the
security boundary of a dual-era proxy.

## Decision

1. Depend on `mcp>=2,<3` and lock MCP Python SDK 2.0.0 plus the matching
   `mcp-types` package.
2. Use the SDK v2 high-level downstream client with `mode="auto"`. A current
   peer uses `server/discover`; an older peer can fall back to the initialize
   lifecycle.
3. Disable the SDK response cache for downstream catalogs. Every security
   fingerprint must be calculated from a fresh server response.
4. Port Python fields to snake_case, low-level handlers to `on_*` constructor
   callbacks, message unions to their v2 form, and `MCPError` handling to the
   v2 API. Wire serialization continues to use MCP aliases.
5. Retain notification monitoring as an early invalidation signal, but perform
   a serialized complete-catalog revalidation immediately before every
   upstream `tools/list` and `tools/call`. A mismatch or refresh failure closes
   the gate before the requested tool can be forwarded.
6. Treat the pre-migration real-Claude, live-Wazuh, and benchmark records as
   historical evidence. Repeat the release acceptance matrix on the exact
   SDK v2 release-candidate commit before publishing v0.1.0.

## Consequences

The active code now follows the stable SDK v2 API and can negotiate the current
2026-07-28 protocol with a compatible stdio peer while retaining a legacy
fallback. Fresh pre-request catalog collection strengthens drift enforcement
across both lifecycle eras and avoids stale SDK cache entries.

The added collection round trip increases proxy latency. The benchmark must
measure that cost, and the documentation must not hide it. There remains an
unavoidable interval between any catalog check and the subsequent tool call;
the project does not claim atomicity from an MCP server that changes its tool
definition concurrently.

All old external acceptance evidence must be rerun. Passing unit and integration
tests alone does not make the migration a public release candidate.
