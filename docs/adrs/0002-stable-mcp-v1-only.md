# ADR 0002: MCP SDK v1 compatibility boundary for version 0.1

Status: superseded by [ADR 0010](0010-migrate-to-mcp-sdk-v2.md)

Date: 2026-07-14

Revalidated: 2026-07-30

Superseded: 2026-08-05

## Context

The implementation, automated tests, Claude acceptance evidence, and committed
benchmark for version 0.1 were produced with MCP Python SDK 1.28.1 and the
2025-11-25 protocol behavior.

On 2026-07-28, MCP Python SDK 2.0.0 became the current stable major version and
the v1.x branch moved to maintenance and security fixes. The 2026-07-28
protocol revision also changes the compatibility surface. A late, silent
migration would therefore invalidate the existing evidence and combine a major
SDK migration with a protocol-boundary change.

## Decision

At the time this decision was accepted, the pre-alpha implementation retained
`mcp>=1.28.1,<2` and the 2025-11-25 protocol behavior as its tested
compatibility boundary. This was not a statement that v1 was the current
stable SDK.

Before the release candidate, the project will make one explicit decision:

1. migrate to SDK v2 and rerun the complete quality, security, Claude, Wazuh,
   and benchmark matrix; or
2. retain a tested v1 maintenance release for the initial release, document
   the limited support window, and publish a v2 migration plan.

The current v1 maintenance release must be evaluated on a separate
compatibility branch at minimum.

## Consequences

The existing evidence remains reproducible because its dependency and protocol
boundary is unchanged. However, the project cannot describe SDK v1 as the
current stable line, and it cannot treat the present dependency constraint as
a final public-release decision. Any migration uses a dedicated compatibility
branch and lockfile, and the resulting build must reproduce the complete
verification evidence before it replaces the current boundary.

## Supersession note

MCP Python SDK 2.0.0 was subsequently migrated, locked, and verified. ADR 0010
records the replacement compatibility and drift-control decision. This file is
retained as the historical reason the project did not adopt a prerelease SDK.
