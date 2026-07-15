# Threat model

## Scope

The first release wraps one local stdio MCP server with one proxy process.
Remote transports, server aggregation, and multi-tenant operation are out of
scope.

## Trust boundaries

Trusted:

- local operator;
- launch-time configuration;
- reviewed local policy;
- proxy process and storage directory;
- local permit secret;
- configured Wazuh deployment.

Untrusted:

- upstream host or agent;
- task instructions and retrieved content;
- downstream tool names, schemas, descriptions, and annotations;
- all tool arguments and results;
- identifiers included in MCP call metadata;
- changed downstream tool definitions.

## Security invariants

1. Default policy effect is DENY.
2. A learned observation cannot allow a call without human review.
3. In enforce mode, denied tools are not returned by tools/list.
4. Enforce mode rejects denied and unknown calls before forwarding.
5. Security-widening drift blocks enforcement until review.
6. Default audit events exclude raw arguments and tool results.
7. A required audit-write failure blocks forwarding.
8. Profile evidence is bound to trusted launch labels and one exact catalog.
9. Profile persistence excludes raw arguments and result bodies.
10. Policy generation requires an exact completed review of sealed evidence.
11. Every enforced constraint is part of that completed review.
12. Constraint denials expose argument identity but not the rejected value.

## Stage 6 failure behavior

- A catalog mismatch at profile-run startup aborts the run before evidence is
  mixed across toolsets.
- A live tools-list change invalidates the profile catalog gate immediately.
- An attempted call is persisted before forwarding; cancellation remains
  incomplete rather than becoming a fabricated outcome.
- A stale evidence fingerprint, incomplete review, duplicate decision, or
  unknown reviewed tool prevents review completion or policy generation.
- A hard-killed host can leave an open run because no process can guarantee a
  final database write after termination; the trusted operator must mark that
  run aborted before sealing.

## Stage 7 failure behavior

- Policy parse or domain validation failure prevents enforce mode from
  starting.
- Every live tool must have exactly one reviewed policy rule; partial and
  extra-rule policies prevent startup.
- A stale complete-tool fingerprint prevents startup. A live list-change signal
  invalidates the gate before background revalidation begins.
- DENY entries are removed from `tools/list`, but call-time checks remain the
  authorization boundary and reject direct denied or unknown requests.
- Missing constraint arguments, type mismatches, traversal, URL normalization
  bypasses, enum misses, and UTF-8 byte overages return stable errors without
  forwarding.
- A constraint name absent from the reviewed tool schema prevents startup, and
  an otherwise allowed call must still satisfy that exact input schema.
- `REQUIRE_APPROVAL` fails closed until Stage 8 implements a separate
  single-use permit channel.
- Downstream timeout and session failure are bounded and returned as stable
  infrastructure errors. Cancellation continues to propagate rather than being
  fabricated as a decision.

Mandatory audit-before-forward is not present in Stage 7. Therefore the Stage
8 invariant that an audit-write failure blocks forwarding is not yet claimed.

## Non-goals

- proving a tool is unnecessary from observation;
- preventing every prompt injection;
- detecting every possible secret;
- protecting every MCP transport or server;
- replacing a full SIEM, authorization system, or sandbox.
