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
- ephemeral local approval-control capability;
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
13. Every non-DENY rule has finite human-reviewed rate, task, and concurrency
    limits.
14. A `REQUIRE_APPROVAL` call is forwarded only after one exact unexpired
    HMAC permit is atomically consumed.
15. Raw pending approval arguments remain in live proxy memory and the local
    operator terminal; they are not stored in audit JSONL or SQLite.

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
- Downstream timeout and session failure are bounded and returned as stable
  infrastructure errors. Cancellation continues to propagate rather than being
  fabricated as a decision.

## Stage 8 failure behavior

- A non-DENY policy rule without all three finite reviewed limits prevents
  startup.
- Persistent per-minute and per-task counters survive proxy restart.
  Concurrency is bounded within the one v0.1 proxy process.
- Limit-state failure, limit exhaustion, missing approval, permit verification
  failure, and mandatory pre-forward audit failure all prevent downstream
  forwarding.
- A pre-forward audit reservation is rolled back when the call does not reach
  the downstream server.
- Audit append uses the exact regular-file identity established at startup.
  Replacement, symlink/non-file initialization, append failure, or fsync
  failure closes the audit gate.
- A completion-audit failure cannot undo an already completed downstream
  action. The proxy returns the real result to avoid a blind retry and closes
  the gate for future calls.
- Approval uses a separate authenticated loopback endpoint because stdio is
  occupied by MCP. The capability file is created exclusively, contains a
  random 256-bit live secret distinct from the in-memory HMAC signing key, and
  is removed only if its file identity still matches.
- Owner-only POSIX mode is not an NTFS ACL guarantee. On Windows, secrecy of
  the capability, policy, audit, and SQLite files depends on the trusted
  operator selecting a parent directory with appropriately restricted Windows
  permissions; the proxy does not configure that operating-system boundary.
- Approval audit failure prevents permit persistence. Changed arguments,
  expiry, invalid HMAC, excessive backward clock skew, and atomic replay all
  fail closed.
- A restart discards pending raw arguments, the live HMAC secret, and the
  in-memory approved-permit index. Previously persisted metadata cannot restore
  authority.

## Non-goals

- proving a tool is unnecessary from observation;
- preventing every prompt injection;
- detecting every possible secret;
- protecting every MCP transport or server;
- coordinating concurrency across multiple proxy processes;
- providing remote or unattended approval;
- encrypting trusted local state at rest;
- replacing a full SIEM, authorization system, or sandbox.
