# ADR 0007: Reviewed limits, mandatory audit, and single-use permits

Status: accepted
Date: 2026-07-16

## Context

ADR 0006 established exact policy enforcement but deliberately left
`REQUIRE_APPROVAL` fail-closed until approval, limit state, and mandatory audit
could be designed as one pipeline.

Three failures must be prevented:

- an approved capability being used without a finite task/rate boundary;
- a downstream side effect occurring without a durable security decision; and
- a human approval authorizing different arguments, surviving too long, or
  being replayed.

Proxy standard input cannot be used for interactive confirmation because it is
the MCP JSON-RPC transport. Persisting raw pending arguments would also violate
the default privacy boundary.

## Decision

Make all three finite per-tool limits part of every non-DENY human review
decision and copy them unchanged into policy. Persist fixed-window per-minute
and per-task reservations in SQLite. Maintain concurrency inside the one v0.1
proxy process.

Construct `event-v1` records from an explicit scalar allowlist. Exclude raw
argument values, canonical argument bytes, and result bodies. Bind the JSONL
sink to the exact regular-file identity opened at startup. Append and fsync the
allowed decision before forwarding; audit failure rolls back the unused limit
reservation and closes the gate.

Keep pending raw approval arguments only in proxy memory. Publish an
exclusively created capability file for an authenticated loopback control
endpoint. The local CLI displays the exact request and defaults confirmation
to No. Use independent random 256-bit values for control authentication and
permit signing so the HMAC key is never written to the capability file.

After an approval event is durably written, create an HMAC-SHA256 permit over
the task, policy, server, tool, RFC 8785 argument digest, issue/expiry times,
random nonce, request ID, and permit ID. Persist only this metadata. The exact
retry atomically consumes the permit once.

## Consequences

Rate and task budgets survive restart. Concurrency is intentionally
single-process because v0.1 supports one local stdio proxy process per boundary.
Approval-required calls and failed pre-forward audit do not consume a
downstream-call budget.

Changed arguments, expiry, invalid HMAC, excessive backward clock skew, audit
failure, and replay fail closed. A restart discards pending raw arguments and
the live HMAC secret, so persisted permit metadata cannot independently restore
authority.

The approval-control capability file is sensitive local state and must be
protected like a live credential. Remote approval, cross-process concurrency,
automatic log rotation, Wazuh delivery, and encryption at rest remain separate
decisions.
