# ADR 0003: Launch-bound profile context

Status: accepted
Date: 2026-07-15

## Context

An upstream agent and the content it processes are untrusted. Accepting a task
type, agent ID, server ID, or scenario label from tool-call arguments or MCP
metadata would let the subject being observed choose its own security context.

Evidence collected against different tool catalogs would also be ambiguous.

## Decision

The local operator supplies profile ID, task type, agent ID, server ID, and all
planned scenario IDs at profile creation. The profile is bound to a freshly
collected complete toolset fingerprint.

Every run selects one of those planned scenarios. It recollects the downstream
catalog at startup and fails unless the fingerprint is identical. A live
tools-list change invalidates the catalog gate immediately.

## Consequences

Agent instructions and tool arguments cannot relabel evidence. Scenario labels
remain human assertions rather than facts inferred from model text. A server
update requires a new profile instead of silently mixing evidence.

The operator and launch configuration are part of the trusted computing base.
