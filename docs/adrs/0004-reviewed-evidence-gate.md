# ADR 0004: Sealed evidence and exact human review gate

Status: accepted
Date: 2026-07-15

## Context

Observed success can show that a tool was useful in one run, but it cannot prove
that the tool is necessary, safe, or appropriate to authorize. Automatically
turning observed use into permission would reproduce compromised-agent behavior
as policy.

## Decision

Profiles must be sealed before review. Sealing is one-way and requires at least
one completed run with no open runs. Candidate reports use reproducible counts
and non-authorizing recommendations.

A completed review must contain exactly one explicit effect for every tool in
the bound catalog. It stores the exact evidence and toolset fingerprints.
Policy generation reloads the sealed facts, recomputes evidence, and succeeds
only through that completed review.

Generated review templates set every tool to `DENY` before operator edits.

## Consequences

There is no observation-to-allow shortcut. Missing tools, duplicate decisions,
stale evidence, and substituted catalogs fail validation. Human review adds an
intentional operational step, but its scope and provenance are auditable.
