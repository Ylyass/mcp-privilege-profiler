# ADR 0008: Pinned Wazuh JSONL bridge and fixture-tested rules

Status: accepted
Date: 2026-07-19

## Context

ADR 0007 made the local privacy-minimized JSONL audit mandatory before a
downstream tool call. Stage 9 must turn that evidence into Wazuh detections
without weakening the enforcement path, exposing the local lab, inventing a
custom JSON decoder, or making fixture-only behavior look live.

The word "agent" is ambiguous in this system. The AI agent or MCP host chooses
tools. A Wazuh agent is a separate log collector. The Wazuh component must
receive completed event records, never participate in the pre-forward
authorization decision.

## Decision

Use official Wazuh Docker `4.14.6` and pin the official `v4.14.6` deployment
inputs to commit `499184cbeb44fc1086791d11ad4b9bdcb77a9bb9` plus hashes for the
three consumed files. Build the local lab as a project overlay instead of
copying or modifying the GPL-licensed official deployment in this repository.

Mount the project JSONL file read-only into the official Wazuh agent container.
Configure `localfile` with `log_format=json`, `only-future-events=yes`, and the
Wazuh-added `@source=mcp_privprof` label. Require that label and exact event
schema version in the level-zero grouping rule. Use Wazuh's built-in JSON
decoder.

Keep all custom IDs inside `100000`–`120000`. Use anchored PCRE2 field
expressions and scalar event fields. Suppress `full_log` duplication. Provide a
positive and a near-miss fixture for every alert rule.

Use two distinct verification claims:

1. static validation proves XML structure, event-contract validity, fixture
   pairing, and target-condition separation;
2. `wazuh-logtest` in the pinned manager image proves actual Wazuh decoder and
   rule behavior.

The full live exit gate additionally requires read-only JSONL ingestion from
proxy to agent to manager. Bind all published lab ports to loopback and remove
the indexer host port.

Treat unapproved-server, policy-load-failure, and audit-failure detections as
fixture-tested forward contracts until a separate privacy-minimized health
producer is implemented. The primary audit file cannot reliably report its own
failure. A later health path is best effort and must never weaken fail-closed
enforcement.

## Consequences

The detection pack is reproducible, based on maintained official inputs, and
can be tested without a custom decoder. The project does not vendor the Wazuh
Docker repository or mix its GPL deployment files into the Apache-2.0 source
tree.

Static tests remain available on machines without Docker. Real Wazuh rule and
live ingestion claims remain incomplete until Docker/WSL prerequisites are
available and both dynamic gates pass.

The full single-node lab is intentionally heavier than a mocked rule engine,
but it provides manager, indexer, dashboard, and agent evidence matching the
documented architecture. It is local-only, disposable, uses no real personal
data, and is not a production deployment.
