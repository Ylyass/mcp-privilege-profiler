# ADR 0009: Prefix Wazuh transport and use a dedicated JSON decoder

Status: accepted; amends ADR 0008
Date: 2026-07-22

## Context

ADR 0008 selected Wazuh's built-in `json` decoder for pure JSONL events. Static
validation passed, but the first real Wazuh 4.14.6 test did not enter the
project rule tree. Built-in Suricata rule 86600 also uses `decoded_as=json` and
matches any decoded JSON containing both `timestamp` and `event_type`. Those
are legitimate fields in `event-v1`, so the earlier built-in-only design was
not collision-safe.

Launching `/var/ossec/bin/wazuh-logtest` as a container entrypoint also failed:
the current tool is a client of the running `wazuh-analysisd` service. A real
test must start the manager normally before invoking the tool.

## Decision

Keep the project audit file as pure, one-object-per-line JSONL. At the Wazuh
transport boundary, configure the agent `localfile` input to:

1. add the namespaced `@source=mcp_privprof` label; and
2. prefix the forwarded record with `mcp_privprof: ` using `out_format`.

Ship a minimal decoder named `mcp_privprof`. Its anchored PCRE2 `prematch`
claims only that prefix, then delegates field extraction to Wazuh's maintained
`JSON_Decoder` plugin after the prefix. The grouping rule requires this decoder,
the source label, and exact event schema version.

Run dynamic verification in one temporary, network-isolated manager container.
Wait for `wazuh-analysisd`, execute every exact fixture assertion with
`wazuh-logtest`, and remove the owned container in a `finally` path.

## Evidence

The original real-engine attempt decoded the event as `json` but finished on
built-in Suricata rule 86600. After this change, Wazuh 4.14.6 passed all 22
positive and near-miss fixture cases with decoder `mcp_privprof`.

The bounded live probe then produced a real enforcement denial, which Wazuh
agent `mcp-privprof-lab` delivered to manager rule `100103` at level 10 and the green
single-node indexer stored under the same trace ID.

## Consequences

The persisted project audit remains pure JSONL and does not acquire a
Wazuh-specific prefix. Only the forwarded copy is prefixed. The custom decoder
contains no duplicated JSON parsing logic; it provides source routing and then
uses the official JSON plugin.

The decoder becomes a required deployment artifact and is mounted read-only
beside the rules. Static validation remains useful, while the manager-backed
test is the authoritative proof against Wazuh rule and decoder precedence.
