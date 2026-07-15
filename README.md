# MCP Privilege Profiler

MCP Privilege Profiler is a task-scoped MCP stdio proxy that learns candidate
least-privilege policies from labeled successful runs, requires human review,
enforces exact decisions, detects tool-definition drift, and emits
privacy-minimized JSONL events for Wazuh.

Status: pre-alpha. The name is provisional until package, repository, domain,
and trademark checks are completed.

## Security boundary

Version 0.1 supports one downstream local stdio MCP server per proxy process.
The trusted task type, agent ID, and server ID are fixed at launch time. The
proxy does not trust task labels supplied in tool-call metadata.

Enforce mode is deny-by-default:

- unlisted tools are hidden from tools/list;
- denied or unknown calls are rejected before forwarding;
- a human-reviewed profile is required before a policy is enforceable;
- raw tool arguments and results are not persisted in default audit events.

## Development status

The current verified build includes:

- professional repository, security-contract, and deterministic lab foundations;
- a one-to-one transparent MCP stdio proxy;
- complete paginated tool inventory with RFC 8785 and SHA-256 fingerprints;
- append-only SQLite inventory history and conservative drift classification;
- versioned JSON and human-readable Markdown inventory reports;
- non-blocking handling of `notifications/tools/list_changed` for long-running sessions.

Profiling, human review, enforcement, limits, audit delivery, Wazuh content, CI,
and release publication are not implemented yet. See the [roadmap](docs/roadmap.md)
for the order and current boundary.

## Current commands

Check the installed development version:

    uv run mcp-privprof version

Inventory the deterministic paginated lab server from the repository root:

    uv run mcp-privprof inventory --server-id pagination-lab --database .mcp-privprof/inventory.sqlite3 --json-report inventory-report.json --markdown-report inventory-report.md -- python -m lab.paginated_server

The inventory command calls `tools/list` only. It does not execute any exposed
tool. It follows all catalog pages, stores a new observation, compares it with
the previous observation for that exact server ID, and writes both reports.

See the [inventory guide](docs/inventory.md) for artifact semantics and failure
behavior.

## Planned commands

    mcp-privprof profile
    mcp-privprof review
    mcp-privprof enforce
    mcp-privprof permit create

These planned commands are not implemented yet.

## License

Apache-2.0. See LICENSE.
