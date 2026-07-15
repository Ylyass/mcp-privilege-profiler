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
- non-blocking handling of `notifications/tools/list_changed` for long-running sessions;
- trusted, launch-bound profiles and labeled scenario runs;
- privacy-safe call evidence containing names, times, and outcomes only;
- sealed evidence reports with reproducible candidate tiers;
- deny-by-default human review files and review-gated policy generation;
- reviewed path, URL, enum, and UTF-8 byte constraints;
- exact-fingerprint enforcement with filtered `tools/list`;
- pre-forward denial of unknown, DENY, constrained, and unapproved calls; and
- immediate fail-closed handling of live tool-catalog changes.

Limits, mandatory audit delivery, approval permits, Wazuh content, hosted CI,
and release publication are not implemented yet. See the
[roadmap](docs/roadmap.md) for the order and current boundary.

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

Create a profile bound to a freshly inventoried lab catalog:

    uv run mcp-privprof profile create --profile-id dependency-review-v1 --task-type dependency-review --agent-id agent-1 --server-id lab --scenario read-project --database .mcp-privprof/state.sqlite3 -- python -m lab.server

Run the profile proxy as the MCP server configured in a host:

    uv run mcp-privprof profile run --profile-id dependency-review-v1 --run-id run-001 --scenario-id read-project --database .mcp-privprof/state.sqlite3 -- python -m lab.server

Then seal the evidence, edit the generated deny-by-default review file, complete
human review, and generate policy:

    uv run mcp-privprof profile seal --profile-id dependency-review-v1 --database .mcp-privprof/state.sqlite3
    uv run mcp-privprof review complete --review-id review-001 --reviewer operator@example.test --decisions review-decisions.json --database .mcp-privprof/state.sqlite3
    uv run mcp-privprof policy generate --review-id review-001 --policy-id policy-001 --database .mcp-privprof/state.sqlite3 --output policy.json

This is deterministic evidence collection and human review, not AI model
training. See the [profiling guide](docs/profiling.md) for the complete data
flow, technology roles, evidence rules, and recovery command.

After review and policy generation, run the live enforcement proxy:

    uv run mcp-privprof enforce --policy policy.json --path-root PROJECT_ROOT=lab/fixtures --cwd . -- python -m lab.server

The path-root option is required only when the reviewed policy refers to that
symbolic alias. Enforce mode verifies the exact live toolset, exposes only
`ALLOW` and `REQUIRE_APPROVAL` tools, and forwards only passing `ALLOW` calls.
`REQUIRE_APPROVAL` fails closed until Stage 8 adds single-use permits. See the
[enforcement guide](docs/enforcement.md) for constraints, failure behavior, and
stable reason codes.

## Planned commands

    mcp-privprof permit create

The permit command is not implemented yet.

## License

Apache-2.0. See LICENSE.
