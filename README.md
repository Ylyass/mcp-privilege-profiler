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
- reviewed per-tool rate, task, and concurrency limits;
- privacy-minimized, fsynced JSONL decisions before downstream forwarding;
- single-use, expiring HMAC approval permits over exact argument digests;
- an authenticated local approval channel that keeps raw arguments out of
  process arguments, audit JSONL, and SQLite;
- pre-forward denial of unknown, DENY, constrained, over-limit, unaudited, and
  unapproved calls; and
- immediate fail-closed handling of live tool-catalog changes;
- a pinned, local-only Wazuh 4.14.6 lab definition with read-only JSONL
  ingestion; and
- 11 custom Wazuh alert rules with 22 contract-valid positive and near-miss
  fixture cases that pass the real Wazuh 4.14.6 analysis engine; and
- a repeatable live probe proving proxy denial, agent delivery, rule `100103`,
  and searchable indexer ingestion for one exact trace; and
- a schema-validated, deterministic benchmark using the real stdio proxy path
  with 30 legitimate, 30 forbidden, 10 drift, and 5 overuse/approval-abuse
  cases, plus p50/p95/p99 measurements and raw machine-readable evidence; and
- a sealed real-Claude profiling result with two controlled runs, six expected
  successful read-only calls, zero unused-tool calls, and privacy-checked
  evidence; and
- an explicit seven-tool review and generated policy whose direct enforcement
  preflight exposed three read-only tools, denied all four hidden tools, enforced
  exact arguments and task limits, prevented downstream writes, and omitted raw
  values from JSONL and SQLite; and
- a successful enforced Claude task that saw only the reviewed three-tool
  catalog, called each tool once, and produced six schema-valid
  privacy-minimized events.

Hosted CI is now defined with minimal permissions and full-SHA action pins, but
it has not run because no public GitHub remote is configured. Name clearance,
the first hosted run, clean-clone testing, external review, and release
publication remain.
See the [benchmark guide](docs/benchmark.md),
[Wazuh bridge guide](docs/wazuh-bridge.md),
[competitive landscape](docs/competitive-landscape.md),
[real-agent acceptance procedure](docs/claude-code-acceptance.md),
[plain-language project explanation](docs/project-explained.md),
[release process](docs/release-process.md), and
[roadmap](docs/roadmap.md) for the verified boundary.

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

    uv run mcp-privprof enforce --policy policy.json --task-id task-001 --agent-id agent-1 --audit-log .mcp-privprof/events.jsonl --state-database .mcp-privprof/enforcement.sqlite3 --approval-control .mcp-privprof/approval-control.json --path-root PROJECT_ROOT=lab/fixtures --cwd . -- python -m lab.server

The path-root option is required only when the reviewed policy refers to that
symbolic alias. Enforce mode verifies the exact live toolset, exposes only
`ALLOW` and `REQUIRE_APPROVAL` tools, enforces the reviewed limits, and writes
the mandatory decision event before forwarding.

When a `REQUIRE_APPROVAL` call returns a request ID, the local operator can
inspect the exact pending arguments and approve one exact retry:

    uv run mcp-privprof permit create --request REQUEST_ID --control .mcp-privprof/approval-control.json

The approval-control file is an ephemeral capability containing a live secret.
Keep it accessible only to the trusted local operator and never commit it.
See the [enforcement guide](docs/enforcement.md) for the exact call order,
privacy boundary, limits, permit behavior, and stable reason codes.

Run the deterministic Stage 10 benchmark without Docker:

    uv run python -m benchmarks.runner --json-output benchmarks/results/reference-windows.json --markdown-output benchmarks/results/reference-windows.md

The runner exercises the real local MCP server and enforcement proxy, validates
75 labeled security cases, and writes versioned raw evidence plus a human-readable
report. Measurements apply only to the documented deterministic lab and host.
See the [benchmark guide](docs/benchmark.md) for methodology and claim limits.

## License

Apache-2.0. See LICENSE.
