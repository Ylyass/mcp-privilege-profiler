# Profiling and human review

## What this stage does

This project does **not** train an AI model or create an AI agent. It wraps the
MCP connection used by an existing agent, records small security facts about
real task runs, and helps a human write a least-privilege policy.

MCP (Model Context Protocol) is the protocol between an AI host and a tool
server. An MCP server advertises tools such as `read_fixture`; the host sends a
`tools/call` request when its agent chooses one. During profiling, this project
sits between those two sides:

    existing AI host or MCP test client
      -> MCP over stdio
    mcp-privprof profile run
      -> records tool name, time, and outcome only
      -> MCP over stdio
    one configured MCP server

The proxy forwards arguments and results in memory so the tool still works. It
does not persist their contents.

## Why each technology is used

| Technology | Job in this stage |
|---|---|
| Python 3.13+ | Implements the application and deterministic lab |
| MCP Python SDK v2 | Provides current and legacy MCP client/server sessions and protocol types |
| AnyIO | Runs asynchronous sessions, timeouts, cancellation, and cleanup |
| SQLite with aiosqlite | Stores inventory, labeled runs, privacy-safe call facts, and completed reviews |
| Pydantic and JSON Schema | Reject malformed evidence, review, and policy documents |
| RFC 8785 plus SHA-256 | Binds profiles and reviews to exact, deterministic tool catalogs and evidence |
| Typer | Exposes the operator CLI without shell-building downstream commands |
| pytest, Hypothesis, Ruff, and Pyright | Verify behavior, invariants, style, and strict types |

There is no vector database, model fine-tuning, prompt training, or statistical
classifier in this stage. Evidence tiers are transparent counting rules.

## The complete workflow

### 1. Create a trusted profile

The operator fixes the task type, agent ID, server ID, and planned scenarios at
launch. The command inventories a freshly started server, stores that exact
catalog, and creates an open profile bound to its SHA-256 fingerprint.

    uv run mcp-privprof profile create --profile-id dependency-review-v1 --task-type dependency-review --agent-id agent-1 --server-id lab --scenario read-project --database .mcp-privprof/state.sqlite3 -- python -m lab.server

These labels are trusted operator configuration. Tool-call arguments and
agent-supplied metadata cannot change them.

### 2. Run each planned scenario through the proxy

Configure the MCP host to launch this command as its MCP server command:

    uv run mcp-privprof profile run --profile-id dependency-review-v1 --run-id run-001 --scenario-id read-project --database .mcp-privprof/state.sqlite3 -- python -m lab.server

This is an MCP stdio server, not an interactive shell command. When launched by
itself it waits for MCP JSON-RPC input. Everything after `--` is passed directly
to one downstream process without shell interpolation.

For every `tools/call`, the proxy first stores an attempt, then forwards it. A
normal result becomes `SUCCESS` or `TOOL_ERROR`; transport and timeout failures
become `INFRASTRUCTURE_ERROR`. Cancellation leaves an incomplete attempt rather
than inventing an outcome.

The downstream catalog is collected again when the run starts and immediately
before every upstream `tools/list` or `tools/call`. A mismatch closes the exact
catalog gate. A legacy `notifications/tools/list_changed` signal can invalidate
the gate earlier, but correctness does not depend on that signal because the
2026-07-28 protocol delivers changes through subscriptions instead.

For `tools/list`, the proxy returns the exact complete snapshot that passed this
check as one page. It does not issue a second downstream list request after
validation, and an unexpected upstream cursor is rejected.

### 3. Seal evidence

    uv run mcp-privprof profile seal --profile-id dependency-review-v1 --database .mcp-privprof/state.sqlite3 --json-report profile-evidence.json --markdown-report profile-evidence.md --review-template review-decisions.json

Sealing requires no open runs and at least one completed run. It freezes the
profile and writes:

- `profile-evidence.json`: schema-versioned machine evidence;
- `profile-evidence.md`: an escaped human summary;
- `review-decisions.json`: one editable decision per available tool, initially
  `DENY` for every tool.

The evidence fingerprint excludes report-generation time, so regenerating a
report for the same sealed facts produces the same identity.

### 4. Review every available tool

Read the evidence, edit each effect to `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`,
and then complete the review. Every non-DENY decision must also contain finite
`max_calls_per_minute`, `max_calls_per_task`, and `max_concurrent_calls`
values, one lowercase `primary_risk_category`, and zero or more lowercase
`capability_tags`. DENY keeps `limits: null` and cannot contain constraints.

    uv run mcp-privprof review complete --review-id review-001 --reviewer operator@example.test --decisions review-decisions.json --database .mcp-privprof/state.sqlite3

Observation never decides permission. The review is accepted only when it
covers the exact available catalog once and its evidence fingerprint still
matches the sealed profile.

### 5. Generate reviewed policy

    uv run mcp-privprof policy generate --review-id review-001 --policy-id policy-001 --database .mcp-privprof/state.sqlite3 --output policy.json

Policy generation has no path around the completed-review record. The policy
contains the reviewed profile ID, exact toolset fingerprint, effects, and any
reviewed constraints, limits, and risk metadata. Stages 7 and 8 enforce it,
filter `tools/list`, write mandatory privacy-minimized audit, and provide exact
single-use approval; see the [enforcement guide](enforcement.md).

## How evidence is interpreted

Only successful calls in completed runs strengthen candidate evidence. An
aborted-run success remains visible in totals but does not strengthen a tier.

| Tier | Reproducible rule |
|---|---|
| Strong | Success in at least three distinct completed runs and every planned scenario |
| Moderate | Success in at least two distinct completed scenarios |
| Weak | Success in at least one completed run |
| Unobserved | No success in a completed run |

The UI says `consider_allow`, not “required” or “approved.” A tool seen in call
facts but absent from the bound catalog is marked `investigate_unlisted`.

## Recovery and current boundary

If a host is killed so abruptly that normal cleanup cannot finish, close the
leftover run explicitly before sealing:

    uv run mcp-privprof profile abort-run --run-id run-001 --database .mcp-privprof/state.sqlite3

The local operator and storage directory remain trusted. SQLite schema version
4 stores reviewed constraints, limit/risk metadata, enforcement counters, and
permit metadata while retaining no argument or result columns in
`profile_calls` or `approval_permits`. The default evidence is data
minimization, not encryption; operators must still protect the database and
report files.

This stage recommends candidates and generates a reviewed policy artifact.
Stages 7 and 8 now enforce effects, exact argument constraints, limits,
mandatory audit JSONL, and single-use approval permits. Stage 9 now includes
the static Wazuh detection pack and local lab definition; real Wazuh analysis
passes all 22 fixture cases, and the bounded live ingestion probe passes from
proxy through Wazuh agent, manager rule, and indexer.
