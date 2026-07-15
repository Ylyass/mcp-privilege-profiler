# Architecture

## Verified transport foundation

    MCP test client
      -> stdio
    MCP Privilege Profiler transparent proxy
      -> persistent downstream ClientSession over stdio
    deterministic lab MCP server

The proxy process is both:

- an MCP server toward the upstream host; and
- an MCP client toward exactly one downstream server.

The downstream command and argument list are passed directly to the process
launcher. They are not joined into a shell command.

## Transparent-mode behavior

The Stage 4 proxy is intentionally transparent:

- tools/list is forwarded with its pagination parameters;
- the complete downstream tool definitions are returned;
- tools/call arguments are validated against the listed input schema;
- the complete downstream CallToolResult is returned;
- downstream MCP tool errors remain tool errors.
- initialization and calls have positive finite timeouts;
- call timeout and connection loss use stable, non-sensitive reason codes;
- cancellation is not converted into a result and can propagate upstream;
- SDK shutdown closes stdin, waits, then terminates the child process tree.

Pagination is verified with a two-page downstream fixture. Startup timeout is
verified with an unresponsive child fixture that is terminated during cleanup.
Malformed downstream JSON-RPC closes the downstream session and is exposed only
as the stable MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE reason code.

## Inventory and drift foundation

Inventory collection follows every tools/list page, rejects cursor cycles,
rejects duplicate tool names, and caps a catalog at 100 pages. Complete known
Tool objects are serialized with aliases, canonicalized with RFC 8785, and
hashed with SHA-256. The toolset digest is independent of catalog ordering.

Drift comparison is conservative: additions are security widening, removals are
breaking, any inputSchema change is security widening, presentation-only fields
are informational, and other changed fields require review.

## Current inventory workflow

    inventory CLI
      -> strict initialized downstream session
      -> complete paginated MCP catalog source
      -> serialized inventory application service
      -> append-only SQLite repository
      -> inventory-report-v1 JSON and escaped Markdown

Each refresh loads the latest observation for the exact trusted server ID,
appends the new complete snapshot in one transaction, and compares the two.
Repeated equal catalogs are retained as separate observations because they are
separate historical facts.

For long-running sessions, the MCP message handler only places
`notifications/tools/list_changed` into a one-element coalescing queue. A
separate worker performs the refresh. Calling tools/list directly inside the
message handler could deadlock the SDK receive loop that must deliver the
response.

The one-shot inventory CLI exits after its report and therefore does not wait
for later notifications. Profile mode composes the same verified monitor into
its long-running proxy.

## Profile, review, and policy path

    trusted CLI labels + fresh inventory snapshot
      -> open profile bound to exact toolset fingerprint
      -> one or more labeled MCP proxy runs
      -> privacy-safe call facts in SQLite
      -> sealed profile-evidence-v1 report
      -> exact human decision for every available tool
      -> completed review bound to evidence fingerprint
      -> policy-v1 artifact bound to profile and toolset

The application separates four facts that must not be collapsed:

1. a tool was available in the catalog;
2. an agent attempted the tool;
3. the tool succeeded during a completed labeled scenario;
4. a human selected a policy effect.

Only the fourth fact can produce an `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`
policy rule. Candidate evidence uses non-authorizing language.

The profile proxy stores an attempt before forwarding. The `profile_calls`
table contains only call ID, run ID, tool name, attempt time, outcome, and
completion time. Arguments and results cross the proxy in memory but have no
profile persistence fields.

At profile creation, trusted task, agent, server, and scenario labels are bound
to a fresh inventory snapshot. At run startup, the proxy recollects the catalog
and requires the exact same fingerprint. A live list-changed notification
invalidates the gate immediately; a background full refresh can revalidate only
an exact match. This prevents mixed-catalog evidence.

Sealing is one-way and requires no open runs plus at least one completed run.
The review input must cover every available tool exactly once and match the
sealed evidence fingerprint. Policy generation reloads and fingerprints the
evidence again, so a stale or substituted review cannot generate policy.

## Layer responsibilities

| Layer | Responsibility |
|---|---|
| Domain | Profile/run state machines, exact review coverage, default-deny policy facts |
| Application | Evidence aggregation, deterministic fingerprints, lifecycle orchestration |
| Ports | Storage interfaces independent of SQLite |
| MCP adapters | Strict downstream session, proxy forwarding, catalog invalidation |
| SQLite adapters | Atomic migrations and privacy-safe durable state |
| Contracts | Strict versioned JSON evidence, review, policy, and event models |
| CLI | Trusted composition, bounded file input, atomic artifact writes |

Policy enforcement, catalog filtering by policy, argument constraints, limits,
and mandatory audit events are not active yet. Stage 7 will consume the reviewed
policy and make authorization decisions before forwarding.
