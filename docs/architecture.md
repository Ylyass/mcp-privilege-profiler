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

## Enforcement path

    reviewed policy-v1 + trusted task/agent IDs + path-root bindings
      -> strict policy and constraint validation
      -> initialized downstream session
      -> complete catalog collection and exact fingerprint gate
      -> filtered tools/list
      -> exact decision and in-memory constraint checks
      -> persistent rate/task reservation + in-process concurrency reservation
      -> exact single-use permit check when approval is required
      -> privacy-minimized decision event appended and fsynced
      -> downstream tools/call
      -> privacy-minimized completion event

The policy carries one rule for every tool in the reviewed catalog and declares
`default_effect: DENY`. Startup requires exact rule coverage and the exact
complete-tool fingerprint. This is stricter than accepting only the names that
appear in an allowlist: it detects both missing review decisions and rules for
tools absent from the live server.

Path constraints refer to symbolic aliases. Trusted launch configuration binds
each alias to an existing directory and resolves it once. URL constraints use
exact normalized scheme and host comparisons. Enum comparison is type-exact,
and byte limits use strict UTF-8 encoding. Constraint errors identify only the
kind and argument name, never the rejected value.

The enforcement catalog is a single complete filtered page containing ALLOW
and REQUIRE_APPROVAL definitions. DENY definitions are absent. Direct calls to
DENY or unknown names are still rejected before forwarding.

Every non-DENY review decision includes finite positive per-minute, per-task,
and concurrent-call limits. The fixed-window minute and task counters persist
in SQLite so a proxy restart does not reset them. Concurrency is maintained
inside the one v0.1 proxy process and is released in a `finally` path. A
reservation is rolled back when the call was not forwarded, including
mandatory pre-forward audit failure.

The audit builder starts from an explicit allowlist of scalar metadata. It may
record sorted argument key names, canonical byte size, normalized URL
scheme/host, symbolic path-root alias, risk category, capability tags,
fingerprints, decisions, and timing. It never copies argument values or tool
result bodies. Each JSONL object is appended and fsynced before a permitted
downstream call. The sink remains bound to the exact regular file opened at
startup; write failure or file replacement closes the enforcement gate.

`REQUIRE_APPROVAL` arguments remain only in live proxy memory. The proxy
publishes an ephemeral capability file for an authenticated loopback control
endpoint. The local permit CLI uses that separate channel to show the exact
pending request to the operator. Approval first writes its audit event, then
persists an HMAC-SHA256 permit containing an RFC 8785 argument digest, expiry,
nonce, and single-use state—but no raw arguments. Only the exact retry can
atomically consume it. Changed arguments, expiry, invalid MAC, excessive
backward clock skew, or replay fail closed. A proxy restart invalidates live
pending requests and its in-memory HMAC secret. The control capability and
permit-signing key are independent random 256-bit secrets; the signing key is
never written to the control file.

A downstream tools-list change invalidates the gate synchronously in the MCP
message handler. A separate worker recollects the complete catalog; only the
exact approved digest can restore validity. This avoids I/O deadlock in the
receive loop while leaving no interval where changed definitions are trusted.

## Layer responsibilities

| Layer | Responsibility |
|---|---|
| Domain | Profile/run state machines, exact review coverage, default-deny policy, constraint, limit, and permit facts |
| Application | Evidence aggregation, fingerprints, lifecycle orchestration, constraint evaluation, audit construction, limit coordination, and permit lifecycle |
| Ports | Audit and storage interfaces independent of JSONL and SQLite |
| MCP adapters | Strict downstream session, proxy forwarding, catalog invalidation, and local approval control |
| SQLite adapters | Atomic migrations, persistent usage counters, permit state, and privacy-safe evidence |
| Contracts | Strict versioned JSON evidence, review, policy, and event models |
| CLI | Trusted composition, bounded file input, atomic artifact writes |

Policy enforcement, catalog minimization, and reviewed path/URL/enum/byte
constraints, limits, mandatory pre-forward audit, and approval permits are
active. The Stage 9 Wazuh rules, fixtures, and pinned local lab definition now
exist and pass static validation. All 22 cases also pass real Wazuh 4.14.6
`wazuh-logtest`. A bounded live probe proved one real proxy denial traveled
through Wazuh agent `001`, matched manager rule `100103` at level 10, and was
searchable in the green single-node indexer under the same trace ID.
