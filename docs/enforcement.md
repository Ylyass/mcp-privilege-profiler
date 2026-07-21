# Policy enforcement

Stages 7 and 8 turn a completed human review into a live least-privilege MCP
boundary. The project does not train a model and does not infer permission.
The proxy loads exact human decisions from `policy-v1`, verifies the downstream
catalog, enforces constraints and finite limits, obtains an exact single-use
permit when required, and durably audits a passing decision before forwarding.

## Data flow

    MCP host or agent
      -> tools/list or tools/call
    enforcement proxy
      -> exact catalog fingerprint gate
      -> exact server ID + tool name decision
      -> reviewed argument constraints
      -> reviewed rate, task, and concurrency limits
      -> exact approval permit when required
      -> append + fsync privacy-minimized decision
      -> downstream MCP server
      -> append + fsync privacy-minimized completion

The proxy is an MCP server toward the host and an MCP client toward one local
stdio server. The downstream process is launched from an argument vector, not
through a shell.

## Startup gate

Before serving the upstream MCP connection, enforce mode:

1. reads at most 1 MiB from the policy file;
2. validates the strict `policy-v1` contract and converts it to domain objects;
3. resolves every trusted `ALIAS=DIRECTORY` path binding;
4. requires finite reviewed limits for every non-DENY rule;
5. requires an approval-control path when any rule uses `REQUIRE_APPROVAL`;
6. initializes the mandatory audit file and persistent enforcement state;
7. initializes the configured downstream server;
8. collects every `tools/list` page;
9. fingerprints every complete tool definition with RFC 8785 and SHA-256;
10. requires an exact match with `approved_toolset_fingerprint`;
11. requires exactly one policy rule for every observed tool; and
12. requires every reviewed constraint argument to exist in that tool's
   top-level input-schema properties.

Malformed policies, missing path-root bindings, partial rule sets, unknown
rules, stale fingerprints, missing limits, unavailable mandatory audit, and a
missing approval channel all prevent startup.

## Catalog and call behavior

`tools/list` returns one complete filtered page:

- `ALLOW` tools are visible;
- `REQUIRE_APPROVAL` tools are visible so a host can discover the capability;
- `DENY` tools are absent; and
- unlisted definitions are never exposed.

`tools/call` uses this order:

1. create one trace ID and privacy-minimized argument facts;
2. require healthy audit state and a currently valid exact catalog;
3. reject a name absent from that catalog;
4. resolve the exact reviewed rule, with missing rules treated as `DENY`;
5. evaluate every reviewed constraint in memory;
6. validate the call against the exact reviewed tool input schema;
7. reserve persistent rate/task capacity and in-process concurrency;
8. for `REQUIRE_APPROVAL`, consume one exact approved permit or return a
   pending request without forwarding;
9. append and fsync the allowed policy-decision event;
10. forward the call and release concurrency in a protected cleanup path; and
11. append and fsync the completion event without copying the result body.

A denied call is not merely hidden. A client that manually sends its name is
still rejected before the downstream server receives a tool request. Denial
events are also audited. If that audit attempt fails, the audit gate closes and
subsequent list/call operations fail safely.

## Reviewed limits

Every `ALLOW` and `REQUIRE_APPROVAL` decision must contain:

    {
      "max_calls_per_minute": 60,
      "max_calls_per_task": 100,
      "max_concurrent_calls": 2
    }

The per-minute fixed-window and per-task counters are keyed by trusted task ID,
policy ID, and exact tool name and are persisted in SQLite. They therefore
survive a proxy restart. Concurrency is counted inside the single v0.1 proxy
process. Limit reservations represent calls that can reach the downstream
server: approval-required and pre-forward-audit-failed requests roll their
reservations back.

`MCP_PRIVPROF_LIMIT_EXCEEDED` includes only `limit_type`, whose value is
`calls_per_minute`, `calls_per_task`, or `concurrent_calls`.

## Privacy-minimized mandatory audit

The `--audit-log` file contains one `event-v1` JSON object per line. The event
builder can include only explicitly approved metadata:

- trusted task, agent, policy, server, and tool identifiers;
- exact tool fingerprint, effect, decision, reason, and trace ID;
- sorted bounded argument key names and RFC 8785 canonical byte size;
- reviewed symbolic path-root alias or an exact allowlisted normalized URL
  scheme/host;
- reviewed risk category and capability tags;
- applicable limit type, permit ID, and completion duration.

Raw argument values, canonical argument bytes, tool response content, and
result bodies are excluded. The argument digest used for approval is not
written into normal policy/completion events.

Each allowed decision is appended to the exact regular file opened at startup
and `fsync` completes before the downstream request. A write error, path
replacement, or non-file destination returns
`MCP_PRIVPROF_AUDIT_WRITE_FAILED`, rolls back the unused limit reservation,
closes the audit gate, and prevents forwarding. If completion audit fails after
the downstream action already occurred, the actual downstream result is
returned to prevent a blind retry and the gate closes for future calls.

## Single-use human approval

`REQUIRE_APPROVAL` does not use proxy standard input because stdio carries MCP
JSON-RPC. Instead:

1. the first exact call is not forwarded and returns a request ID, RFC 8785
   argument digest, and expiry;
2. raw arguments remain only in live proxy memory;
3. the trusted local operator runs `permit create` against the ephemeral
   approval-control file;
4. the CLI retrieves and displays the exact request over an authenticated
   `127.0.0.1` control connection;
5. confirmation defaults to **No**;
6. an approval audit event is fsynced before permit persistence;
7. SQLite stores only identifiers, digest, times, nonce, HMAC-SHA256, decision,
   and single-use state; and
8. one exact retry verifies the digest, MAC, expiry, and clock boundary and
   atomically changes use count from zero to one.

Changed arguments do not consume the original exact permit. Expired, invalid,
clock-skewed, and replayed permits fail closed. Pending raw arguments and the
256-bit permit-signing key live only in that proxy process, so a restart
invalidates them. The approval-control file contains a separate random 256-bit
capability secret and must remain private to the trusted local operator.

## Reviewed constraints

Constraints are entered in the review decision file and therefore become part
of the evidence-bound completed review. They cannot be added later by manually
editing generated policy without breaking review provenance.

### Path containment

    {
      "kind": "path",
      "argument": "relative_path",
      "path_roots": ["PROJECT_ROOT"]
    }

At startup, bind every symbolic root to an existing trusted directory:

    --path-root PROJECT_ROOT=C:\work\project

The evaluator resolves the candidate and existing symbolic links before
containment comparison. It rejects parent traversal, outside absolute paths,
Windows drive-relative paths, alternate data stream syntax, reserved device
names, control characters, and trailing-space or trailing-dot components.

### Exact URL destination

    {
      "kind": "url",
      "argument": "url",
      "schemes": ["https"],
      "hosts": ["osv.dev"]
    }

Schemes are lowercased and hosts use exact IP or IDNA DNS normalization. DNS
suffixes, credentials in the authority, backslashes, ambiguous numeric hosts,
and non-default explicit ports are denied. Explicit standard ports such as 443
for HTTPS are equivalent to the implicit default.

### Exact enum

    {
      "kind": "enum",
      "argument": "mode",
      "values": ["safe", 1]
    }

Only exact strings and integers are supported. Booleans are not treated as
integers.

### Maximum UTF-8 bytes

    {
      "kind": "max_utf8_bytes",
      "argument": "content",
      "maximum": 4096
    }

The limit is calculated from strict UTF-8 encoded length, not character count.

No wildcards, regular expressions, free-form expressions, or embedded policy
language are supported.

## Run enforce mode

From the repository root, after generating `policy.json`:

    uv run mcp-privprof enforce --policy policy.json --task-id task-001 --agent-id agent-1 --audit-log .mcp-privprof/events.jsonl --state-database .mcp-privprof/enforcement.sqlite3 --approval-control .mcp-privprof/approval-control.json --path-root PROJECT_ROOT=lab/fixtures --cwd . -- python -m lab.server

The command's standard input and output are the MCP transport. Diagnostics go
to standard error so they cannot corrupt JSON-RPC messages.

When a call returns `MCP_PRIVPROF_APPROVAL_REQUIRED`, approve it from a
separate local terminal:

    uv run mcp-privprof permit create --request REQUEST_ID --control .mcp-privprof/approval-control.json

Inspect the displayed task, policy, server, tool, digest, expiry, and exact
arguments. Confirm only if the whole call is intended, then let the agent retry
that exact call once.

## Stable denial data

Tool denials use `isError: true`, a stable text code, and matching structured
data. Constraint denials add only `constraint_kind` and `argument_name`; the
rejected value is never copied into the error.

| Reason code | Meaning |
|---|---|
| `MCP_PRIVPROF_POLICY_DENY` | Exact rule denies the observed tool |
| `MCP_PRIVPROF_UNKNOWN_TOOL` | Requested name is absent from the verified catalog |
| `MCP_PRIVPROF_APPROVAL_REQUIRED` | No exact live permit exists; includes request ID, digest, and expiry |
| `MCP_PRIVPROF_PERMIT_REPLAY` | A permit was already consumed |
| `MCP_PRIVPROF_PERMIT_ARGUMENT_MISMATCH` | Retry arguments differ from the approved canonical digest |
| `MCP_PRIVPROF_PERMIT_EXPIRED` | Permit expiry has passed |
| `MCP_PRIVPROF_PERMIT_CLOCK_SKEW` | Verification time is too far before issue time |
| `MCP_PRIVPROF_PERMIT_INVALID` | HMAC verification failed |
| `MCP_PRIVPROF_LIMIT_EXCEEDED` | Reviewed rate, task, or concurrency limit is exhausted |
| `MCP_PRIVPROF_LIMIT_STATE_UNAVAILABLE` | Persistent limit reservation failed |
| `MCP_PRIVPROF_AUDIT_WRITE_FAILED` | Mandatory event could not be durably written before forwarding |
| `MCP_PRIVPROF_AUDIT_UNAVAILABLE` | A previous mandatory audit failure closed the gate |
| `MCP_PRIVPROF_POLICY_TOOLSET_DRIFT` | Live catalog no longer matches the reviewed fingerprint |
| `MCP_PRIVPROF_CONSTRAINT_ARGUMENT_MISSING` | Reviewed argument is absent |
| `MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH` | Argument has the wrong exact type |
| `MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT` | Path does not remain within a bound root |
| `MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED` | URL scheme, normalized host, or port is outside policy |
| `MCP_PRIVPROF_CONSTRAINT_ENUM_NOT_ALLOWED` | Value is absent from the exact enum |
| `MCP_PRIVPROF_CONSTRAINT_MAX_UTF8_BYTES_EXCEEDED` | String exceeds its reviewed UTF-8 limit |
| `MCP_PRIVPROF_INPUT_SCHEMA_INVALID` | Allowed call does not satisfy the reviewed tool input schema |
| `MCP_PRIVPROF_DOWNSTREAM_TIMEOUT` | Allowed downstream call exceeded its finite timeout |
| `MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE` | Allowed downstream session failed |

## Live drift

`notifications/tools/list_changed` invalidates the enforcement gate
immediately. A background collection may reopen it only when the complete live
fingerprint is exactly the approved fingerprint. A changed catalog stays
closed until a new profile, review, and policy are completed.

## Current enforcement and detection boundary

Stage 8 produces local `event-v1` JSONL. Stage 9 now provides a pinned,
local-only Wazuh definition, read-only agent ingestion, custom rules, and
positive/near-miss fixtures without changing the pre-forward enforcement
decision. Static validation and all 22 real Wazuh 4.14.6 `wazuh-logtest` cases
pass. A bounded live proxy denial also passed agent-to-manager rule matching
and indexer ingestion under one exact trace ID.

Cross-process concurrency, remote approval, remote MCP transports, multi-server
aggregation, key recovery, and automatic log rotation remain outside the v0.1
single-process local-stdio boundary.
