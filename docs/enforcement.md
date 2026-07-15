# Policy enforcement

Stage 7 turns a completed human review into a live least-privilege MCP
boundary. It does not train a model and it does not infer permission. The proxy
loads exact decisions already present in `policy-v1`, verifies the downstream
catalog, and decides every call before sending it to the downstream server.

## Data flow

    MCP host or agent
      -> tools/list or tools/call
    enforcement proxy
      -> exact catalog fingerprint gate
      -> exact server ID + tool name decision
      -> reviewed argument constraints
      -> downstream MCP server only if ALLOW

The proxy is an MCP server toward the host and an MCP client toward one local
stdio server. The downstream process is launched from an argument vector, not
through a shell.

## Startup gate

Before serving the upstream MCP connection, enforce mode:

1. reads at most 1 MiB from the policy file;
2. validates the strict `policy-v1` contract and converts it to domain objects;
3. resolves every trusted `ALIAS=DIRECTORY` path binding;
4. initializes the configured downstream server;
5. collects every `tools/list` page;
6. fingerprints every complete tool definition with RFC 8785 and SHA-256;
7. requires an exact match with `approved_toolset_fingerprint`; and
8. requires exactly one policy rule for every observed tool; and
9. requires every reviewed constraint argument to exist in that tool's
   top-level input-schema properties.

Malformed policies, missing path-root bindings, partial rule sets, unknown
rules, and stale fingerprints all prevent startup.

## Catalog and call behavior

`tools/list` returns one complete filtered page:

- `ALLOW` tools are visible;
- `REQUIRE_APPROVAL` tools are visible so a host can discover the capability;
- `DENY` tools are absent; and
- unlisted definitions are never exposed.

`tools/call` uses this order:

1. require a currently valid exact catalog;
2. reject a name absent from that catalog;
3. resolve the exact reviewed rule, with missing rules treated as `DENY`;
4. evaluate all reviewed constraints in memory;
5. return `APPROVAL_REQUIRED` without forwarding in Stage 7; and
6. require an `ALLOW` call to satisfy the exact reviewed tool input schema; and
7. forward only when every preceding check passes.

A denied call is not merely hidden. A client that manually sends its name is
still rejected before the downstream server receives a tool request.

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

    uv run mcp-privprof enforce --policy policy.json --path-root PROJECT_ROOT=lab/fixtures --cwd . -- python -m lab.server

The command's standard input and output are the MCP transport. Diagnostics go
to standard error so they cannot corrupt JSON-RPC messages.

## Stable denial data

Tool denials use `isError: true`, a stable text code, and matching structured
data. Constraint denials add only `constraint_kind` and `argument_name`; the
rejected value is never copied into the error.

| Reason code | Meaning |
|---|---|
| `MCP_PRIVPROF_POLICY_DENY` | Exact rule denies the observed tool |
| `MCP_PRIVPROF_UNKNOWN_TOOL` | Requested name is absent from the verified catalog |
| `MCP_PRIVPROF_APPROVAL_REQUIRED` | Rule requires a permit; Stage 7 never forwards it |
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

## Deliberate Stage 7 boundary

Stage 7 does not yet write mandatory audit JSONL, enforce call-rate/task/
concurrency limits, or consume approval permits. `REQUIRE_APPROVAL` therefore
fails closed. These capabilities are Stage 8 because audit-before-forward and
single-use permit state must be designed and tested as one atomic enforcement
pipeline.
