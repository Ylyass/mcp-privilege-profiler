# Architecture

## Current verified path

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

## Current behavior

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

Policy, catalog filtering, profiling, drift detection, limits, and audit events
are not active yet. They will be inserted between the upstream handlers and the
downstream session only after transparent transport is proven.
