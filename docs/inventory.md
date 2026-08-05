# Inventory and drift

## Purpose

Inventory answers three questions before the project attempts to learn or
enforce a policy:

1. Which tools does this exact MCP server currently expose?
2. What complete definitions did the server provide?
3. What changed since the preceding stored observation?

Inventory does not call any exposed tool and does not prove that a tool is safe,
necessary, or unnecessary.

## Command

Run from the repository root after the locked environment is installed:

    uv run mcp-privprof inventory --server-id pagination-lab --database .mcp-privprof/inventory.sqlite3 --json-report inventory-report.json --markdown-report inventory-report.md -- python -m lab.paginated_server

Everything after `--` is passed directly as the downstream executable and
argument list. The project does not join these values into a shell command.

`--server-id` is trusted launch configuration. It is not read from downstream
tool metadata. Use a stable, unique value for each configured server.

The database and the two report paths must be different so a report cannot
overwrite durable history.

`--startup-timeout` bounds each MCP handshake request. In automatic negotiation,
the SDK may first probe the current protocol and then perform the legacy
initialization handshake, so the total connection time can include more than
one bounded request. `--catalog-timeout` separately bounds the entire paginated
tools/list collection, not each page. Timeouts must be positive and finite.

## Stored evidence

Inventory tables were introduced by SQLite migration 1. The current combined
database is schema version 3: migration 2 adds profiling and review tables, and
migration 3 adds reviewed policy constraints without changing or deleting
inventory history. Inventory storage
contains:

- one append-only row per complete catalog observation;
- the exact server ID, observation timestamp, tool count, and toolset fingerprint;
- one row per tool with its complete canonical JSON bytes and SHA-256 fingerprint;
- an explicit migration version.

Writes use a transaction. A partial toolset is rolled back. Databases from a
newer unsupported schema version are rejected rather than guessed at. On read,
the repository checks the stored tool count and verifies each canonical tool's
SHA-256 identity.

The storage directory is inside the trusted boundary and should remain local to
the operator.

## Reports

`inventory-report-v1.schema.json` defines the machine-readable JSON artifact.
It includes the complete known MCP Tool objects, snapshot identity, timestamps,
fingerprints, and the comparison with the immediately preceding observation.

The Markdown report is a concise human summary. Tool names and server text are
escaped because downstream catalog content is untrusted. Complete definitions
remain in JSON rather than being rendered as active Markdown or HTML.

## Drift classifications

| Change | Classification | Meaning in the current inventory stage |
|---|---|---|
| Tool added | Security widening | The server exposes a new capability; review it |
| Tool removed | Breaking | Existing tasks or future policies may no longer work |
| `inputSchema` changed | Security widening | v0.1 does not claim semantic schema equivalence |
| Title, description, or icons only | Informational | Presentation changed without an input-contract change |
| Other known field changed | Review required | The effect is not safe to infer automatically |

Stage 5 reports these facts. Stage 7 enforcement uses the stricter exact digest
gate: every changed complete Tool value blocks the reviewed policy until a new
profile and review approve it, regardless of the report classification.

## Live catalog changes

MCP servers can advertise and send `notifications/tools/list_changed`. The
monitor queues this signal without performing network work inside the SDK
message callback. A separate worker retrieves the complete current catalog.

The queue holds one pending signal. Bursts are intentionally coalesced because
the protocol notification is not a delta: every refresh asks for the entire
current catalog. A refresh failure propagates to the owning task group and is
not silently ignored.

The public inventory command is a one-shot scan. Profile and enforce modes both
use live monitoring to invalidate changed catalogs immediately. Enforce mode
can reopen the gate only when a complete refresh exactly matches the reviewed
fingerprint.
