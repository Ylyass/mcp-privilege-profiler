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

The initial repository foundation is in progress. See the project plan for the
build sequence, protocol baseline, threat model, Wazuh design, test strategy,
and release gates.

## Planned commands

    mcp-privprof inventory
    mcp-privprof profile
    mcp-privprof review
    mcp-privprof enforce
    mcp-privprof permit create

These commands are not implemented yet.

## License

Apache-2.0. See LICENSE.

