# Threat model

## Scope

The first release wraps one local stdio MCP server with one proxy process.
Remote transports, server aggregation, and multi-tenant operation are out of
scope.

## Trust boundaries

Trusted:

- local operator;
- launch-time configuration;
- reviewed local policy;
- proxy process and storage directory;
- local permit secret;
- configured Wazuh deployment.

Untrusted:

- upstream host or agent;
- task instructions and retrieved content;
- downstream tool names, schemas, descriptions, and annotations;
- all tool arguments and results;
- identifiers included in MCP call metadata;
- changed downstream tool definitions.

## Security invariants

1. Default policy effect is DENY.
2. A learned observation cannot allow a call without human review.
3. In enforce mode, denied tools are not returned by tools/list.
4. Enforce mode rejects denied and unknown calls before forwarding.
5. Security-widening drift blocks enforcement until review.
6. Default audit events exclude raw arguments and tool results.
7. A required audit-write failure blocks forwarding.

## Non-goals

- proving a tool is unnecessary from observation;
- preventing every prompt injection;
- detecting every possible secret;
- protecting every MCP transport or server;
- replacing a full SIEM, authorization system, or sandbox.

