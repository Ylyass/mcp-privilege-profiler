# ADR 0001: One downstream stdio server per proxy process

Status: accepted  
Date: 2026-07-14

## Context

Combining multiple MCP servers creates server identity, tool-name collision,
catalog pagination, failure-isolation, and policy-attribution problems.

## Decision

Version 0.1 proxies exactly one local stdio MCP server per process. Users run
multiple wrapper processes when they use multiple downstream servers.

## Consequences

The security boundary and audit attribution are simple and testable. Server
aggregation is deferred until isolated-server behavior is proven.

