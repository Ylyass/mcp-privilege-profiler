# ADR 0002: Stable MCP SDK v1 only for version 0.1

Status: accepted  
Date: 2026-07-14

## Context

The current Python MCP SDK v1 line is stable while v2 is prerelease. A single
environment cannot satisfy both a dependency constrained below v2 and a v2
prerelease pin.

## Decision

Version 0.1 constrains mcp to >=1.28.1,<2 and implements protocol behavior
against the 2025-11-25 stable specification.

## Consequences

The release is reproducible and avoids prerelease API churn. Any v2 work is a
separate post-release subproject with its own pyproject.toml and lockfile.

