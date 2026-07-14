# Technology baseline

Validated on 2026-07-14. Versions are locked with uv before the first runnable
milestone and changed only through a tested update.

| Component | Baseline | Decision |
|---|---:|---|
| Python | 3.13.14 development; 3.14.6 CI | Supported mature baseline plus compatibility coverage |
| MCP specification | 2025-11-25 | Current stable protocol revision |
| MCP Python SDK | >=1.28.1,<2 | Stable v1 line only |
| Wazuh Docker | 4.14.6 | Current stable baseline |
| JSON canonicalization | RFC 8785 | Deterministic complete-tool fingerprints |
| Storage | SQLite plus JSONL | Local state and privacy-minimized security events |

The MCP v2 prerelease is deliberately excluded from this project environment.
Any later experiment uses a separate subproject and separate lockfile.

Primary references:

- https://modelcontextprotocol.io/specification/2025-11-25/basic
- https://github.com/modelcontextprotocol/python-sdk
- https://documentation.wazuh.com/current/release-notes/index.html
- https://www.rfc-editor.org/rfc/rfc8785.html

