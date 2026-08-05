# Technology baseline

Validated on 2026-07-14 and rechecked against primary sources on 2026-08-05.
Versions are locked with uv and changed only through a tested update.

| Component | Baseline | Decision |
|---|---:|---|
| Python | 3.13.14 development; 3.14.6 CI | Supported mature baseline plus compatibility coverage |
| MCP specification | 2026-07-28 current; legacy fallback | Current stdio lifecycle with older-server interoperability |
| MCP Python SDK | 2.0.0 locked; `>=2,<3` declared | Current stable major after a complete tested migration |
| uv | 0.11.28 local; 0.11.31 CI | Locked workflow; CI uses one reviewed pin |
| Wazuh Docker | 4.14.6 | Current stable 4.x baseline |
| JSON canonicalization | RFC 8785 | Deterministic complete-tool fingerprints |
| Storage | SQLite plus JSONL | Local state and privacy-minimized security events |

MCP Python SDK 2.0.0 became the stable major line on 2026-07-28. The project
subsequently migrated the proxy, deterministic lab, and full automated test
matrix from SDK 1.28.1. The downstream SDK client uses automatic negotiation:
`server/discover` selects the 2026-07-28 lifecycle for a current peer, while an
older peer can fall back to the initialize lifecycle. A dedicated integration
test proves a 2026-07-28 client-to-proxy-to-server stdio path.

The SDK response cache is disabled. The proxy recollects and fingerprints the
complete live catalog before every upstream list or call. This is required
because the 2026-07-28 protocol delivers catalog changes through subscription
streams instead of the legacy standalone list-change notification. Notification
handling remains an early signal on legacy sessions, not the only security gate.

The SDK migration invalidated release claims based only on older runtime
evidence. The automated suite has been rerun on SDK 2.0.0; the real-Claude
acceptance, live Wazuh ingestion, and exact release benchmark must also be
repeated before a release candidate.

Primary references:

- https://github.com/modelcontextprotocol/python-sdk
- https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md
- https://modelcontextprotocol.io/specification/2026-07-28
- https://documentation.wazuh.com/current/release-notes/index.html
- https://docs.astral.sh/uv/concepts/projects/sync/
- https://www.rfc-editor.org/rfc/rfc8785.html
