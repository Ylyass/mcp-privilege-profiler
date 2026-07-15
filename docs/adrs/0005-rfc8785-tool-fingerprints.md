# ADR 0005: RFC 8785 complete-tool fingerprints

Status: accepted
Date: 2026-07-15

## Context

MCP Tool definitions are JSON objects. Ordinary serialization can produce
different bytes for the same parsed value when object keys arrive in a
different order. Hashing those bytes directly would create false drift.

Semantic equivalence between different JSON Schemas is much harder and cannot
be claimed safely by simple normalization.

## Decision

Serialize every complete known MCP Tool object with its SDK aliases, omit only
fields whose value is absent, canonicalize the resulting JSON value with RFC
8785 JCS, and compute SHA-256 over those canonical bytes.

The toolset fingerprint is computed from the sorted sequence of exact tool names
and tool fingerprints. Duplicate names are rejected.

## Consequences

Different object-key order for the same parsed JSON value produces the same
fingerprint. Catalog listing order also does not affect the toolset fingerprint.

Any changed JSON value is detectable. The project does not promise that two
different but semantically equivalent JSON Schemas have the same fingerprint.
Input-schema changes are conservatively classified as security widening.
