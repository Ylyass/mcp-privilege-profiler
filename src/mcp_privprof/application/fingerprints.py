"""RFC 8785 canonicalization shared by versioned evidence artifacts."""

from __future__ import annotations

from hashlib import sha256

import rfc8785

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


def canonicalize_json(document: JsonValue) -> bytes:
    """Return RFC 8785 canonical bytes for a JSON-compatible value."""
    return rfc8785.dumps(document)


def fingerprint_json(document: JsonValue) -> tuple[bytes, str]:
    """Return canonical bytes and a prefixed SHA-256 digest."""
    canonical = canonicalize_json(document)
    return canonical, f"sha256:{sha256(canonical).hexdigest()}"
