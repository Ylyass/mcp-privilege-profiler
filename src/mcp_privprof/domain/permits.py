"""Single-use HMAC approval permit facts and verification."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch


@dataclass(frozen=True, slots=True)
class ApprovalPermit:
    """One approved exact call digest, valid once within a short window."""

    permit_id: str
    request_id: str
    task_id: str
    policy_id: str
    server_id: str
    tool_name: str
    argument_digest: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    permit_mac: str

    def __post_init__(self) -> None:
        for label, value in (
            ("permit_id", self.permit_id),
            ("request_id", self.request_id),
            ("task_id", self.task_id),
            ("policy_id", self.policy_id),
            ("server_id", self.server_id),
            ("tool_name", self.tool_name),
        ):
            if not value:
                raise ValueError(f"{label} must not be empty")
        if fullmatch(r"sha256:[0-9a-f]{64}", self.argument_digest) is None:
            raise ValueError("argument_digest must be a lowercase SHA-256 fingerprint")
        if fullmatch(r"[0-9a-f]{32,}", self.nonce) is None:
            raise ValueError("permit nonce must be at least 128 random bits in hex")
        if fullmatch(r"[0-9a-f]{64}", self.permit_mac) is None:
            raise ValueError("permit_mac must be an HMAC-SHA256 hex digest")
        issued_at = _utc(self.issued_at, "issued_at")
        expires_at = _utc(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise ValueError("permit expiry must be after issue time")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)


def sign_permit(
    *,
    secret: bytes,
    permit_id: str,
    request_id: str,
    task_id: str,
    policy_id: str,
    server_id: str,
    tool_name: str,
    argument_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
) -> str:
    """Create HMAC-SHA256 over every security-relevant permit field."""
    if len(secret) < 32:
        raise ValueError("permit secret must contain at least 256 bits")
    message = _permit_message(
        permit_id=permit_id,
        request_id=request_id,
        task_id=task_id,
        policy_id=policy_id,
        server_id=server_id,
        tool_name=tool_name,
        argument_digest=argument_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_permit(
    permit: ApprovalPermit,
    *,
    secret: bytes,
    argument_digest: str,
    now: datetime,
    allowed_clock_skew: timedelta = timedelta(seconds=30),
) -> str | None:
    """Return a stable denial reason or verify exact, timely HMAC authorization."""
    checked_at = _utc(now, "now")
    if argument_digest != permit.argument_digest:
        return "MCP_PRIVPROF_PERMIT_ARGUMENT_MISMATCH"
    if checked_at + allowed_clock_skew < permit.issued_at:
        return "MCP_PRIVPROF_PERMIT_CLOCK_SKEW"
    if checked_at > permit.expires_at:
        return "MCP_PRIVPROF_PERMIT_EXPIRED"
    expected = sign_permit(
        secret=secret,
        permit_id=permit.permit_id,
        request_id=permit.request_id,
        task_id=permit.task_id,
        policy_id=permit.policy_id,
        server_id=permit.server_id,
        tool_name=permit.tool_name,
        argument_digest=permit.argument_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
        nonce=permit.nonce,
    )
    if not hmac.compare_digest(expected, permit.permit_mac):
        return "MCP_PRIVPROF_PERMIT_INVALID"
    return None


def _permit_message(
    *,
    permit_id: str,
    request_id: str,
    task_id: str,
    policy_id: str,
    server_id: str,
    tool_name: str,
    argument_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
) -> bytes:
    document = {
        "argument_digest": argument_digest,
        "expires_at": _timestamp(expires_at),
        "issued_at": _timestamp(issued_at),
        "nonce": nonce,
        "permit_id": permit_id,
        "policy_id": policy_id,
        "request_id": request_id,
        "server_id": server_id,
        "task_id": task_id,
        "tool_name": tool_name,
        "version": 1,
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value, "permit timestamp").isoformat(timespec="microseconds").replace("+00:00", "Z")
