"""In-memory pending approvals and durable single-use HMAC permits."""

from __future__ import annotations

import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import anyio
import rfc8785

from mcp_privprof.domain.permits import ApprovalPermit, sign_permit, verify_permit
from mcp_privprof.ports.permits import PermitRepository

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """Raw arguments retained only in live proxy memory for operator inspection."""

    request_id: str
    task_id: str
    policy_id: str
    server_id: str
    tool_name: str
    argument_digest: str
    arguments: dict[str, JsonValue]
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PermitCheck:
    """Permit consumption, pending request, or stable fail-closed reason."""

    allowed: bool
    reason_code: str
    permit_id: str | None = None
    pending: PendingApproval | None = None


class PermitService:
    """Own pending raw arguments and one live HMAC secret."""

    def __init__(
        self,
        repository: PermitRepository,
        *,
        secret: bytes,
        ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if len(secret) < 32:
            raise ValueError("permit secret must contain at least 256 bits")
        if not timedelta(seconds=1) <= ttl <= timedelta(hours=1):
            raise ValueError("permit TTL must be from 1 second to 1 hour")
        self._repository = repository
        self._secret = secret
        self._ttl = ttl
        self._pending_by_id: dict[str, PendingApproval] = {}
        self._pending_by_key: dict[tuple[str, str, str, str, str], str] = {}
        self._approved_by_key: dict[
            tuple[str, str, str, str, str],
            ApprovalPermit,
        ] = {}
        self._lock = anyio.Lock()

    async def initialize(self) -> None:
        await self._repository.initialize()

    async def authorize_or_request(
        self,
        *,
        task_id: str,
        policy_id: str,
        server_id: str,
        tool_name: str,
        arguments: dict[str, object],
        now: datetime,
    ) -> PermitCheck:
        """Consume an exact approved permit or create one pending request."""
        checked_at = _utc(now)
        canonical = rfc8785.dumps(cast(JsonValue, arguments))
        digest = _digest(canonical)
        key = (task_id, policy_id, server_id, tool_name, digest)
        async with self._lock:
            approved = self._approved_by_key.get(key)
            if approved is not None:
                reason = verify_permit(
                    approved,
                    secret=self._secret,
                    argument_digest=digest,
                    now=checked_at,
                )
                if reason is not None:
                    self._approved_by_key.pop(key, None)
                    self._drop_pending(approved.request_id)
                    return PermitCheck(allowed=False, reason_code=reason)
                consumed = await self._repository.consume_permit(
                    approved.permit_id,
                    consumed_at=checked_at,
                )
                self._approved_by_key.pop(key, None)
                self._drop_pending(approved.request_id)
                if not consumed:
                    return PermitCheck(
                        allowed=False,
                        reason_code="MCP_PRIVPROF_PERMIT_REPLAY",
                        permit_id=approved.permit_id,
                    )
                return PermitCheck(
                    allowed=True,
                    reason_code="MCP_PRIVPROF_PERMIT_CONSUMED",
                    permit_id=approved.permit_id,
                )

            existing_id = self._pending_by_key.get(key)
            if existing_id is not None:
                pending = self._pending_by_id[existing_id]
                if checked_at <= pending.expires_at:
                    return PermitCheck(
                        allowed=False,
                        reason_code="MCP_PRIVPROF_APPROVAL_REQUIRED",
                        pending=pending,
                    )
                self._drop_pending(existing_id)

            decoded = cast(dict[str, JsonValue], json.loads(canonical))
            pending = PendingApproval(
                request_id=f"approval-{uuid4().hex}",
                task_id=task_id,
                policy_id=policy_id,
                server_id=server_id,
                tool_name=tool_name,
                argument_digest=digest,
                arguments=decoded,
                created_at=checked_at,
                expires_at=checked_at + self._ttl,
            )
            self._pending_by_id[pending.request_id] = pending
            self._pending_by_key[key] = pending.request_id
            return PermitCheck(
                allowed=False,
                reason_code="MCP_PRIVPROF_APPROVAL_REQUIRED",
                pending=pending,
            )

    async def pending(self, request_id: str, *, now: datetime) -> PendingApproval:
        """Return exact live arguments for an authenticated local operator."""
        checked_at = _utc(now)
        async with self._lock:
            pending = self._pending_by_id.get(request_id)
            if pending is None:
                raise ValueError("approval request does not exist")
            if checked_at > pending.expires_at:
                self._drop_pending(request_id)
                raise ValueError("approval request expired")
            return pending

    async def approve(
        self,
        request_id: str,
        *,
        now: datetime,
        before_persist: Callable[[ApprovalPermit], Awaitable[None]] | None = None,
    ) -> ApprovalPermit:
        """Create and persist a signed one-use permit for one pending request."""
        issued_at = _utc(now)
        async with self._lock:
            pending = self._pending_by_id.get(request_id)
            if pending is None:
                raise ValueError("approval request does not exist")
            if issued_at > pending.expires_at:
                self._drop_pending(request_id)
                raise ValueError("approval request expired")
            permit_id = f"permit-{uuid4().hex}"
            nonce = secrets.token_hex(16)
            permit_mac = sign_permit(
                secret=self._secret,
                permit_id=permit_id,
                request_id=pending.request_id,
                task_id=pending.task_id,
                policy_id=pending.policy_id,
                server_id=pending.server_id,
                tool_name=pending.tool_name,
                argument_digest=pending.argument_digest,
                issued_at=issued_at,
                expires_at=pending.expires_at,
                nonce=nonce,
            )
            permit = ApprovalPermit(
                permit_id=permit_id,
                request_id=pending.request_id,
                task_id=pending.task_id,
                policy_id=pending.policy_id,
                server_id=pending.server_id,
                tool_name=pending.tool_name,
                argument_digest=pending.argument_digest,
                issued_at=issued_at,
                expires_at=pending.expires_at,
                nonce=nonce,
                permit_mac=permit_mac,
            )
            if before_persist is not None:
                await before_persist(permit)
            await self._repository.save_permit(permit)
            key = (
                pending.task_id,
                pending.policy_id,
                pending.server_id,
                pending.tool_name,
                pending.argument_digest,
            )
            self._approved_by_key[key] = permit
            return permit

    async def consume_exact(
        self,
        permit: ApprovalPermit,
        *,
        argument_digest: str,
        now: datetime,
    ) -> PermitCheck:
        """Verify and atomically consume an explicit permit for property tests."""
        checked_at = _utc(now)
        reason = verify_permit(
            permit,
            secret=self._secret,
            argument_digest=argument_digest,
            now=checked_at,
        )
        if reason is not None:
            return PermitCheck(allowed=False, reason_code=reason, permit_id=permit.permit_id)
        consumed = await self._repository.consume_permit(
            permit.permit_id,
            consumed_at=checked_at,
        )
        return PermitCheck(
            allowed=consumed,
            reason_code=(
                "MCP_PRIVPROF_PERMIT_CONSUMED" if consumed else "MCP_PRIVPROF_PERMIT_REPLAY"
            ),
            permit_id=permit.permit_id,
        )

    def _drop_pending(self, request_id: str) -> None:
        pending = self._pending_by_id.pop(request_id, None)
        if pending is not None:
            key = (
                pending.task_id,
                pending.policy_id,
                pending.server_id,
                pending.tool_name,
                pending.argument_digest,
            )
            self._pending_by_key.pop(key, None)


def generate_permit_secret() -> bytes:
    """Return a fresh 256-bit in-memory permit/control secret."""
    return secrets.token_bytes(32)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("permit time must include a timezone")
    return value.astimezone(UTC)


def _digest(canonical: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
