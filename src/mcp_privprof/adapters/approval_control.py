"""Authenticated loopback control channel for human approval."""

from __future__ import annotations

import hmac
import json
import os
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import anyio
from anyio.abc import SocketAttribute, SocketStream
from anyio.streams.buffered import BufferedByteReceiveStream
from anyio.streams.stapled import MultiListener
from anyio.to_thread import run_sync as run_sync_in_worker_thread

from mcp_privprof.application.permits import PendingApproval, PermitService
from mcp_privprof.domain.permits import ApprovalPermit

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

MAX_CONTROL_FILE_BYTES = 4096
MAX_CONTROL_REQUEST_BYTES = 16_384
MAX_CONTROL_RESPONSE_BYTES = 1_048_576


class ApprovalControlServer:
    """Expose pending arguments only through an authenticated local endpoint."""

    def __init__(
        self,
        *,
        control_path: Path,
        secret: bytes,
        permits: PermitService,
        on_approved: Callable[[ApprovalPermit], Awaitable[None]],
    ) -> None:
        if not control_path.name:
            raise ValueError("approval control path must name a file")
        if len(secret) < 32:
            raise ValueError("approval control secret must contain at least 256 bits")
        self._control_path = control_path
        self._secret = secret
        self._permits = permits
        self._on_approved = on_approved
        self._listener: MultiListener[SocketStream] | None = None
        self._control_identity: tuple[int, int] | None = None
        self._closing = False

    async def initialize(self) -> None:
        """Bind exclusive loopback TCP and publish a restrictive capability file."""
        listener = await anyio.create_tcp_listener(
            local_host="127.0.0.1",
            local_port=0,
            family=socket.AddressFamily.AF_INET,
        )
        port = listener.extra(SocketAttribute.local_port)
        document: dict[str, JsonValue] = {
            "approval_control_version": 1,
            "host": "127.0.0.1",
            "port": port,
            "secret": self._secret.hex(),
        }
        control_bytes = (
            json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        try:
            control_identity = await run_sync_in_worker_thread(
                self._write_control_file,
                control_bytes,
            )
        except BaseException:
            with anyio.CancelScope(shield=True):
                await listener.aclose()
            raise
        self._listener = listener
        self._control_identity = control_identity

    async def serve(self) -> None:
        """Serve authenticated inspect and approve operations until cancelled."""
        if self._listener is None:
            raise RuntimeError("approval control server is not initialized")
        try:
            await self._listener.serve(self._handle)
        except* (anyio.BrokenResourceError, anyio.ClosedResourceError):
            if not self._closing:
                raise

    async def aclose(self) -> None:
        """Close the endpoint and remove only this server's capability file."""
        self._closing = True
        try:
            if self._listener is not None:
                await self._listener.aclose()
        finally:
            self._listener = None
            if self._control_identity is not None:
                try:
                    await run_sync_in_worker_thread(
                        self._remove_control_file,
                        self._control_identity,
                    )
                finally:
                    self._control_identity = None

    async def _handle(self, stream: SocketStream) -> None:
        async with stream:
            try:
                buffered = BufferedByteReceiveStream(stream)
                raw = await buffered.receive_until(b"\n", MAX_CONTROL_REQUEST_BYTES)
                request = _request_document(raw)
                supplied_secret = request["secret"]
                if not isinstance(supplied_secret, str) or not hmac.compare_digest(
                    supplied_secret,
                    self._secret.hex(),
                ):
                    await _send(stream, {"ok": False, "error": "CONTROL_AUTHENTICATION_FAILED"})
                    return
                action = request["action"]
                request_id = request["request_id"]
                if not isinstance(action, str) or not isinstance(request_id, str):
                    raise ValueError("invalid control request fields")
                if action == "inspect":
                    pending = await self._permits.pending(request_id, now=datetime.now(UTC))
                    await _send(stream, {"ok": True, "request": _pending_document(pending)})
                    return
                if action == "approve":
                    permit = await self._permits.approve(
                        request_id,
                        now=datetime.now(UTC),
                        before_persist=self._on_approved,
                    )
                    await _send(
                        stream,
                        {
                            "ok": True,
                            "permit": {
                                "permit_id": permit.permit_id,
                                "request_id": permit.request_id,
                                "expires_at": _timestamp(permit.expires_at),
                            },
                        },
                    )
                    return
                raise ValueError("unsupported control action")
            except Exception as exc:
                await _send(
                    stream,
                    {"ok": False, "error": f"CONTROL_REQUEST_FAILED:{type(exc).__name__}"},
                )

    def _write_control_file(self, content: bytes) -> tuple[int, int]:
        self._control_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self._control_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        identity: tuple[int, int] | None = None
        try:
            status = os.fstat(descriptor)
            identity = (status.st_dev, status.st_ino)
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("approval control write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            if identity is not None:
                self._remove_control_file(identity)
            raise
        else:
            os.close(descriptor)
            assert identity is not None
            return identity

    def _remove_control_file(self, expected_identity: tuple[int, int]) -> None:
        try:
            status = os.lstat(self._control_path)
            if (status.st_dev, status.st_ino) == expected_identity:
                self._control_path.unlink()
        except FileNotFoundError:
            pass


async def inspect_approval(control_path: Path, request_id: str) -> dict[str, JsonValue]:
    """Retrieve one pending request through its live authenticated endpoint."""
    return await _control_request(control_path, "inspect", request_id)


async def approve_request(control_path: Path, request_id: str) -> dict[str, JsonValue]:
    """Approve one already inspected request through the local endpoint."""
    return await _control_request(control_path, "approve", request_id)


async def _control_request(
    control_path: Path,
    action: str,
    request_id: str,
) -> dict[str, JsonValue]:
    control = _read_control_file(control_path)
    host = control["host"]
    port = control["port"]
    secret = control["secret"]
    if (
        not isinstance(host, str)
        or host != "127.0.0.1"
        or type(port) is not int
        or not isinstance(secret, str)
    ):
        raise ValueError("approval control file contains invalid endpoint data")
    stream = await anyio.connect_tcp(host, port)
    async with stream:
        await _send(
            stream,
            {
                "action": action,
                "request_id": request_id,
                "secret": secret,
                "version": 1,
            },
        )
        buffered = BufferedByteReceiveStream(stream)
        raw = await buffered.receive_until(b"\n", MAX_CONTROL_RESPONSE_BYTES)
    response = _json_object(raw)
    if response.get("ok") is not True:
        raise RuntimeError(str(response.get("error", "CONTROL_REQUEST_FAILED")))
    return response


def _read_control_file(path: Path) -> dict[str, JsonValue]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("approval control path must be a regular non-symlink file")
    with path.open("rb") as source:
        content = source.read(MAX_CONTROL_FILE_BYTES + 1)
    if len(content) > MAX_CONTROL_FILE_BYTES:
        raise ValueError("approval control file exceeds its size limit")
    document = _json_object(content)
    if set(document) != {"approval_control_version", "host", "port", "secret"}:
        raise ValueError("approval control file contains missing or unknown fields")
    if document["approval_control_version"] != 1:
        raise ValueError("unsupported approval control version")
    return document


def _request_document(payload: bytes) -> dict[str, JsonValue]:
    document = _json_object(payload)
    if set(document) != {"action", "request_id", "secret", "version"}:
        raise ValueError("control request contains missing or unknown fields")
    if document["version"] != 1:
        raise ValueError("unsupported control request version")
    return document


def _json_object(payload: bytes) -> dict[str, JsonValue]:
    try:
        document = cast(JsonValue, json.loads(payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("control JSON is invalid") from exc
    if not isinstance(document, dict):
        raise ValueError("control JSON must be an object")
    return document


def _pending_document(pending: PendingApproval) -> dict[str, JsonValue]:
    return {
        "request_id": pending.request_id,
        "task_id": pending.task_id,
        "policy_id": pending.policy_id,
        "server_id": pending.server_id,
        "tool_name": pending.tool_name,
        "argument_digest": pending.argument_digest,
        "arguments": pending.arguments,
        "created_at": _timestamp(pending.created_at),
        "expires_at": _timestamp(pending.expires_at),
    }


async def _send(stream: SocketStream, document: dict[str, JsonValue]) -> None:
    payload = (json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    await stream.send(payload)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
