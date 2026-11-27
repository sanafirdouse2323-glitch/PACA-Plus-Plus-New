"""One-shot Linux Unix-domain-socket transport for a separate PACA broker process.

The kernel authenticates the connecting process credentials (SO_PEERCRED). A
configured UID/GID binding supplies the worker identity; the existing broker
mediators still verify the Ed25519-signed operation and consume its replay
receipt. Each connection receives a fresh session/channel binding and may send
exactly one operation.

This module is a narrow local IPC boundary, not a universal host sandbox. It
protects only operations explicitly routed through this socket. Deploy workers
under dedicated OS identities, keep resource credentials in the broker process,
and restrict workers' filesystem/network access independently.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import secrets
import socket
import socketserver
import stat
import struct
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .contracts.broker import BrokerSessionContext

_SESSION_DOMAIN = b"PACA++/UNIX-BROKER-SESSION/V1\n"
_ALLOWED_OPERATIONS = frozenset({"read", "write"})
_DEFAULT_FRAME_LIMIT = 1_048_576


class BrokerTransportError(RuntimeError):
    """A local broker transport or session exchange failed."""


@dataclass(frozen=True)
class PeerBinding:
    """Identity allowed for one dedicated worker UID and optional primary GID."""

    uid: int
    issuer: str
    key_id: str
    audience: str
    principal_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    purpose: str
    gid: int | None = None
    principal_kind: str = "agent"

    def __post_init__(self) -> None:
        for name in ("uid",):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.gid is not None and (
            isinstance(self.gid, bool) or not isinstance(self.gid, int) or self.gid < 0
        ):
            raise ValueError("gid must be a non-negative integer or None")
        for name in (
            "issuer",
            "key_id",
            "audience",
            "principal_id",
            "workload_id",
            "tenant_id",
            "task_id",
            "purpose",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if self.principal_kind not in {
            "human",
            "agent",
            "service",
            "workload",
            "provider",
        }:
            raise ValueError("principal_kind is not a supported subject kind")

    def session(self, *, pid: int, uid: int, gid: int) -> BrokerSessionContext:
        """Create a server-side session from kernel peer credentials."""
        session_id = secrets.token_urlsafe(32)
        challenge = secrets.token_bytes(32)
        binding = hashlib.sha256(
            _SESSION_DOMAIN
            + struct.pack("!III", pid, uid, gid)
            + session_id.encode("ascii")
            + challenge
        ).hexdigest()
        return BrokerSessionContext(
            session_id=session_id,
            issuer=self.issuer,
            key_id=self.key_id,
            audience=self.audience,
            channel_binding_digest=binding,
            principal_id=self.principal_id,
            workload_id=self.workload_id,
            tenant_id=self.tenant_id,
            task_id=self.task_id,
            purpose=self.purpose,
            principal_kind=self.principal_kind,
        )


Dispatcher = Callable[
    [Mapping[str, Any], BrokerSessionContext], Mapping[str, object]
]


class BrokerMediatorDispatcher:
    """Expose only the existing local-file read and write mediators."""

    def __init__(
        self, *, read_mediator: Any = None, write_mediator: Any = None
    ) -> None:
        if read_mediator is None and write_mediator is None:
            raise ValueError("at least one broker mediator must be configured")
        if read_mediator is not None and not callable(
            getattr(read_mediator, "read", None)
        ):
            raise TypeError("read_mediator must expose read(message, session=...)")
        if write_mediator is not None and not callable(
            getattr(write_mediator, "write", None)
        ):
            raise TypeError("write_mediator must expose write(message, session=...)")
        self._read = read_mediator
        self._write = write_mediator

    def __call__(
        self, message: Mapping[str, Any], session: BrokerSessionContext
    ) -> Mapping[str, object]:
        operation = message.get("operation")
        if operation == "read" and self._read is not None:
            return self._read.read(message, session=session)
        if operation == "write" and self._write is not None:
            return self._write.write(message, session=session)
        raise PermissionError("operation is outside the configured broker profile")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _decode_object(frame: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            frame.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BrokerTransportError("invalid_json") from exc
    if not isinstance(value, dict):
        raise BrokerTransportError("request_must_be_object")
    return value


def _encode_frame(value: Mapping[str, Any], max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BrokerTransportError("response_not_json") from exc
    if len(encoded) > max_bytes:
        raise BrokerTransportError("frame_too_large")
    return encoded + b"\n"


def _session_wire(session: BrokerSessionContext) -> dict[str, str]:
    return {
        "session_id": session.session_id,
        "issuer": session.issuer,
        "key_id": session.key_id,
        "audience": session.audience,
        "channel_binding_digest": session.channel_binding_digest,
        "principal_id": session.principal_id,
        "workload_id": session.workload_id,
        "tenant_id": session.tenant_id,
        "task_id": session.task_id,
        "purpose": session.purpose,
        "principal_kind": session.principal_kind,
    }


def _session_from_wire(value: Any) -> BrokerSessionContext:
    if not isinstance(value, dict):
        raise BrokerTransportError("invalid_session")
    try:
        return BrokerSessionContext(**value)
    except (TypeError, ValueError) as exc:
        raise BrokerTransportError("invalid_session") from exc


class _BoundedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        socket_path: str,
        handler: type[socketserver.BaseRequestHandler],
        *,
        bindings: Mapping[int, PeerBinding],
        dispatcher: Dispatcher,
        max_request_bytes: int,
        max_response_bytes: int,
        client_timeout: float,
        max_workers: int,
    ) -> None:
        self.peer_bindings = dict(bindings)
        self.dispatcher = dispatcher
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.client_timeout = client_timeout
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(socket_path, handler, bind_and_activate=True)

    def process_request(self, request, client_address) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class _BrokerRequestHandler(socketserver.StreamRequestHandler):
    server: _BoundedUnixServer

    def handle(self) -> None:
        self.connection.settimeout(self.server.client_timeout)
        session: BrokerSessionContext | None = None
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise BrokerTransportError("peer_credentials_unsupported")
            raw = self.connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            if len(raw) != struct.calcsize("3i"):
                raise BrokerTransportError("peer_credentials_unavailable")
            pid, uid, gid = struct.unpack("3i", raw)
            binding = self.server.peer_bindings.get(uid)
            if binding is None or (binding.gid is not None and binding.gid != gid):
                self._send({"ok": False, "error": "unauthorized_peer"})
                return
            session = binding.session(pid=pid, uid=uid, gid=gid)
            self._send({"ok": True, "session": _session_wire(session)})

            line = self.rfile.readline(self.server.max_request_bytes + 1)
            if (
                not line
                or len(line) > self.server.max_request_bytes
                or not line.endswith(b"\n")
            ):
                self._send({"ok": False, "error": "invalid_or_oversized_request"})
                return
            message = _decode_object(line[:-1])
            operation = message.get("operation")
            if operation not in _ALLOWED_OPERATIONS:
                self._send({"ok": False, "error": "unsupported_operation"})
                return

            result = self.server.dispatcher(message, session)
            if not isinstance(result, Mapping):
                raise BrokerTransportError("dispatcher_result_must_be_object")
            frame = _encode_frame(
                {"ok": True, "result": dict(result)},
                self.server.max_response_bytes,
            )
            self.wfile.write(frame)
            self.wfile.flush()
        except PermissionError:
            self._safe_send({"ok": False, "error": "denied"})
        except (BrokerTransportError, OSError, ValueError, TypeError):
            self._safe_send({"ok": False, "error": "broker_failure"})
        except Exception:
            # Do not return internal exception text, credentials or request data.
            self._safe_send({"ok": False, "error": "broker_failure"})

    def _send(self, value: Mapping[str, Any]) -> None:
        self.wfile.write(_encode_frame(value, self.server.max_response_bytes))
        self.wfile.flush()

    def _safe_send(self, value: Mapping[str, Any]) -> None:
        with contextlib.suppress(OSError, BrokerTransportError):
            self._send(value)


class UnixDomainBrokerServer:
    """Run a bounded one-request-per-connection broker on a Linux UDS.

    The socket parent directory must already exist, must not be a symlink, and
    must not be world-writable. Existing socket paths are never unlinked or
    replaced automatically. Only kernel-authenticated UIDs in peer_bindings
    are accepted. The private signing key stays with the worker; the broker
    verifies it through the configured mediator's trusted key ring.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        peer_bindings: Mapping[int, PeerBinding],
        dispatcher: Dispatcher,
        socket_mode: int = 0o600,
        socket_gid: int | None = None,
        max_request_bytes: int = _DEFAULT_FRAME_LIMIT,
        max_response_bytes: int = _DEFAULT_FRAME_LIMIT,
        client_timeout: float = 5.0,
        max_workers: int = 32,
    ) -> None:
        if not isinstance(socket_path, str) or not os.path.isabs(socket_path):
            raise ValueError("socket_path must be an absolute path")
        if len(os.fsencode(socket_path)) >= 104:
            raise ValueError("socket_path is too long for a Linux Unix socket")
        if not isinstance(peer_bindings, Mapping) or not peer_bindings:
            raise ValueError("peer_bindings must be a non-empty UID mapping")
        normalized: dict[int, PeerBinding] = {}
        for uid, binding in peer_bindings.items():
            if isinstance(uid, bool) or not isinstance(uid, int):
                raise ValueError("peer binding keys must be integer UIDs")
            if not isinstance(binding, PeerBinding) or binding.uid != uid:
                raise ValueError("each peer binding must match its UID key")
            normalized[uid] = binding
        if not callable(dispatcher):
            raise TypeError("dispatcher must be callable")
        if socket_mode not in {0o600, 0o660}:
            raise ValueError("socket_mode must be 0600 or 0660")
        if socket_gid is not None and (
            isinstance(socket_gid, bool)
            or not isinstance(socket_gid, int)
            or socket_gid < 0
        ):
            raise ValueError("socket_gid must be a non-negative integer or None")
        for name, value in (
            ("max_request_bytes", max_request_bytes),
            ("max_response_bytes", max_response_bytes),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1_024 <= value <= 16_777_216
            ):
                raise ValueError(f"{name} must be between 1 KiB and 16 MiB")
        if (
            isinstance(client_timeout, bool)
            or not isinstance(client_timeout, (int, float))
            or not math.isfinite(client_timeout)
            or not 0.1 <= client_timeout <= 30
        ):
            raise ValueError("client_timeout must be between 0.1 and 30 seconds")
        if (
            isinstance(max_workers, bool)
            or not isinstance(max_workers, int)
            or not 1 <= max_workers <= 128
        ):
            raise ValueError("max_workers must be between 1 and 128")

        parent = os.path.dirname(socket_path)
        parent_stat = os.lstat(parent)
        if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
            raise ValueError("socket parent must be an existing real directory")
        if parent_stat.st_mode & stat.S_IWOTH:
            raise ValueError("socket parent directory must not be world-writable")
        if os.path.lexists(socket_path):
            raise FileExistsError("refusing to replace an existing broker socket path")

        self.socket_path = socket_path
        self._socket_identity: tuple[int, int] | None = None
        self._closed = False
        server = _BoundedUnixServer(
            socket_path,
            _BrokerRequestHandler,
            bindings=normalized,
            dispatcher=dispatcher,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            client_timeout=float(client_timeout),
            max_workers=max_workers,
        )
        try:
            socket_stat = os.lstat(socket_path)
            if not stat.S_ISSOCK(socket_stat.st_mode):
                raise BrokerTransportError("bound_path_is_not_socket")
            self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)
            if socket_gid is not None:
                os.chown(socket_path, -1, socket_gid)
            os.chmod(socket_path, socket_mode)
        except Exception:
            server.server_close()
            try:
                current = os.lstat(socket_path)
                if self._socket_identity == (current.st_dev, current.st_ino):
                    os.unlink(socket_path)
            except FileNotFoundError:
                pass
            raise
        self._server = server

    def serve_forever(self, poll_interval: float = 0.25) -> None:
        """Block while serving requests. Call shutdown from another thread."""
        if self._closed:
            raise BrokerTransportError("server_closed")
        self._server.serve_forever(poll_interval=poll_interval)

    def shutdown(self) -> None:
        """Stop a running serve_forever loop; call from a different thread."""
        if not self._closed:
            self._server.shutdown()

    def server_close(self) -> None:
        """Close the listener and remove only the socket inode this instance bound."""
        if self._closed:
            return
        self._closed = True
        self._server.server_close()
        try:
            current = os.lstat(self.socket_path)
            if (
                self._socket_identity == (current.st_dev, current.st_ino)
                and stat.S_ISSOCK(current.st_mode)
            ):
                os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def __enter__(self) -> UnixDomainBrokerServer:
        if self._closed:
            raise BrokerTransportError("server_closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.server_close()


class UnixDomainBrokerClient:
    """One-shot client; sign receives the session issued on this connection."""

    def __init__(
        self,
        socket_path: str,
        *,
        timeout: float = 5.0,
        max_frame_bytes: int = _DEFAULT_FRAME_LIMIT,
    ) -> None:
        if not isinstance(socket_path, str) or not os.path.isabs(socket_path):
            raise ValueError("socket_path must be an absolute path")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0.1 <= timeout <= 30
        ):
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        if (
            isinstance(max_frame_bytes, bool)
            or not isinstance(max_frame_bytes, int)
            or not 1_024 <= max_frame_bytes <= 16_777_216
        ):
            raise ValueError("max_frame_bytes must be between 1 KiB and 16 MiB")
        self.socket_path = socket_path
        self.timeout = float(timeout)
        self.max_frame_bytes = max_frame_bytes

    def request(
        self,
        sign: Callable[[BrokerSessionContext], Mapping[str, Any]],
    ) -> Mapping[str, object]:
        """Obtain a fresh session, sign one request and return its broker result."""
        if not callable(sign):
            raise TypeError("sign must be a callable accepting BrokerSessionContext")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.socket_path)
                reader = connection.makefile("rb")
                hello = reader.readline(self.max_frame_bytes + 1)
                if not hello or len(hello) > self.max_frame_bytes or not hello.endswith(b"\n"):
                    raise BrokerTransportError("invalid_handshake")
                hello_object = _decode_object(hello[:-1])
                if hello_object.get("ok") is not True:
                    raise BrokerTransportError(
                        str(hello_object.get("error", "handshake_denied"))
                    )
                session = _session_from_wire(hello_object.get("session"))
                message = sign(session)
                if not isinstance(message, Mapping):
                    raise BrokerTransportError("signed_request_must_be_object")
                frame = _encode_frame(message, self.max_frame_bytes)
                connection.sendall(frame)
                response = reader.readline(self.max_frame_bytes + 1)
                if (
                    not response
                    or len(response) > self.max_frame_bytes
                    or not response.endswith(b"\n")
                ):
                    raise BrokerTransportError("invalid_response")
                response_object = _decode_object(response[:-1])
                if response_object.get("ok") is not True:
                    raise BrokerTransportError(
                        str(response_object.get("error", "broker_denied"))
                    )
                result = response_object.get("result")
                if not isinstance(result, Mapping):
                    raise BrokerTransportError("invalid_result")
                return dict(result)
        except BrokerTransportError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise BrokerTransportError("broker_connection_failed") from exc


__all__ = [
    "BrokerMediatorDispatcher",
    "BrokerTransportError",
    "PeerBinding",
    "UnixDomainBrokerClient",
    "UnixDomainBrokerServer",
]
