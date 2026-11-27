from __future__ import annotations

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.contracts import (
    BrokerOperationVerifier,
    MessageSigner,
    MessageVerifier,
    TrustedMessageKey,
)
from paca.contracts.broker import BrokerSessionContext
from paca.unix_broker import (
    BrokerMediatorDispatcher,
    BrokerTransportError,
    PeerBinding,
    UnixDomainBrokerClient,
    UnixDomainBrokerServer,
)


def _binding(*, uid: int | None = None, gid: int | None = None) -> PeerBinding:
    return PeerBinding(
        uid=os.geteuid() if uid is None else uid,
        gid=gid,
        issuer="worker-issuer",
        key_id="worker-key",
        audience="local-broker",
        principal_id="agent-17",
        workload_id="worker-17",
        tenant_id="tenant-a",
        task_id="task-17",
        purpose="research-test",
        principal_kind="agent",
    )


def _start_server(tmp_path, dispatcher, *, binding=None):
    path = str(tmp_path / "broker.sock")
    configured = _binding(gid=os.getegid()) if binding is None else binding
    server = UnixDomainBrokerServer(
        path,
        peer_bindings={configured.uid: configured},
        dispatcher=dispatcher,
        socket_mode=0o600,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return path, server, thread


def _stop_server(server, thread) -> None:
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()
    assert not thread.is_alive()


def test_one_shot_session_is_kernel_bound_and_unique_per_connection(tmp_path):
    seen: list[tuple[dict[str, object], BrokerSessionContext]] = []

    def dispatch(message, session):
        seen.append((dict(message), session))
        return {"operation_id": message["operation_id"]}

    path, server, thread = _start_server(tmp_path, dispatch)
    client = UnixDomainBrokerClient(path, expected_server_uid=os.geteuid())
    try:
        first = client.request(
            lambda session: {
                "operation": "read",
                "operation_id": "request-1",
                "session_id": session.session_id,
                "channel_binding_digest": {
                    "algorithm": "sha-256",
                    "value": session.channel_binding_digest,
                },
            }
        )
        second = client.request(
            lambda session: {
                "operation": "read",
                "operation_id": "request-2",
                "session_id": session.session_id,
                "channel_binding_digest": {
                    "algorithm": "sha-256",
                    "value": session.channel_binding_digest,
                },
            }
        )
    finally:
        _stop_server(server, thread)

    assert first == {"operation_id": "request-1"}
    assert second == {"operation_id": "request-2"}
    assert len(seen) == 2
    assert seen[0][1].session_id != seen[1][1].session_id
    assert (
        seen[0][1].channel_binding_digest
        != seen[1][1].channel_binding_digest
    )
    assert seen[0][1].principal_id == "agent-17"
    assert seen[0][1].tenant_id == "tenant-a"


def test_unmapped_or_wrong_gid_peer_is_denied_before_dispatch(tmp_path):
    calls = []
    binding = _binding(gid=os.getegid() + 1)
    path, server, thread = _start_server(
        tmp_path,
        lambda message, session: calls.append(message) or {"ok": True},
        binding=binding,
    )
    try:
        with pytest.raises(BrokerTransportError, match="unauthorized_peer"):
            client = UnixDomainBrokerClient(
                path, expected_server_uid=os.geteuid()
            )
            client.request(lambda session: {"operation": "read"})
    finally:
        _stop_server(server, thread)
    assert calls == []


def test_dispatcher_errors_are_redacted(tmp_path):
    def dispatch(message, session):
        raise PermissionError("secret database path and credential material")

    path, server, thread = _start_server(tmp_path, dispatch)
    try:
        with pytest.raises(BrokerTransportError, match="denied"):
            client = UnixDomainBrokerClient(
                path, expected_server_uid=os.geteuid()
            )
            client.request(lambda session: {"operation": "read"})
    finally:
        _stop_server(server, thread)


def test_server_rejects_unsupported_operations_before_dispatch(tmp_path):
    calls = []
    path, server, thread = _start_server(
        tmp_path, lambda message, session: calls.append(message) or {"ok": True}
    )
    try:
        with pytest.raises(BrokerTransportError, match="unsupported_operation"):
            UnixDomainBrokerClient(path, expected_server_uid=os.geteuid()).request(
                lambda session: {"operation": "delete"}
            )
    finally:
        _stop_server(server, thread)
    assert calls == []


def test_duplicate_json_keys_are_rejected_before_dispatch(tmp_path):
    calls = []
    path, server, thread = _start_server(
        tmp_path, lambda message, session: calls.append(message) or {"ok": True}
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(path)
            reader = connection.makefile("rb")
            hello = reader.readline()
            assert b'"ok":true' in hello
            connection.sendall(
                b'{"operation":"read","operation":"write"}\n'
            )
            response = reader.readline()
            assert b'"ok":false' in response
    finally:
        _stop_server(server, thread)
    assert calls == []


def test_server_refuses_to_replace_existing_socket_path(tmp_path):
    path = tmp_path / "broker.sock"
    path.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        UnixDomainBrokerServer(
            str(path),
            peer_bindings={os.geteuid(): _binding(gid=os.getegid())},
            dispatcher=lambda message, session: {"ok": True},
        )
    assert path.read_text(encoding="utf-8") == "keep"


def test_world_writable_parent_directory_is_rejected(tmp_path):
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="world-writable"):
            UnixDomainBrokerServer(
                str(parent / "broker.sock"),
                peer_bindings={os.geteuid(): _binding(gid=os.getegid())},
                dispatcher=lambda message, session: {"ok": True},
            )
    finally:
        parent.chmod(0o700)


def test_broker_mediator_dispatcher_exposes_only_configured_local_read_write():
    class ReadMediator:
        def read(self, message, *, session):
            return {"read": message["operation_id"], "session": session.session_id}

    class WriteMediator:
        def write(self, message, *, session):
            return {"write": message["operation_id"], "session": session.session_id}

    session = _binding().session(
        pid=os.getpid(),
        uid=os.geteuid(),
        gid=os.getegid(),
    )
    dispatcher = BrokerMediatorDispatcher(
        read_mediator=ReadMediator(),
        write_mediator=WriteMediator(),
    )
    read_result = dispatcher({"operation": "read", "operation_id": "r"}, session)
    write_result = dispatcher({"operation": "write", "operation_id": "w"}, session)
    assert read_result["read"] == "r"
    assert write_result["write"] == "w"
    with pytest.raises(PermissionError):
        dispatcher({"operation": "send"}, session)


def test_transport_fails_closed_when_dispatch_result_exceeds_limit(tmp_path):
    path, server, thread = _start_server(
        tmp_path,
        lambda message, session: {"large": "x" * 2_000_000},
    )
    try:
        with pytest.raises(BrokerTransportError, match="broker_failure"):
            client = UnixDomainBrokerClient(
                path, expected_server_uid=os.geteuid()
            )
            client.request(lambda session: {"operation": "read"})
    finally:
        _stop_server(server, thread)


def test_concurrent_connections_receive_distinct_sessions_and_one_result_each(tmp_path):
    sessions: list[str] = []
    lock = threading.Lock()

    def dispatch(message, session):
        with lock:
            sessions.append(session.session_id)
        return {"operation_id": message["operation_id"]}

    path, server, thread = _start_server(tmp_path, dispatch)
    try:
        def send(index: int):
            client = UnixDomainBrokerClient(
                path, expected_server_uid=os.geteuid(), timeout=10.0
            )
            return client.request(
                lambda session: {
                    "operation": "read",
                    "operation_id": f"concurrent-{index}",
                    "session_id": session.session_id,
                    "channel_binding_digest": {
                        "algorithm": "sha-256",
                        "value": session.channel_binding_digest,
                    },
                }
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(send, range(24)))
    finally:
        _stop_server(server, thread)

    assert {item["operation_id"] for item in results} == {
        f"concurrent-{index}" for index in range(24)
    }
    assert len(sessions) == 24
    assert len(set(sessions)) == 24


def test_client_rejects_a_different_broker_uid_before_receiving_session(tmp_path):
    calls = []
    path, server, thread = _start_server(
        tmp_path, lambda message, session: calls.append(message) or {"ok": True}
    )
    try:
        with pytest.raises(BrokerTransportError, match="untrusted_broker_process"):
            UnixDomainBrokerClient(
                path, expected_server_uid=os.geteuid() + 1
            ).request(lambda session: {"operation": "read"})
    finally:
        _stop_server(server, thread)
    assert calls == []


def test_group_writable_parent_directory_is_rejected(tmp_path):
    parent = tmp_path / "group-writable"
    parent.mkdir()
    parent.chmod(0o770)
    try:
        with pytest.raises(ValueError, match="group/world-writable"):
            UnixDomainBrokerServer(
                str(parent / "broker.sock"),
                peer_bindings={os.geteuid(): _binding(gid=os.getegid())},
                dispatcher=lambda message, session: {"ok": True},
            )
    finally:
        parent.chmod(0o700)


def test_signed_operation_is_verified_against_the_kernel_bound_session(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id="worker-key",
        issuer="worker-issuer",
        audiences=frozenset({"local-broker"}),
        private_key=private_key,
    )
    message_verifier = MessageVerifier(
        {
            "worker-key": TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer="worker-issuer",
                audiences=frozenset({"local-broker"}),
                message_types=frozenset({"paca.broker-operation.v1"}),
            )
        }
    )
    operation_verifier = BrokerOperationVerifier(message_verifier)

    def dispatch(message, session):
        verified = operation_verifier.verify(
            message,
            session=session,
            expected_grant_ref="grant-transport-test",
        )
        return {
            "operation_id": verified.operation_id,
            "principal_id": verified.principal_id,
            "tenant_id": verified.tenant_id,
        }

    path, server, thread = _start_server(tmp_path, dispatch)
    try:
        def sign(session):
            unsigned = {
                "message_id": "uds-test-message",
                "message_type": "paca.broker-operation.v1",
                "contract_version": "1.0.0",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "issuer": session.issuer,
                "audience": session.audience,
                "operation_id": "uds-test-operation",
                "session_id": session.session_id,
                "channel_binding_digest": {
                    "algorithm": "sha-256",
                    "value": session.channel_binding_digest,
                },
                "request_nonce": "uds-test-nonce-0123456789",
                "operation": "read",
                "resource": {
                    "resource_type": "file",
                    "resource_id": "reports/allowed.txt",
                },
                "read_constraints": {"max_bytes": 4096},
                "authorization_grant_ref": "grant-transport-test",
            }
            return signer.sign(unsigned)

        result = UnixDomainBrokerClient(
            path, expected_server_uid=os.geteuid()
        ).request(sign)
    finally:
        _stop_server(server, thread)

    assert result == {
        "operation_id": "uds-test-operation",
        "principal_id": "agent-17",
        "tenant_id": "tenant-a",
    }
