from __future__ import annotations

import contextlib
import multiprocessing
import os
import socket
import tempfile
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


def _serve_child_broker(socket_path: str, ready, stop) -> None:
    server = UnixDomainBrokerServer(
        socket_path,
        peer_bindings={os.geteuid(): _binding(gid=os.getegid())},
        dispatcher=lambda _message, session: {
            "broker_pid": os.getpid(),
            "session_id": session.session_id,
        },
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ready.set()
    try:
        stop.wait(timeout=15)
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


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
    assert seen[0][1].channel_binding_digest != seen[1][1].channel_binding_digest
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
            client = UnixDomainBrokerClient(path, expected_server_uid=os.geteuid())
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
            client = UnixDomainBrokerClient(path, expected_server_uid=os.geteuid())
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
            connection.sendall(b'{"operation":"read","operation":"write"}\n')
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
            client = UnixDomainBrokerClient(path, expected_server_uid=os.geteuid())
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
            UnixDomainBrokerClient(path, expected_server_uid=os.geteuid() + 1).request(
                lambda session: {"operation": "read"}
            )
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

        result = UnixDomainBrokerClient(path, expected_server_uid=os.geteuid()).request(
            sign
        )
    finally:
        _stop_server(server, thread)

    assert result == {
        "operation_id": "uds-test-operation",
        "principal_id": "agent-17",
        "tenant_id": "tenant-a",
    }


@pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED is required"
)
def test_broker_runs_in_a_separate_process(tmp_path):
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    stop = context.Event()
    socket_path = str(tmp_path / "child-broker.sock")
    process = context.Process(
        target=_serve_child_broker,
        args=(socket_path, ready, stop),
    )
    process.start()
    try:
        assert ready.wait(timeout=10), "child broker did not become ready"
        result = UnixDomainBrokerClient(
            socket_path, expected_server_uid=os.geteuid()
        ).request(lambda session: {"operation": "read"})
        assert result["broker_pid"] == process.pid
        assert result["broker_pid"] != os.getpid()
        assert isinstance(result["session_id"], str)
    finally:
        stop.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
    assert process.exitcode == 0


@pytest.mark.skipif(
    not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or not hasattr(socket, "SO_PEERCRED"),
    reason="requires root and Linux SO_PEERCRED for a cross-UID broker test",
)
def test_unprivileged_worker_uses_broker_without_direct_file_access():
    import pwd

    try:
        worker_account = pwd.getpwnam("nobody")
    except KeyError:
        pytest.skip("the CI image has no nobody account")

    worker_uid = worker_account.pw_uid
    worker_gid = worker_account.pw_gid
    service_dir = tempfile.mkdtemp(prefix="paca-uds-uid-", dir="/tmp")
    os.chown(service_dir, 0, worker_gid)
    os.chmod(service_dir, 0o710)
    socket_path = os.path.join(service_dir, "broker.sock")
    protected_path = os.path.join(service_dir, "protected.txt")
    with open(protected_path, "wb") as protected_file:
        protected_file.write(b"broker-only")
    os.chmod(protected_path, 0o600)

    ready_read, ready_write = os.pipe()
    result_read, result_write = os.pipe()
    worker_pid = os.fork()
    if worker_pid == 0:
        os.close(ready_write)
        os.close(result_read)
        try:
            os.chdir("/tmp")
            os.setgroups([])
            os.setgid(worker_gid)
            os.setuid(worker_uid)
            if os.read(ready_read, 1) != b"1":
                os._exit(3)
            try:
                with open(protected_path, "rb"):
                    direct_access_blocked = False
            except PermissionError:
                direct_access_blocked = True
            response = UnixDomainBrokerClient(
                socket_path,
                expected_server_uid=0,
            ).request(lambda session: {"operation": "read"})
            marker = "blocked" if direct_access_blocked else "direct-access-allowed"
            payload = (
                f"{marker}:{response['principal_id']}:{response['content']}"
            ).encode("ascii")
            os.write(result_write, payload)
            os._exit(0)
        except BaseException:
            with contextlib.suppress(OSError):
                os.write(result_write, b"worker-error")
            os._exit(2)

    os.close(ready_read)
    os.close(result_write)
    server = None
    thread = None
    ready_signalled = False
    worker_reaped = False

    def broker_read(_message, session):
        with open(protected_path, "rb") as protected_file:
            content = protected_file.read().decode("ascii")
        return {"principal_id": session.principal_id, "content": content}

    try:
        server = UnixDomainBrokerServer(
            socket_path,
            peer_bindings={worker_uid: _binding(uid=worker_uid, gid=worker_gid)},
            dispatcher=broker_read,
            socket_mode=0o660,
            socket_gid=worker_gid,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.write(ready_write, b"1")
        os.close(ready_write)
        ready_signalled = True

        payload = os.read(result_read, 256)
        _finished_pid, worker_status = os.waitpid(worker_pid, 0)
        worker_reaped = True
        assert os.WIFEXITED(worker_status)
        assert os.WEXITSTATUS(worker_status) == 0, payload
        assert payload == b"blocked:agent-17:broker-only"
    finally:
        if not ready_signalled:
            with contextlib.suppress(OSError):
                os.write(ready_write, b"0")
            os.close(ready_write)
        if thread is not None and server is not None:
            _stop_server(server, thread)
        if not worker_reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(worker_pid, 15)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(worker_pid, 0)
        os.close(result_read)
        if os.path.lexists(socket_path):
            os.unlink(socket_path)
        os.unlink(protected_path)
        os.chmod(service_dir, 0o700)
        os.rmdir(service_dir)
