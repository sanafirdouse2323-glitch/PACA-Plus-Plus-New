from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.authority_runtime import (
    CapabilityAuthenticationError,
    Ed25519CapabilityAuthority,
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)
from paca.durable import SQLiteProvenanceRepository
from paca.memory import (
    HMACAgentMessageCodec,
    MemoryAccessDenied,
    PACAAgentRuntime,
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
    canonical_value_bytes,
)
from paca.resource_commit import (
    FencedResourceExecutor,
    ResourceCommitDenied,
    SQLiteFencedResourceExecutor,
)
from paca.filesystem_commit import FilesystemFencedResourceExecutor
from paca.secure_io import SecurePathUnavailable
from paca.runtime import Decision, Request, Tool


def _write_tool() -> Tool:
    return Tool(
        "write_file", "1.0", "Write a file to the workspace", ("path", "content")
    )


def _environment(
    tmp_path,
    *,
    max_calls=40,
    asymmetric=False,
    resource_path="/acme/reports/report.txt",
):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    callbacks = {
        "identity_verifier": lambda principal, tenant: bool(
            principal and tenant == "acme"
        ),
        "task_context_verifier": lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and task_id == "task-fence"
            and purpose == "write-report"
        ),
        "clock": clock,
    }
    verifier = None
    if asymmetric:
        private_seed = b"E" * 32
        private = Ed25519PrivateKey.from_private_bytes(private_seed)
        public_key = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        issuer = Ed25519CapabilityAuthority(
            registry,
            issuer_id="fenced-test-issuer",
            key_id="ed-fenced-test-key",
            audience="fenced-test-runtime",
            private_key=private_seed,
            **callbacks,
        )
        verifier = Ed25519CapabilityAuthority(
            registry,
            issuer_id="fenced-test-issuer",
            key_id="ed-fenced-test-key",
            audience="fenced-test-runtime",
            public_key=public_key,
            **callbacks,
        )
        resource_authority = verifier
    else:
        issuer = HMACCapabilityAuthority(
            registry,
            issuer_id="fenced-test-issuer",
            key_id="fenced-test-key",
            key=b"R" * 32,
            audience="fenced-test-runtime",
            **callbacks,
        )
        resource_authority = issuer
    tool = _write_tool()
    signed = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-fence",
        purpose="write-report",
        grants={
            "mem_read": ("mem/*",),
            "mem_write": ("mem/*",),
            "write_file": ("/acme/*",),
        },
        expires_at=2_000,
        max_calls=max_calls,
        max_fanout=2,
        tool_pins={"write_file": tool.hash},
    )
    repository = SQLiteProvenanceRepository(tmp_path / "lineage.sqlite3")
    values = SQLiteMemoryValueStore(tmp_path / "values.sqlite3")
    memory = TrustedMemoryAdapter(
        repository,
        values,
        issuer,
        authorize=lambda _context, _node: True,
        clock=clock,
    )
    messages = HMACAgentMessageCodec(
        b"S" * 32,
        issuer,
        repository,
        memory=memory,
        clock=clock,
    )
    connector = TrustedConnectorAdapter(
        memory,
        connector_id="fixture:trusted-input",
        source_class="tool_input",
        tenant="acme",
        sensitivity=1,
        integrity="untrusted",
    )
    path = connector.ingest(
        resource_path,
        object_id="mem/fence/path",
        version_id="v1",
        purpose="write-report",
        capability_token=signed.token,
    )
    content = connector.ingest(
        "approved report body",
        object_id="mem/fence/content",
        version_id="v1",
        purpose="write-report",
        capability_token=signed.token,
    )

    class AllowMonitor:
        def decide(self, request):
            return Decision("allow", digest=request.digest)

        def verify(self, request, decision):
            return decision.digest == request.digest

    runtime = PACAAgentRuntime(
        issuer,
        memory,
        AllowMonitor(),
        messages,
        require_resource_commit_fence=True,
        resource_commit_verifier=resource_authority,
    )
    request = Request(
        "write_file",
        {"path": path, "content": content},
        issuer.verify(signed.token).capability,
        1,
        tool=tool,
    )
    executor = SQLiteFencedResourceExecutor(resource_authority)
    return {
        "clock": clock,
        "verifier": verifier,
        "registry": registry,
        "issuer": issuer,
        "signed": signed,
        "repository": repository,
        "memory": memory,
        "runtime": runtime,
        "request": request,
        "executor": executor,
        "tool": tool,
    }


def _stored_resource(registry, *, resource="/acme/reports/report.txt"):
    with sqlite3.connect(registry.database) as connection:
        row = connection.execute(
            "SELECT value_json,payload_digest,version,authority_id,request_digest,commit_nonce "
            "FROM paca_resource_values WHERE tenant=? AND task_id=? AND resource_key=?",
            ("acme", "task-fence", resource),
        ).fetchone()
    return row


def test_resource_write_and_effect_budget_commit_in_one_authority_transaction(tmp_path):
    env = _environment(tmp_path)
    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        env["executor"],
    )

    assert decision.verdict == "allow"
    assert result["resource"] == "/acme/reports/report.txt"
    assert result["version"] == 1
    stored = _stored_resource(env["registry"])
    assert stored is not None
    assert json.loads(stored[0]) == {"content": "approved report body"}
    assert (
        stored[1]
        == hashlib.sha256(
            canonical_value_bytes({"content": "approved report body"})
        ).hexdigest()
    )
    assert stored[2] == 1
    assert stored[3] == env["signed"].capability.cap_id
    # Two source-argument reads and the actual effect commit were charged.
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 5
    assert env["registry"].task_usage("acme", "task-fence")[0] == 5


def test_strict_ed25519_runtime_rejects_non_public_only_or_mismatched_verifier(
    tmp_path,
):
    env = _environment(tmp_path, asymmetric=True)
    issuer = env["issuer"]
    verifier = env["verifier"]
    assert verifier is not None

    # A signer is not accepted as its own resource-side verifier in Ed25519 mode.
    with pytest.raises(ValueError, match="separate public-key-only"):
        PACAAgentRuntime(
            issuer,
            env["memory"],
            env["runtime"].monitor,
            env["runtime"].messages,
            require_resource_commit_fence=True,
            resource_commit_verifier=issuer,
        )

    # A verifier using another key ID must not be bound to the issuer's fence.
    mismatched_verifier = Ed25519CapabilityAuthority(
        env["registry"],
        issuer_id="fenced-test-issuer",
        key_id="different-key-id",
        audience="fenced-test-runtime",
        public_key=b"\x31" * 32,
        identity_verifier=lambda principal, tenant: bool(
            principal and tenant == "acme"
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and task_id == "task-fence"
            and purpose == "write-report"
        ),
        clock=env["clock"],
    )
    with pytest.raises(ValueError, match="must match the issuer identity"):
        PACAAgentRuntime(
            issuer,
            env["memory"],
            env["runtime"].monitor,
            env["runtime"].messages,
            require_resource_commit_fence=True,
            resource_commit_verifier=mismatched_verifier,
        )


def test_ed25519_private_issuer_and_public_only_resource_verifier_commit_write(
    tmp_path,
):
    env = _environment(tmp_path, asymmetric=True)
    verifier = env["verifier"]
    assert verifier is not None
    assert verifier._ed25519_signing_key is None

    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        env["executor"],
    )

    assert decision.verdict == "allow"
    assert result["resource"] == "/acme/reports/report.txt"
    assert result["version"] == 1
    stored = _stored_resource(env["registry"])
    assert stored is not None
    assert json.loads(stored[0]) == {"content": "approved report body"}

    with pytest.raises(CapabilityAuthenticationError, match="public-key-only verifier"):
        verifier.issue_resource_commit_permit(
            env["signed"].token,
            request_digest=env["request"].digest,
            action="write_file",
            resource="/acme/reports/report.txt",
            payload_digest=hashlib.sha256(
                canonical_value_bytes({"content": "approved report body"})
            ).hexdigest(),
        )


def test_strict_runtime_rejects_in_process_executor_before_any_budget_or_effect(
    tmp_path,
):
    env = _environment(tmp_path)
    executed = []
    with pytest.raises(MemoryAccessDenied, match="requires the runtime-bound"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            lambda request: executed.append(request) or "unsafe",
        )
    assert executed == []
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 2
    assert _stored_resource(env["registry"]) is None


def test_revocation_between_runtime_authorization_and_resource_commit_blocks_write(
    tmp_path,
):
    env = _environment(tmp_path)
    executor = env["executor"]
    original = executor.execute_authorized

    def revoke_before_commit(request, permit):
        env["registry"].revoke(
            env["signed"].capability.cap_id,
            "test revocation before resource commit",
        )
        return original(request, permit)

    executor.execute_authorized = revoke_before_commit
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    assert _stored_resource(env["registry"]) is None
    # Only the two source-read charges happened; the fenced effect was not charged.
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 4


def test_commit_permit_is_one_use_and_cannot_be_replayed(tmp_path, monkeypatch):
    env = _environment(tmp_path)
    issued = []
    original_issue = env["issuer"].issue_resource_commit_permit

    def capture_permit(*args, **kwargs):
        permit = original_issue(*args, **kwargs)
        issued.append(permit)
        return permit

    monkeypatch.setattr(env["issuer"], "issue_resource_commit_permit", capture_permit)
    env["runtime"].execute_effect(env["signed"].token, env["request"], env["executor"])
    usage_after_first_commit = env["registry"].usage(env["signed"].capability.cap_id)[0]
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["executor"].execute_authorized(env["request"], issued[0])

    stored = _stored_resource(env["registry"])
    assert stored is not None and stored[2] == 1
    assert (
        env["registry"].usage(env["signed"].capability.cap_id)[0]
        == usage_after_first_commit
    )


def test_resource_commit_rejects_modified_signed_permit(tmp_path):
    env = _environment(tmp_path)
    permit = env["issuer"].issue_resource_commit_permit(
        env["signed"].token,
        request_digest=env["request"].digest,
        action="write_file",
        resource="/acme/reports/report.txt",
        payload_digest=hashlib.sha256(
            canonical_value_bytes({"content": "approved report body"})
        ).hexdigest(),
    )
    parts = permit.split(".")
    signature = parts[-1]
    parts[-1] = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = ".".join(parts)
    with pytest.raises(ResourceCommitDenied, match="permit authentication"):
        env["executor"].execute_authorized(env["request"], tampered)
    assert _stored_resource(env["registry"]) is None


def test_revocation_waits_for_inflight_commit_and_linearizes_after_it(
    tmp_path, monkeypatch
):
    env = _environment(tmp_path)
    permit = env["issuer"].issue_resource_commit_permit(
        env["signed"].token,
        request_digest=env["request"].digest,
        action="write_file",
        resource="/acme/reports/report.txt",
        payload_digest=hashlib.sha256(
            canonical_value_bytes({"content": "approved report body"})
        ).hexdigest(),
    )
    registry = env["registry"]
    original_is_active = registry._is_active
    checked_active = threading.Event()
    release_commit = threading.Event()
    revoke_started = threading.Event()

    def pause_after_active_check(connection, authority_id):
        active = original_is_active(connection, authority_id)
        if authority_id == env["signed"].capability.cap_id:
            checked_active.set()
            if not release_commit.wait(timeout=10):
                raise RuntimeError("test did not release the commit transaction")
        return active

    monkeypatch.setattr(registry, "_is_active", pause_after_active_check)

    def commit():
        return env["executor"].execute_authorized(env["request"], permit)

    def revoke():
        revoke_started.set()
        return registry.revoke(
            env["signed"].capability.cap_id,
            "revocation serialized after an in-flight local resource commit",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit)
        assert checked_active.wait(timeout=10)
        revoke_future = pool.submit(revoke)
        assert revoke_started.wait(timeout=10)
        # The commit is holding BEGIN IMMEDIATE; revoke cannot overtake it.
        release_commit.set()
        committed = commit_future.result(timeout=10)
        revoked = revoke_future.result(timeout=10)

    assert committed["version"] == 1
    assert env["signed"].capability.cap_id in revoked
    assert not registry.is_active(env["signed"].capability.cap_id)
    assert _stored_resource(registry) is not None


def test_task_quota_exhaustion_prevents_resource_write_and_rolls_back_receipt(tmp_path):
    env = _environment(tmp_path, max_calls=4)
    # Two trusted ingress captures have already consumed two call units.
    # Both effect-argument reads can complete, but the commit transaction sees
    # an exhausted capability quota and cannot write.
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            env["executor"],
        )
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 4
    assert _stored_resource(env["registry"]) is None
    with sqlite3.connect(env["registry"].database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM paca_resource_commit_receipts"
        ).fetchone()[0]
    assert count == 0


def test_async_runtime_uses_the_same_resource_commit_fence(tmp_path):
    env = _environment(tmp_path)

    async def exercise():
        decision, result = await env["runtime"].aexecute_effect(
            env["signed"].token,
            env["request"],
            env["executor"],
        )
        assert decision.verdict == "allow"
        assert result["version"] == 1

    asyncio.run(exercise())
    stored = _stored_resource(env["registry"])
    assert stored is not None
    assert json.loads(stored[0]) == {"content": "approved report body"}
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 5


def test_sqlite_fenced_executor_name_remains_a_compatibility_alias():
    assert SQLiteFencedResourceExecutor is FencedResourceExecutor


def test_sqlite_authority_store_identity_is_stable_and_database_scoped(tmp_path):
    first = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3")
    second = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3")
    separate = SQLiteAuthorityRegistry(tmp_path / "separate-authority.sqlite3")

    assert first.authority_store_id == second.authority_store_id
    assert first.authority_store_id.startswith("sqlite:")
    assert first.authority_store_id != separate.authority_store_id


def _filesystem_executor(env, tmp_path, *, initial_content=None):
    root = tmp_path / "filesystem-root"
    target_parent = root / "acme" / "reports"
    target_parent.mkdir(parents=True)
    root.chmod(0o700)
    if initial_content is not None:
        (target_parent / "report.txt").write_bytes(initial_content)
    state_dir = tmp_path / "filesystem-state"
    try:
        executor = FilesystemFencedResourceExecutor(
            env["executor"].authority,
            root=root,
            state_dir=state_dir,
        )
    except SecurePathUnavailable as exc:
        pytest.skip(str(exc))
    return root, state_dir, executor


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_resource_commit_writes_real_file_under_authority_fence(tmp_path):
    env = _environment(tmp_path)
    root, state_dir, executor = _filesystem_executor(env, tmp_path)

    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        executor,
    )

    target = root / "acme" / "reports" / "report.txt"
    assert decision.verdict == "allow"
    assert target.read_bytes() == b"approved report body"
    assert result["storage"] == "filesystem"
    assert result["version"] == 1
    assert result["recovery_pending"] is False
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 5
    assert env["registry"].get_resource_commit_receipt(result["commit_nonce"]) is not None
    assert sorted(path.name for path in state_dir.iterdir()) == ["broker.lock"]
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_commit_replaces_existing_file_and_keeps_single_link_inode(tmp_path):
    env = _environment(tmp_path)
    root, _, executor = _filesystem_executor(
        env,
        tmp_path,
        initial_content=b"previous report",
    )

    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        executor,
    )

    target = root / "acme" / "reports" / "report.txt"
    metadata = target.stat()
    assert decision.verdict == "allow"
    assert target.read_bytes() == b"approved report body"
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o777 == 0o600
    assert result["version"] == 1
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_commit_rolls_back_file_when_database_transaction_fails_after_rename(
    tmp_path,
    monkeypatch,
):
    env = _environment(tmp_path)
    root, _, executor = _filesystem_executor(
        env,
        tmp_path,
        initial_content=b"previous report",
    )
    original = env["registry"].commit_fenced_filesystem_write

    def fail_after_destination_rename(permit, payload, *, commit_callback):
        commit_callback()
        raise RuntimeError("simulated process failure before database commit")

    monkeypatch.setattr(
        env["registry"],
        "commit_fenced_filesystem_write",
        fail_after_destination_rename,
    )

    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    target = root / "acme" / "reports" / "report.txt"
    assert target.read_bytes() == b"previous report"
    assert env["registry"].get_resource_commit_receipt(
        "no-such-permit"
    ) is None
    assert not list((tmp_path / "filesystem-state").glob("*.json"))
    monkeypatch.setattr(env["registry"], "commit_fenced_filesystem_write", original)
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_executor_recovers_committed_journal_after_cleanup_failure(
    tmp_path,
    monkeypatch,
):
    env = _environment(tmp_path)
    root, state_dir, executor = _filesystem_executor(env, tmp_path)

    def leave_journal_for_restart(*_args, **_kwargs):
        raise OSError("simulated crash after durable database commit")

    monkeypatch.setattr(executor, "_recover_one_locked", leave_journal_for_restart)
    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        executor,
    )
    target = root / "acme" / "reports" / "report.txt"
    assert decision.verdict == "allow"
    assert target.read_bytes() == b"approved report body"
    assert result["recovery_pending"] is True
    assert len(list(state_dir.glob("*.json"))) == 1
    executor.close()

    recovered = FilesystemFencedResourceExecutor(
        env["executor"].authority,
        root=root,
        state_dir=state_dir,
    )
    assert recovered.recover_pending() == {"committed": 0, "rolled_back": 0}
    assert target.read_bytes() == b"approved report body"
    assert sorted(path.name for path in state_dir.iterdir()) == ["broker.lock"]
    recovered.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_executor_restores_file_when_revocation_overtakes_commit(tmp_path):
    env = _environment(tmp_path)
    root, _, executor = _filesystem_executor(
        env,
        tmp_path,
        initial_content=b"previous report",
    )
    registry = env["registry"]
    original = registry.commit_fenced_filesystem_write

    def revoke_then_commit(permit, payload, *, commit_callback):
        registry.revoke(
            env["signed"].capability.cap_id,
            "revoked before filesystem destination commit",
        )
        return original(
            permit,
            payload,
            commit_callback=commit_callback,
        )

    registry.commit_fenced_filesystem_write = revoke_then_commit
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    target = root / "acme" / "reports" / "report.txt"
    assert target.read_bytes() == b"previous report"
    assert _stored_resource(registry) is None
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
@pytest.mark.parametrize(
    "resource_path",
    [
        "/acme/reports/../outside.txt",
        "/acme//reports/report.txt",
        "/other/reports/report.txt",
    ],
)
def test_filesystem_executor_rejects_traversal_or_cross_tenant_targets(
    tmp_path,
    resource_path,
):
    env = _environment(tmp_path, resource_path=resource_path)
    root, _, executor = _filesystem_executor(env, tmp_path)

    with pytest.raises(ResourceCommitDenied, match="normalized tenant path|tenant directory"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    assert not (tmp_path / "outside.txt").exists()
    assert _stored_resource(env["registry"]) is None
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_executor_rejects_symlink_target_without_touching_outside_file(tmp_path):
    resource_path = "/acme/reports/escape.txt"
    env = _environment(tmp_path, resource_path=resource_path)
    root = tmp_path / "filesystem-root"
    target_parent = root / "acme" / "reports"
    target_parent.mkdir(parents=True)
    outside = tmp_path / "outside-secret.txt"
    outside.write_bytes(b"outside secret")
    (target_parent / "escape.txt").symlink_to(outside)

    try:
        executor = FilesystemFencedResourceExecutor(
            env["executor"].authority,
            root=root,
            state_dir=tmp_path / "filesystem-state",
        )
    except SecurePathUnavailable as exc:
        pytest.skip(str(exc))

    with pytest.raises(ResourceCommitDenied, match="regular file"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    assert outside.read_bytes() == b"outside secret"
    assert _stored_resource(env["registry"]) is None
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_executor_rejects_hard_link_target(tmp_path):
    env = _environment(tmp_path)
    root = tmp_path / "filesystem-root"
    target_parent = root / "acme" / "reports"
    target_parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside content")
    os.link(outside, target_parent / "report.txt")
    try:
        executor = FilesystemFencedResourceExecutor(
            env["executor"].authority,
            root=root,
            state_dir=tmp_path / "filesystem-state",
        )
    except SecurePathUnavailable as exc:
        pytest.skip(str(exc))

    with pytest.raises(ResourceCommitDenied, match="single-link regular file"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    assert outside.read_bytes() == b"outside content"
    assert _stored_resource(env["registry"]) is None
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_commit_permit_replay_cannot_replace_file_twice(tmp_path, monkeypatch):
    env = _environment(tmp_path)
    root, _, executor = _filesystem_executor(env, tmp_path)
    issued = []
    original_issue = env["issuer"].issue_resource_commit_permit

    def capture_permit(*args, **kwargs):
        token = original_issue(*args, **kwargs)
        issued.append(token)
        return token

    monkeypatch.setattr(env["issuer"], "issue_resource_commit_permit", capture_permit)
    env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        executor,
    )
    first_content = (root / "acme" / "reports" / "report.txt").read_bytes()
    usage_after_first_commit = env["registry"].usage(
        env["signed"].capability.cap_id
    )[0]

    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        executor.execute_authorized(env["request"], issued[0])

    assert (root / "acme" / "reports" / "report.txt").read_bytes() == first_content
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == usage_after_first_commit
    executor.close()


@pytest.mark.skipif(sys.platform != "linux", reason="filesystem commit fence requires Linux openat2")
def test_filesystem_commit_holds_authority_transaction_until_destination_rename_finishes(
    tmp_path,
):
    env = _environment(tmp_path)
    root, _, executor = _filesystem_executor(env, tmp_path)
    registry = env["registry"]
    original = registry.commit_fenced_filesystem_write
    destination_renamed = threading.Event()
    allow_database_commit = threading.Event()
    revoke_started = threading.Event()

    def pause_after_rename(permit, payload, *, commit_callback):
        def rename_then_pause():
            commit_callback()
            destination_renamed.set()
            if not allow_database_commit.wait(timeout=10):
                raise RuntimeError("test did not release filesystem commit")

        return original(
            permit,
            payload,
            commit_callback=rename_then_pause,
        )

    registry.commit_fenced_filesystem_write = pause_after_rename

    def commit():
        return env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    def revoke():
        revoke_started.set()
        return registry.revoke(
            env["signed"].capability.cap_id,
            "filesystem commit serializes before revocation",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit)
        assert destination_renamed.wait(timeout=10)
        revoke_future = pool.submit(revoke)
        assert revoke_started.wait(timeout=10)
        allow_database_commit.set()
        decision, result = commit_future.result(timeout=10)
        revoked = revoke_future.result(timeout=10)

    target = root / "acme" / "reports" / "report.txt"
    assert decision.verdict == "allow"
    assert result["storage"] == "filesystem"
    assert target.read_bytes() == b"approved report body"
    assert env["signed"].capability.cap_id in revoked
    assert not registry.is_active(env["signed"].capability.cap_id)
    executor.close()


def test_filesystem_executor_configuration_rejects_public_state_directory(tmp_path):
    env = _environment(tmp_path)
    root = tmp_path / "filesystem-root"
    (root / "acme" / "reports").mkdir(parents=True)
    state_dir = tmp_path / "public-state"
    state_dir.mkdir(mode=0o755)
    state_dir.chmod(0o755)

    with pytest.raises(ResourceCommitDenied, match="private broker-owned"):
        FilesystemFencedResourceExecutor(
            env["executor"].authority,
            root=root,
            state_dir=state_dir,
        )
