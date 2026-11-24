from __future__ import annotations

import hashlib
import json

import pytest

from paca.agent_runtime import PACAAgentRuntime
from paca.memory import MemoryAccessDenied
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request, Tool
from paca.sandbox import (
    DockerSandbox,
    DockerSandboxExecutor,
    SandboxExecutionError,
    SandboxResult,
)

IMAGE = "ghcr.io/example/paca-worker@sha256:" + ("a" * 64)


def _sandbox(**kwargs):
    return DockerSandbox(IMAGE, **kwargs)


def test_tool_implementation_digest_is_validated_and_legacy_hashes_are_stable():
    legacy = Tool("read_file", "1.0", "Read a file", ("path",))
    legacy_payload = json.dumps(
        ["read_file", "1.0", "Read a file", ["path"]],
        sort_keys=True,
    )
    assert legacy.hash == hashlib.sha256(legacy_payload.encode("utf-8")).hexdigest()

    pinned = Tool(
        "read_file",
        "1.0",
        "Read a file",
        ("path",),
        implementation_digest="b" * 64,
    )
    assert pinned.hash != legacy.hash

    capability = Capability(
        cap_id="cap",
        principal="agent-a",
        tenant="acme",
        task_id="task-1",
        role="assistant",
        grants={"read_file": ("/workspace/*",)},
        expires=9999999999,
    )
    legacy_request = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt")},
        cap=capability,
        step=1,
        tool=legacy,
    )
    pinned_request = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt")},
        cap=capability,
        step=1,
        tool=pinned,
    )
    assert pinned_request.digest != legacy_request.digest

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        Tool(
            "read_file",
            "1.0",
            "Read a file",
            ("path",),
            implementation_digest="BAD",
        )


def test_docker_artifact_digest_binds_image_command_and_isolation_profile():
    command = ("/usr/local/bin/paca-worker", "--stdio")
    baseline = _sandbox()
    digest = baseline.implementation_digest(command)
    descriptor = baseline._implementation_descriptor(command)
    expected_invocation = list(baseline._build_command(command, "<PACA_CIDFILE>"))

    assert descriptor["docker_invocation"] == expected_invocation
    assert "--workdir=/tmp" in expected_invocation
    assert "--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" in expected_invocation
    assert digest == hashlib.sha256(
        json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    assert len(digest) == 64
    assert digest == baseline.implementation_digest(command)
    assert digest != baseline.implementation_digest(
        ("/usr/local/bin/paca-worker", "--different-mode")
    )
    assert digest != _sandbox(memory_bytes=268_435_456).implementation_digest(command)
    assert digest != DockerSandbox(
        IMAGE,
        platform="linux/arm64",
    ).implementation_digest(command)
    assert digest != DockerSandbox(
        IMAGE,
        docker_env={"DOCKER_HOST": "unix:///run/alternate-docker.sock"},
    ).implementation_digest(command)


def test_agent_runtime_tool_pin_includes_implementation_digest():
    pinned_tool = Tool(
        "read_file",
        "1.0",
        "Read a file",
        ("path",),
        implementation_digest="a" * 64,
    )
    changed_tool = Tool(
        "read_file",
        "1.0",
        "Read a file",
        ("path",),
        implementation_digest="b" * 64,
    )
    capability = Capability(
        cap_id="cap",
        principal="agent-a",
        tenant="acme",
        task_id="task-1",
        role="assistant",
        grants={"read_file": ("/workspace/*",)},
        expires=9999999999,
        tool_pins={pinned_tool.name: pinned_tool.hash},
    )
    args = {"path": Arg("/workspace/report.txt")}
    allowed = Request(
        "read_file",
        args,
        cap=capability,
        step=1,
        tool=pinned_tool,
    )
    denied = Request(
        "read_file",
        args,
        cap=capability,
        step=1,
        tool=changed_tool,
    )

    PACAAgentRuntime._assert_tool_binding(capability, allowed)
    with pytest.raises(MemoryAccessDenied, match="not pinned"):
        PACAAgentRuntime._assert_tool_binding(capability, denied)


def test_docker_sandbox_rejects_ambiguous_platform_values():
    with pytest.raises(ValueError, match="platform"):
        DockerSandbox(IMAGE, platform="amd64")
    with pytest.raises(ValueError, match="platform"):
        DockerSandbox(IMAGE, platform="linux/amd64;--privileged")


def test_docker_sandbox_requires_an_immutable_image_digest():
    with pytest.raises(ValueError, match="sha256 digest"):
        DockerSandbox("ghcr.io/example/paca-worker:latest")
    with pytest.raises(ValueError, match="sha256 digest"):
        DockerSandbox("ghcr.io/example/paca-worker@sha256:ABC")


def test_docker_command_enforces_no_network_no_mounts_and_resource_limits():
    sandbox = _sandbox(memory_bytes=268_435_456, cpu_limit=0.5, pids_limit=24)
    command = sandbox._build_command(
        ("/usr/local/bin/paca-worker", "--mode", "read;touch /tmp/pwned"),
        "/tmp/container-id",
    )
    args = list(command)
    assert "--platform=linux/amd64" in args
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args
    assert "--security-opt=seccomp=default" in args
    assert "--memory=268435456" in args
    assert "--memory-swap=268435456" in args
    assert "--cpus=0.500" in args
    assert "--pids-limit=24" in args
    assert "--user=65534:65534" in args
    assert "--ulimit=core=0:0" in args
    assert "--ipc=private" in args
    assert "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=33554432" in args
    assert "--entrypoint" in args
    assert command[-2:] == ("--mode", "read;touch /tmp/pwned")
    assert not any(
        part in {"--privileged", "--mount", "-v", "--volume", "--network=host"}
        or part.startswith(("--mount=", "--volume="))
        for part in args
    )


@pytest.mark.parametrize(
    "argv",
    [
        "python -c pass",
        (),
        ("relative-worker",),
        ("/worker", "bad\x00argument"),
    ],
)
def test_sandbox_rejects_invalid_or_shell_string_commands(argv):
    sandbox = _sandbox()
    with pytest.raises(ValueError):
        sandbox._build_command(argv, "/tmp/cid")


def test_docker_sandbox_executor_passes_only_tool_input_not_authority_material():
    class FakeSandbox:
        def __init__(self):
            self.argv = None
            self.input_data = None

        def run(self, argv, input_data):
            self.argv = argv
            self.input_data = input_data
            return SandboxResult(
                returncode=0,
                stdout=b'{"version":1,"result":{"status":"ok"}}',
                stderr=b"",
                duration_seconds=0.01,
            )

    sandbox = FakeSandbox()
    command = ("/usr/local/bin/paca-worker", "--stdio")
    sandbox_config = _sandbox()
    sandbox.implementation_digest = sandbox_config.implementation_digest
    executor = DockerSandboxExecutor(
        sandbox,
        commands={"read_file": command},
    )
    tool = Tool(
        "read_file",
        "1.0",
        "Read a file",
        ("path",),
        implementation_digest=sandbox_config.implementation_digest(command),
    )
    request = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt", Label("untrusted"))},
        # Deliberately include a visible capability to prove it is not serialized.
        cap=Capability(
            cap_id="secret-capability-id",
            principal="agent-a",
            tenant="acme",
            task_id="task-1",
            role="assistant",
            grants={"read_file": ("/workspace/*",)},
            expires=9999999999,
        ),
        step=1,
        tool=tool,
    )
    assert executor(request) == {"status": "ok"}
    payload = json.loads(sandbox.input_data)
    assert payload == {
        "version": 1,
        "action": "read_file",
        "arguments": {"path": "/workspace/report.txt"},
        "tool": {
            "name": "read_file",
            "version": "1.0",
            "description": "Read a file",
            "schema": ["path"],
            "hash": tool.hash,
        },
    }
    assert "secret-capability-id" not in sandbox.input_data.decode()
    assert "grants" not in payload
    with pytest.raises(TypeError):
        executor.commands["read_file"] = ("/different/worker",)


def test_docker_sandbox_executor_rejects_missing_or_mismatched_implementation_pin():
    class FakeSandbox:
        def run(self, *_args, **_kwargs):
            pytest.fail("unverified worker must not start")

        def implementation_digest(self, argv):
            return _sandbox().implementation_digest(argv)

    command = ("/usr/local/bin/paca-worker",)
    executor = DockerSandboxExecutor(
        FakeSandbox(),
        commands={"read_file": command},
    )
    capability = Capability(
        cap_id="cap",
        principal="agent-a",
        tenant="acme",
        task_id="task-1",
        role="assistant",
        grants={"read_file": ("/workspace/*",)},
        expires=9999999999,
    )
    missing = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt")},
        cap=capability,
        step=1,
        tool=Tool("read_file", "1.0", "Read a file", ("path",)),
    )
    with pytest.raises(SandboxExecutionError, match="no signed implementation digest"):
        executor(missing)

    mismatched = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt")},
        cap=capability,
        step=1,
        tool=Tool(
            "read_file",
            "1.0",
            "Read a file",
            ("path",),
            implementation_digest="b" * 64,
        ),
    )
    with pytest.raises(SandboxExecutionError, match="does not match"):
        executor(mismatched)


def test_docker_sandbox_executor_fails_closed_for_unregistered_actions():
    class FakeSandbox:
        def run(self, *_args, **_kwargs):
            pytest.fail("unregistered action must not start a container")

    executor = DockerSandboxExecutor(
        FakeSandbox(),
        commands={"read_file": ("/usr/local/bin/paca-worker",)},
    )
    request = Request(
        "send_email",
        {"to": Arg("external@example.test")},
        cap=__import__("paca.runtime", fromlist=["Capability"]).Capability(
            cap_id="cap",
            principal="agent-a",
            tenant="acme",
            task_id="task-1",
            role="assistant",
            grants={},
            expires=9999999999,
        ),
        step=1,
    )
    with pytest.raises(SandboxExecutionError, match="no isolated worker"):
        executor(request)


def test_docker_sandbox_executor_rejects_non_json_worker_output():
    class FakeSandbox:
        def run(self, *_args, **_kwargs):
            return SandboxResult(0, b"not-json", b"", 0.01)

    fake_sandbox = FakeSandbox()
    fake_sandbox.implementation_digest = _sandbox().implementation_digest
    executor = DockerSandboxExecutor(
        fake_sandbox,
        commands={"read_file": ("/usr/local/bin/paca-worker",)},
    )
    tool_command = ("/usr/local/bin/paca-worker",)
    request = Request(
        "read_file",
        {"path": Arg("/workspace/report.txt")},
        cap=__import__("paca.runtime", fromlist=["Capability"]).Capability(
            cap_id="cap",
            principal="agent-a",
            tenant="acme",
            task_id="task-1",
            role="assistant",
            grants={},
            expires=9999999999,
        ),
        step=1,
        tool=Tool(
            "read_file",
            "1.0",
            "Read a file",
            ("path",),
            implementation_digest=_sandbox().implementation_digest(tool_command),
        ),
    )
    with pytest.raises(SandboxExecutionError, match="invalid JSON"):
        executor(request)


def test_docker_sandbox_configuration_is_immutable_after_initialization():
    sandbox = _sandbox(docker_env={"DOCKER_HOST": "unix:///var/run/docker.sock"})

    with pytest.raises(AttributeError, match="configuration is immutable"):
        sandbox.memory_bytes = 64 * 1024 * 1024
    with pytest.raises(TypeError):
        sandbox.docker_env["DOCKER_HOST"] = "tcp://untrusted.example:2376"


def test_docker_sandbox_does_not_inherit_ambient_docker_context(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.example:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "untrusted-context")
    monkeypatch.setenv("DOCKER_CONFIG", "/tmp/untrusted-docker-config")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")

    sandbox = _sandbox()

    assert sandbox.docker_env == {}


def test_docker_sandbox_requires_explicit_mapping_for_cli_environment():
    with pytest.raises(TypeError, match="must be a mapping"):
        _sandbox(docker_env=["DOCKER_HOST", "tcp://example.invalid"])

    configured = _sandbox(docker_env={"DOCKER_HOST": "unix:///var/run/docker.sock"})
    assert configured.docker_env == {"DOCKER_HOST": "unix:///var/run/docker.sock"}
