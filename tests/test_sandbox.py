from __future__ import annotations

import json

import pytest

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
    executor = DockerSandboxExecutor(
        sandbox,
        commands={"read_file": ("/usr/local/bin/paca-worker", "--stdio")},
    )
    tool = Tool("read_file", "1.0", "Read a file", ("path",))
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

    executor = DockerSandboxExecutor(
        FakeSandbox(),
        commands={"read_file": ("/usr/local/bin/paca-worker",)},
    )
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
    )
    with pytest.raises(SandboxExecutionError, match="invalid JSON"):
        executor(request)
