"""Docker-backed worker isolation for PACA tool execution.

The host keeps policy, capabilities, provider credentials and resource commits.
Workers receive only a bounded JSON request inside a digest-pinned container
with no network, no host mounts, a read-only root filesystem and resource limits.
This is an execution boundary adapter, not a substitute for resource-side commit
authorization or a host kernel/container-runtime security review.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any


class SandboxError(RuntimeError):
    """A sandboxed worker could not be started or safely completed."""


class SandboxUnavailable(SandboxError):
    """The configured container runtime is unavailable."""


class SandboxTimeout(SandboxError):
    """A sandboxed worker exceeded its wall-clock deadline."""


class SandboxOutputLimitExceeded(SandboxError):
    """A sandboxed worker exceeded the host-side output limit."""


class SandboxExecutionError(SandboxError):
    """The worker failed or returned an invalid result envelope."""


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float


_DOCKER_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
    }
)
_IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")


class DockerSandbox:
    """Run a fixed command in a digest-pinned, network-isolated Docker container.

    No host volumes, devices, credentials, Docker socket, or environment variables
    are passed into the container. The command and image are trusted deployment
    configuration; model-provided strings are arguments only and never a shell.
    """

    def __init__(
        self,
        image: str,
        *,
        docker_binary: str = "docker",
        timeout_seconds: float = 15.0,
        memory_bytes: int = 536_870_912,
        cpu_limit: float = 1.0,
        pids_limit: int = 64,
        max_input_bytes: int = 1_048_576,
        max_output_bytes: int = 1_048_576,
        tmpfs_bytes: int = 33_554_432,
        docker_env: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(image, str) or _IMAGE_DIGEST.fullmatch(image) is None:
            raise ValueError(
                "sandbox image must be pinned by an immutable sha256 digest"
            )
        if not isinstance(docker_binary, str) or not docker_binary:
            raise ValueError(
                "docker_binary must be a non-empty executable name or path"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive")
        for name, value, minimum, maximum in (
            ("memory_bytes", memory_bytes, 64 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
            ("pids_limit", pids_limit, 1, 512),
            ("max_input_bytes", max_input_bytes, 1, 16 * 1024 * 1024),
            ("max_output_bytes", max_output_bytes, 1, 16 * 1024 * 1024),
            ("tmpfs_bytes", tmpfs_bytes, 1024 * 1024, 512 * 1024 * 1024),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} is outside the supported range")
        if (
            isinstance(cpu_limit, bool)
            or not isinstance(cpu_limit, (int, float))
            or not math.isfinite(cpu_limit)
            or not 0.1 <= cpu_limit <= 8.0
        ):
            raise ValueError("cpu_limit must be between 0.1 and 8.0")
        if docker_env is not None and not isinstance(docker_env, Mapping):
            raise TypeError(
                "docker_env must be a mapping of trusted Docker CLI settings"
            )
        # Do not inherit ambient daemon/context selection from the host process.
        # A remote daemon or alternate Docker config must be an explicit operator choice.
        supplied_env = dict(docker_env) if docker_env is not None else {}
        if set(supplied_env) - _DOCKER_ENV_ALLOWLIST:
            raise ValueError(
                "docker_env contains variables outside the explicit Docker CLI allowlist"
            )
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or "\x00" in key
            or "\x00" in value
            for key, value in supplied_env.items()
        ):
            raise ValueError("docker_env keys and values must be NUL-free strings")
        self.image = image
        self.docker_binary = docker_binary
        self.timeout_seconds = float(timeout_seconds)
        self.memory_bytes = memory_bytes
        self.cpu_limit = float(cpu_limit)
        self.pids_limit = pids_limit
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes
        self.tmpfs_bytes = tmpfs_bytes
        self.docker_env = supplied_env

    @staticmethod
    def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not argv:
            raise ValueError("sandbox command must be a non-empty argument sequence")
        command = tuple(argv)
        if any(
            not isinstance(part, str) or not part or "\x00" in part for part in command
        ) or not command[0].startswith("/"):
            raise ValueError(
                "sandbox executable must be an absolute path and arguments must be NUL-free strings"
            )
        return command

    def implementation_digest(self, argv: Sequence[str]) -> str:
        """Digest the exact worker image, command and enforced isolation profile.

        Configure this value as Tool.implementation_digest before issuing the
        capability. A changed image, command or sandbox limit requires a new
        signed tool pin.
        """
        command = self._validate_argv(argv)
        descriptor = {
            "profile": "paca-docker-worker-v1",
            "image": self.image,
            "argv": list(command),
            "isolation": {
                "network": "none",
                "read_only_root": True,
                "capabilities_dropped": "ALL",
                "no_new_privileges": True,
                "seccomp": "default",
                "user": "65534:65534",
                "ipc": "private",
                "pids_limit": self.pids_limit,
                "memory_bytes": self.memory_bytes,
                "cpu_limit": self.cpu_limit,
                "nofile_limit": 64,
                "core_limit": 0,
                "file_size_limit": self.max_output_bytes,
                "tmpfs_bytes": self.tmpfs_bytes,
                "timeout_seconds": self.timeout_seconds,
                "max_input_bytes": self.max_input_bytes,
                "max_output_bytes": self.max_output_bytes,
                "docker_cli_environment": dict(sorted(self.docker_env.items())),
            },
        }
        encoded = json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _build_command(self, argv: Sequence[str], cidfile: str) -> tuple[str, ...]:
        command = self._validate_argv(argv)
        if not isinstance(cidfile, str) or not cidfile:
            raise ValueError("cidfile path must be non-empty")
        return (
            self.docker_binary,
            "run",
            "--rm",
            "--interactive",
            "--init",
            "--cidfile",
            cidfile,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--security-opt=seccomp=default",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory_bytes}",
            f"--memory-swap={self.memory_bytes}",
            f"--cpus={self.cpu_limit:.3f}",
            "--user=65534:65534",
            "--ipc=private",
            "--ulimit=nofile=64:64",
            "--ulimit=core=0:0",
            f"--ulimit=fsize={self.max_output_bytes}:{self.max_output_bytes}",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_bytes}",
            "--workdir=/tmp",
            "--env=HOME=/tmp",
            "--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--env=LANG=C.UTF-8",
            "--entrypoint",
            command[0],
            self.image,
            *command[1:],
        )

    def _remove_container(self, cidfile: Path) -> None:
        try:
            container_id = cidfile.read_text(encoding="ascii").strip()
        except OSError:
            return
        if _CONTAINER_ID.fullmatch(container_id) is None:
            return
        # The original timeout/output-limit error remains the actionable
        # failure; an unavailable cleanup CLI must not be reported as success.
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                [self.docker_binary, "rm", "--force", container_id],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.docker_env,
                timeout=5,
                check=False,
            )

    def run(self, argv: Sequence[str], input_data: bytes) -> SandboxResult:
        """Execute argv with bounded input/output and a wall-clock deadline."""
        command = self._validate_argv(argv)
        if not isinstance(input_data, bytes):
            raise TypeError("sandbox input_data must be bytes")
        if len(input_data) > self.max_input_bytes:
            raise SandboxError("sandbox input exceeds the configured byte limit")
        docker_path = shutil.which(self.docker_binary)
        if docker_path is None:
            raise SandboxUnavailable("Docker CLI is not installed or not on PATH")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="paca-sandbox-") as directory:
            cidfile = Path(directory) / "container-id"
            docker_command = self._build_command(command, str(cidfile))
            docker_command = (docker_path, *docker_command[1:])
            try:
                process = subprocess.Popen(
                    docker_command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self.docker_env,
                    start_new_session=True,
                    bufsize=0,
                )
            except OSError as exc:
                raise SandboxUnavailable("could not start the Docker CLI") from exc

            stdout = bytearray()
            stderr = bytearray()
            output_total = [0]
            output_lock = threading.Lock()
            output_exceeded = threading.Event()

            def drain(stream, destination: bytearray) -> None:
                try:
                    while True:
                        chunk = stream.read(65_536)
                        if not chunk:
                            return
                        with output_lock:
                            if output_total[0] + len(chunk) > self.max_output_bytes:
                                output_exceeded.set()
                            elif not output_exceeded.is_set():
                                destination.extend(chunk)
                                output_total[0] += len(chunk)
                        if output_exceeded.is_set():
                            with contextlib.suppress(OSError):
                                process.kill()
                            return
                finally:
                    with contextlib.suppress(OSError):
                        stream.close()

            def feed_input() -> None:
                try:
                    assert process.stdin is not None
                    process.stdin.write(input_data)
                    process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    if process.stdin is not None:
                        with contextlib.suppress(OSError):
                            process.stdin.close()

            assert process.stdout is not None and process.stderr is not None
            readers = [
                threading.Thread(
                    target=drain, args=(process.stdout, stdout), daemon=True
                ),
                threading.Thread(
                    target=drain, args=(process.stderr, stderr), daemon=True
                ),
            ]
            writer = threading.Thread(target=feed_input, daemon=True)
            for thread in readers:
                thread.start()
            writer.start()

            timed_out = False
            try:
                returncode = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(OSError):
                    process.kill()
                returncode = process.wait()

            writer.join(timeout=1.0)
            for thread in readers:
                thread.join(timeout=2.0)

            if timed_out or output_exceeded.is_set():
                self._remove_container(cidfile)
            duration = time.monotonic() - started
            if timed_out:
                raise SandboxTimeout(
                    "sandboxed worker exceeded its wall-clock deadline"
                )
            if output_exceeded.is_set():
                raise SandboxOutputLimitExceeded(
                    "sandboxed worker exceeded the combined stdout/stderr limit"
                )
            return SandboxResult(
                returncode=int(returncode),
                stdout=bytes(stdout),
                stderr=bytes(stderr),
                duration_seconds=duration,
            )


class DockerSandboxExecutor:
    """Adapt a trusted action-to-command registry to PACA's executor callback.

    Only action name, argument values and the pinned tool manifest are sent to
    the worker. No capability token, grant set, authority record, signing key,
    registry handle or provider credential is serialized into the container.
    The worker returns a JSON result; consequential host-resource commits must
    still pass through a separate resource-side commit authorization gate.
    """

    def __init__(
        self,
        sandbox: DockerSandbox,
        *,
        commands: Mapping[str, Sequence[str]],
    ) -> None:
        if not callable(getattr(sandbox, "run", None)):
            raise TypeError(
                "sandbox must provide a callable run(argv, input_data) method"
            )
        if not isinstance(commands, Mapping) or not commands:
            raise ValueError(
                "commands must be a non-empty trusted action-to-command mapping"
            )
        normalized: dict[str, tuple[str, ...]] = {}
        for action, argv in commands.items():
            if not isinstance(action, str) or not action:
                raise ValueError("sandbox action names must be non-empty strings")
            if action in normalized:
                raise ValueError("duplicate sandbox action mapping")
            normalized[action] = DockerSandbox._validate_argv(argv)
        self.sandbox = sandbox
        # Prevent runtime mutation of the trusted action-to-command map. The
        # implementation-digest check also detects changed sandbox configuration.
        self.commands = MappingProxyType(normalized)

    def __call__(self, request: Any) -> Any:
        from .provenance import Arg
        from .runtime import Request, Tool

        if not isinstance(request, Request):
            raise TypeError("DockerSandboxExecutor requires a typed PACA Request")
        command = self.commands.get(request.action)
        if command is None:
            raise SandboxExecutionError(
                "no isolated worker is registered for this action"
            )
        tool_manifest = request.tool
        if not isinstance(tool_manifest, Tool):
            raise SandboxExecutionError(
                "isolated tool execution requires a typed, capability-pinned tool manifest"
            )
        implementation_digest = tool_manifest.implementation_digest
        if implementation_digest is None:
            raise SandboxExecutionError(
                "isolated tool manifest has no signed implementation digest"
            )
        digest_builder = getattr(self.sandbox, "implementation_digest", None)
        if not callable(digest_builder):
            raise SandboxExecutionError(
                "sandbox runner cannot attest its configured worker identity"
            )
        try:
            actual_implementation_digest = digest_builder(command)
        except Exception as exc:
            raise SandboxExecutionError(
                "sandbox worker identity could not be computed"
            ) from exc
        if (
            not isinstance(actual_implementation_digest, str)
            or not hmac.compare_digest(
                actual_implementation_digest,
                implementation_digest,
            )
        ):
            raise SandboxExecutionError(
                "tool implementation digest does not match the configured sandbox worker"
            )

        arguments: dict[str, Any] = {}
        for name, argument in request.args.items():
            if not isinstance(name, str) or not name or not isinstance(argument, Arg):
                raise SandboxExecutionError(
                    "sandbox request contains an invalid typed argument"
                )
            arguments[name] = argument.value
        tool = {
            "name": tool_manifest.name,
            "version": tool_manifest.version,
            "description": tool_manifest.description,
            "schema": list(tool_manifest.schema),
            "hash": tool_manifest.hash,
        }
        try:
            encoded = json.dumps(
                {
                    "version": 1,
                    "action": request.action,
                    "arguments": arguments,
                    "tool": tool,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SandboxExecutionError(
                "sandbox request is not canonical JSON"
            ) from exc
        result = self.sandbox.run(command, encoded)
        if not isinstance(result, SandboxResult):
            raise SandboxExecutionError(
                "sandbox runner returned an invalid result object"
            )
        if result.returncode != 0:
            detail = result.stderr[:2048].decode("utf-8", errors="replace")
            raise SandboxExecutionError(
                f"isolated worker exited with status {result.returncode}: {detail}"
            )
        try:
            response = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxExecutionError(
                "isolated worker returned invalid JSON"
            ) from exc
        if (
            not isinstance(response, dict)
            or response.get("version") != 1
            or "result" not in response
        ):
            raise SandboxExecutionError(
                "isolated worker returned an invalid result envelope"
            )
        return response["result"]


__all__ = [
    "DockerSandbox",
    "DockerSandboxExecutor",
    "SandboxError",
    "SandboxExecutionError",
    "SandboxOutputLimitExceeded",
    "SandboxResult",
    "SandboxTimeout",
    "SandboxUnavailable",
]
