"""Crash-recoverable filesystem commits fenced by PACA authority state.

This adapter is for a broker-owned Linux directory that is not mounted into or
writable by agent-controlled processes. It stages bytes and a private recovery
journal, then performs the destination rename while the authority registry's
serialized commit transaction is held. Readers and writers must use the broker;
raw host access is outside this guarantee.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .authority_runtime import HMACCapabilityAuthority
from .resource_commit import FencedResourceExecutor, ResourceCommitDenied
from .secure_io import SecurePathError, SecurePathUnavailable, SecureRoot


class FilesystemFencedResourceExecutor(FencedResourceExecutor):
    """Commit write_file requests to a real filesystem under a DB fence.

    The configured root is a private service-owned resource namespace. A target
    such as /acme/reports/report.txt maps to
    <root>/acme/tasks/<sha256(task_id)>/reports/report.txt. This keeps the
    physical namespace consistent with the authority store's (tenant, task_id,
    resource) key. Existing
    parent directories are required; traversal, symlinks, hard links, special
    files and oversized files are rejected.

    A separate, private state directory stores backups and durable journals. A
    journal is reconciled against the registry's one-use commit receipt at start
    up and before every write. If the database transaction did not commit, the
    adapter restores the old file (or removes a newly-created file). If it did
    commit, the adapter verifies the new bytes and only then cleans recovery data.
    """

    SUPPORTED_ACTIONS = frozenset({"write_file"})

    def __init__(
        self,
        authority: HMACCapabilityAuthority,
        *,
        root: str | os.PathLike[str],
        state_dir: str | os.PathLike[str],
        max_file_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        super().__init__(authority)
        if (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or not 1 <= max_file_bytes <= 64 * 1024 * 1024
        ):
            raise ValueError("max_file_bytes must be between 1 byte and 64 MiB")
        try:
            import fcntl
        except ImportError as exc:
            raise ResourceCommitDenied(
                "filesystem commit broker requires Linux/POSIX advisory locking"
            ) from exc
        self._fcntl = fcntl
        self.max_file_bytes = max_file_bytes
        self._closed = False

        root_path = Path(root).expanduser().absolute()
        try:
            root_metadata = os.lstat(root_path)
        except OSError as exc:
            raise ResourceCommitDenied(
                "configured filesystem root is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or root_metadata.st_mode & 0o077
        ):
            raise ResourceCommitDenied(
                "filesystem root must be a private broker-owned directory with no group or other permissions"
            )
        try:
            self.secure_root = SecureRoot(root_path)
        except SecurePathUnavailable:
            raise
        except (OSError, SecurePathError) as exc:
            raise ResourceCommitDenied(
                "filesystem root could not be opened with required openat2 constraints"
            ) from exc

        state_path = Path(state_dir).expanduser().absolute()
        try:
            state_path.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_metadata = os.lstat(state_path)
        except OSError as exc:
            self.secure_root.close()
            raise ResourceCommitDenied(
                "private filesystem state directory is unavailable"
            ) from exc

        root_resolved = root_path.resolve(strict=True)
        state_resolved = state_path.resolve(strict=True)
        if (
            root_resolved == state_resolved
            or root_resolved in state_resolved.parents
            or state_resolved in root_resolved.parents
        ):
            self.secure_root.close()
            raise ValueError(
                "filesystem state_dir must be outside and separate from the resource root"
            )
        if (
            not stat.S_ISDIR(state_metadata.st_mode)
            or stat.S_ISLNK(state_metadata.st_mode)
            or state_metadata.st_uid != os.geteuid()
            or state_metadata.st_mode & 0o077
        ):
            self.secure_root.close()
            raise ResourceCommitDenied(
                "filesystem state_dir must be a private broker-owned directory with mode 0700 or stricter"
            )
        try:
            state_fd = os.open(
                state_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            self.secure_root.close()
            raise ResourceCommitDenied(
                "private filesystem state directory cannot be opened"
            ) from exc
        opened_state_metadata = os.fstat(state_fd)
        if (
            (state_metadata.st_dev, state_metadata.st_ino)
            != (opened_state_metadata.st_dev, opened_state_metadata.st_ino)
            or opened_state_metadata.st_uid != os.geteuid()
            or opened_state_metadata.st_mode & 0o077
        ):
            os.close(state_fd)
            self.secure_root.close()
            raise ResourceCommitDenied(
                "private filesystem state directory changed while opening"
            )
        self._state_fd = state_fd
        self._state_path = state_path

        # Recovery must finish before the broker accepts a new write.
        try:
            with self._locked():
                self._recover_pending_locked()
        except Exception:
            self.close()
            raise

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self._closed:
            raise ResourceCommitDenied("filesystem resource executor is closed")
        lock_fd = os.open(
            "broker.lock",
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._state_fd,
        )
        try:
            metadata = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise ResourceCommitDenied("filesystem broker lock file is not private")
            self._fcntl.flock(lock_fd, self._fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                self._fcntl.flock(lock_fd, self._fcntl.LOCK_UN)
            os.close(lock_fd)

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _validate_relative_resource(
        resource: str,
        tenant: str,
        task_id: str,
    ) -> str:
        if (
            not isinstance(resource, str)
            or not resource.startswith("/")
            or resource.startswith("//")
            or "\x00" in resource
            or "\\" in resource
            or any(ord(character) < 32 for character in resource)
        ):
            raise ResourceCommitDenied(
                "filesystem resource must be a normalized tenant path"
            )
        if (
            not isinstance(tenant, str)
            or not tenant
            or "/" in tenant
            or "\\" in tenant
            or tenant in {".", ".."}
            or any(ord(character) < 32 for character in tenant)
            or not isinstance(task_id, str)
            or not task_id
        ):
            raise ResourceCommitDenied(
                "filesystem tenant or task namespace is invalid"
            )
        parts = resource[1:].split("/")
        if (
            len(parts) < 2
            or any(part in {"", ".", ".."} for part in parts)
            or parts[0] != tenant
        ):
            raise ResourceCommitDenied(
                "filesystem resource must stay beneath its capability tenant directory"
            )
        task_namespace = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
        return "/".join((tenant, "tasks", task_namespace, *parts[1:]))

    def _parent_and_name(self, relative: str) -> tuple[int, str]:
        parts = relative.split("/")
        parent_relative = "/".join(parts[:-1])
        try:
            parent_fd = self.secure_root.open_directory_fd(parent_relative)
        except (OSError, SecurePathUnavailable, SecurePathError) as exc:
            raise ResourceCommitDenied(
                "filesystem target parent is missing or not safely resolvable"
            ) from exc
        return parent_fd, parts[-1]

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while staging filesystem resource")
            view = view[written:]
        os.fsync(fd)

    def _write_state_file(self, name: str, data: bytes) -> None:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._state_fd,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise ResourceCommitDenied(
                    "filesystem journal artifact is not a private regular file"
                )
            self._write_all(fd, data)
        finally:
            os.close(fd)
        os.fsync(self._state_fd)

    def _read_state_file(self, name: str, *, maximum: int) -> bytes:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self._state_fd,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
                or metadata.st_size > maximum
            ):
                raise ResourceCommitDenied(
                    "filesystem recovery artifact failed validation"
                )
            chunks = bytearray()
            while len(chunks) <= maximum:
                block = os.read(fd, min(65_536, maximum + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > maximum:
                raise ResourceCommitDenied(
                    "filesystem recovery artifact exceeds its size limit"
                )
            return bytes(chunks)
        finally:
            os.close(fd)

    def _read_target(self, parent_fd: int, name: str) -> bytes | None:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > self.max_file_bytes
        ):
            raise ResourceCommitDenied(
                "filesystem target must be a single-link regular file within the configured size limit"
            )
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            after = os.fstat(fd)
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_nlink != 1
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_size > self.max_file_bytes
            ):
                raise ResourceCommitDenied(
                    "filesystem target identity changed while opening"
                )
            chunks = bytearray()
            while len(chunks) <= self.max_file_bytes:
                block = os.read(
                    fd,
                    min(65_536, self.max_file_bytes + 1 - len(chunks)),
                )
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > self.max_file_bytes:
                raise ResourceCommitDenied(
                    "filesystem target exceeds the configured size limit"
                )
            return bytes(chunks)
        finally:
            os.close(fd)

    def _write_target_temp(self, parent_fd: int, name: str, data: bytes) -> None:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ResourceCommitDenied(
                    "filesystem staging target is not a regular file"
                )
            self._write_all(fd, data)
        finally:
            os.close(fd)
        os.fsync(parent_fd)

    def _write_journal(self, record: Mapping[str, object]) -> str:
        operation_id = record["operation_id"]
        if not isinstance(operation_id, str):
            raise ResourceCommitDenied("filesystem journal operation ID is invalid")
        final_name = operation_id + ".json"
        temporary_name = "." + operation_id + ".journal.tmp"
        encoded = json.dumps(
            dict(record),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        self._write_state_file(temporary_name, encoded)
        os.replace(
            temporary_name,
            final_name,
            src_dir_fd=self._state_fd,
            dst_dir_fd=self._state_fd,
        )
        os.fsync(self._state_fd)
        return final_name

    def _parse_journal(self, journal_name: str) -> dict[str, Any]:
        if (
            not isinstance(journal_name, str)
            or len(journal_name) != 37
            or not journal_name.endswith(".json")
        ):
            raise ResourceCommitDenied("filesystem journal filename is invalid")
        operation_id = journal_name[:-5]
        if len(operation_id) != 32 or any(
            character not in "0123456789abcdef" for character in operation_id
        ):
            raise ResourceCommitDenied("filesystem journal operation ID is invalid")
        raw = self._read_state_file(journal_name, maximum=64 * 1024)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ResourceCommitDenied("filesystem journal is malformed") from exc
        expected = {
            "version",
            "operation_id",
            "nonce",
            "authority_id",
            "tenant",
            "task_id",
            "action",
            "resource",
            "relative_path",
            "temp_name",
            "backup_name",
            "old_exists",
            "old_digest",
            "new_digest",
            "request_digest",
            "payload_digest",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ResourceCommitDenied(
                "filesystem journal fields are incomplete or unknown"
            )
        if value["version"] != 1 or value["operation_id"] != operation_id:
            raise ResourceCommitDenied(
                "filesystem journal version or identity is invalid"
            )
        if value["temp_name"] != f".paca-{operation_id}.tmp":
            raise ResourceCommitDenied(
                "filesystem journal staging filename is invalid"
            )
        if value["backup_name"] != f"{operation_id}.bak":
            raise ResourceCommitDenied(
                "filesystem journal backup filename is invalid"
            )
        for field in (
            "nonce",
            "authority_id",
            "tenant",
            "task_id",
            "action",
            "resource",
            "relative_path",
            "request_digest",
            "payload_digest",
            "new_digest",
        ):
            if not isinstance(value[field], str) or not value[field]:
                raise ResourceCommitDenied(
                    f"filesystem journal {field} is invalid"
                )
        for field in ("request_digest", "payload_digest", "new_digest"):
            digest = value[field]
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ResourceCommitDenied(
                    f"filesystem journal {field} is not a SHA-256 digest"
                )
        if not isinstance(value["old_exists"], bool):
            raise ResourceCommitDenied(
                "filesystem journal old_exists flag is invalid"
            )
        if value["old_exists"]:
            digest = value["old_digest"]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ResourceCommitDenied(
                    "filesystem journal old_digest is invalid"
                )
        elif value["old_digest"] is not None:
            raise ResourceCommitDenied(
                "filesystem journal has an unexpected old digest"
            )
        relative = self._validate_relative_resource(
            value["resource"],
            value["tenant"],
            value["task_id"],
        )
        if relative != value["relative_path"]:
            raise ResourceCommitDenied(
                "filesystem journal resource path is inconsistent"
            )
        return value

    @staticmethod
    def _receipt_matches(
        record: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> bool:
        fields = (
            ("nonce", "nonce"),
            ("authority_id", "authority_id"),
            ("tenant", "tenant"),
            ("task_id", "task_id"),
            ("action", "action"),
            ("resource", "resource_key"),
            ("request_digest", "request_digest"),
            ("payload_digest", "payload_digest"),
        )
        return all(
            record[left] == receipt.get(right)
            for left, right in fields
        )

    def _restore_uncommitted(
        self,
        record: Mapping[str, Any],
        parent_fd: int,
        name: str,
    ) -> None:
        current = self._read_target(parent_fd, name)
        current_digest = self._digest(current) if current is not None else None
        new_digest = record["new_digest"]

        if record["old_exists"]:
            old_digest = record["old_digest"]
            if current_digest == old_digest:
                return
            if current is not None and current_digest != new_digest:
                raise ResourceCommitDenied(
                    "uncommitted filesystem target changed outside the resource broker"
                )
            backup = self._read_state_file(
                record["backup_name"],
                maximum=self.max_file_bytes,
            )
            if self._digest(backup) != old_digest:
                raise ResourceCommitDenied(
                    "filesystem rollback backup failed its digest check"
                )
            restore_name = f".paca-{record['operation_id']}.restore"
            staged = None
            try:
                staged = self._read_target(parent_fd, restore_name)
            except FileNotFoundError:
                staged = None
            if staged is not None:
                if self._digest(staged) != old_digest:
                    raise ResourceCommitDenied(
                        "filesystem restore staging file is inconsistent"
                    )
            else:
                self._write_target_temp(parent_fd, restore_name, backup)
            os.replace(
                restore_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
            restored = self._read_target(parent_fd, name)
            if restored is None or self._digest(restored) != old_digest:
                raise ResourceCommitDenied(
                    "filesystem rollback did not restore the prior bytes"
                )
        elif current is not None:
            if current_digest != new_digest:
                raise ResourceCommitDenied(
                    "new filesystem target changed outside the resource broker before rollback"
                )
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)

    def _cleanup_journal(
        self,
        record: Mapping[str, Any],
        journal_name: str,
        parent_fd: int,
    ) -> None:
        for name in (
            record["temp_name"],
            f".paca-{record['operation_id']}.restore",
        ):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(record["backup_name"], dir_fd=self._state_fd)
            os.fsync(self._state_fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(journal_name, dir_fd=self._state_fd)
            os.fsync(self._state_fd)

    def _recover_one_locked(self, journal_name: str) -> str:
        record = self._parse_journal(journal_name)
        parent_fd, target_name = self._parent_and_name(
            record["relative_path"]
        )
        try:
            receipt = self.registry.get_resource_commit_receipt(record["nonce"])
            if receipt is not None:
                if not self._receipt_matches(record, receipt):
                    raise ResourceCommitDenied(
                        "filesystem journal does not match the durable authority commit receipt"
                    )
                if receipt.get("version") is None:
                    raise ResourceCommitDenied(
                        "filesystem recovery receipt no longer identifies the current resource value"
                    )
                current = self._read_target(parent_fd, target_name)
                if current is None or self._digest(current) != record["new_digest"]:
                    raise ResourceCommitDenied(
                        "committed filesystem target is missing or differs from its signed journal"
                    )
                outcome = "committed"
            else:
                self._restore_uncommitted(record, parent_fd, target_name)
                outcome = "rolled_back"
            self._cleanup_journal(record, journal_name, parent_fd)
            return outcome
        finally:
            os.close(parent_fd)

    def _recover_pending_locked(self) -> dict[str, int]:
        recovered = {"committed": 0, "rolled_back": 0}
        for name in sorted(os.listdir(self._state_fd)):
            if name.startswith(".") and name.endswith(".journal.tmp"):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=self._state_fd)
                    os.fsync(self._state_fd)
                continue
            if not name.endswith(".json"):
                continue
            outcome = self._recover_one_locked(name)
            recovered[outcome] += 1
        return recovered

    def recover_pending(self) -> dict[str, int]:
        """Reconcile leftover journals against durable commit receipts."""
        with self._locked():
            return self._recover_pending_locked()

    def execute_authorized(
        self,
        request: Request,
        permit_token: str,
    ) -> dict[str, Any]:
        permit, payload = self._verify_request(request, permit_token)
        if permit.action != "write_file":
            raise ResourceCommitDenied(
                "filesystem commit adapter only supports write_file"
            )
        content = payload.get("content")
        if not isinstance(content, str):
            raise ResourceCommitDenied(
                "filesystem write_file content must be text"
            )
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > self.max_file_bytes:
            raise ResourceCommitDenied(
                "filesystem write_file content exceeds the configured byte limit"
            )

        relative = self._validate_relative_resource(
            permit.resource,
            permit.tenant,
            permit.task_id,
        )
        operation_id = secrets.token_hex(16)
        temp_name = f".paca-{operation_id}.tmp"
        backup_name = operation_id + ".bak"

        with self._locked():
            self._recover_pending_locked()
            # Fast replay rejection avoids mistaking an older receipt for the
            # result of a new journal with a reused one-use permit nonce. The
            # unique database receipt remains the authoritative concurrency gate.
            if self.registry.get_resource_commit_receipt(permit.nonce) is not None:
                raise ResourceCommitDenied("resource commit permit replay was rejected")
            parent_fd, target_name = self._parent_and_name(relative)
            try:
                previous = self._read_target(parent_fd, target_name)
                journal: dict[str, object] = {
                    "version": 1,
                    "operation_id": operation_id,
                    "nonce": permit.nonce,
                    "authority_id": permit.authority_id,
                    "tenant": permit.tenant,
                    "task_id": permit.task_id,
                    "action": permit.action,
                    "resource": permit.resource,
                    "relative_path": relative,
                    "temp_name": temp_name,
                    "backup_name": backup_name,
                    "old_exists": previous is not None,
                    "old_digest": self._digest(previous) if previous is not None else None,
                    "new_digest": self._digest(content_bytes),
                    "request_digest": permit.request_digest,
                    "payload_digest": permit.payload_digest,
                }
                # Journal first. A crash during backup or temp staging leaves
                # the target unchanged, so recovery can safely discard partial
                # artifacts without needing an unstaged backup.
                journal_name = self._write_journal(journal)

                try:
                    if previous is not None:
                        self._write_state_file(backup_name, previous)
                    self._write_target_temp(parent_fd, temp_name, content_bytes)
                except Exception as exc:
                    try:
                        self._recover_one_locked(journal_name)
                    except Exception as recovery_error:
                        raise ResourceCommitDenied(
                            "filesystem staging failed and recovery needs operator review"
                        ) from recovery_error
                    raise ResourceCommitDenied(
                        "filesystem resource could not be staged safely"
                    ) from exc

                def commit_filesystem_rename() -> None:
                    # Detect an out-of-band same-identity writer that changed
                    # the destination after staging. Never silently overwrite
                    # bytes that were not the snapshot covered by this permit.
                    current = self._read_target(parent_fd, target_name)
                    if journal["old_exists"]:
                        if (
                            current is None
                            or self._digest(current) != journal["old_digest"]
                        ):
                            raise ResourceCommitDenied(
                                "filesystem destination changed after the commit snapshot"
                            )
                    elif current is not None:
                        raise ResourceCommitDenied(
                            "filesystem destination appeared after the commit snapshot"
                        )
                    os.replace(
                        temp_name,
                        target_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    os.fsync(parent_fd)

                try:
                    result = self.registry.commit_fenced_filesystem_write(
                        permit,
                        payload,
                        commit_callback=commit_filesystem_rename,
                    )
                except Exception as exc:
                    try:
                        receipt = self.registry.get_resource_commit_receipt(
                            permit.nonce
                        )
                        if receipt is not None:
                            if not self._receipt_matches(journal, receipt):
                                raise ResourceCommitDenied(
                                    "durable commit receipt does not match the filesystem operation"
                                )
                            if receipt.get("version") is None:
                                raise ResourceCommitDenied(
                                    "durable commit receipt no longer identifies the current resource value"
                                )
                            current = self._read_target(parent_fd, target_name)
                            if current is None or self._digest(current) != journal["new_digest"]:
                                raise ResourceCommitDenied(
                                    "database committed but filesystem bytes need operator recovery"
                                )
                            self._cleanup_journal(journal, journal_name, parent_fd)
                            return {
                                **receipt,
                                "commit_nonce": receipt["nonce"],
                                "storage": "filesystem",
                                "recovered_after_database_error": True,
                                "recovery_pending": False,
                            }
                        self._recover_one_locked(journal_name)
                    except Exception as recovery_error:
                        raise ResourceCommitDenied(
                            "filesystem commit failed and automatic recovery could not establish a safe state; operator review is required"
                        ) from recovery_error
                    raise ResourceCommitDenied(
                        "filesystem commit was rejected by the atomic authority fence"
                    ) from exc

                recovery_pending = False
                try:
                    self._recover_one_locked(journal_name)
                except Exception:
                    # Commit is durable. Keep its journal for a later recovery.
                    recovery_pending = True
                return {
                    **result,
                    "storage": "filesystem",
                    "recovery_pending": recovery_pending,
                }
            finally:
                os.close(parent_fd)

    async def aexecute_authorized(
        self,
        request: Request,
        permit_token: str,
    ) -> dict[str, Any]:
        """Async-compatible adapter; the final commit is synchronous and fenced."""
        return self.execute_authorized(request, permit_token)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(OSError):
                self.secure_root.close()
            with contextlib.suppress(OSError):
                os.close(self._state_fd)

    def __enter__(self) -> FilesystemFencedResourceExecutor:
        if self._closed:
            raise ResourceCommitDenied("filesystem resource executor is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


__all__ = ["FilesystemFencedResourceExecutor"]
