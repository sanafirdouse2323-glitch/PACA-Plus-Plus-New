"""Linux openat2-based filesystem access constrained beneath a trusted root.

This module intentionally fails closed when the kernel lacks openat2. It does
not silently fall back to path-based checks that can reintroduce symlink or
time-of-check/time-of-use races.
"""
from __future__ import annotations

import ctypes
import errno
import os
import stat
import struct
from typing import Union


class SecurePathError(OSError):
    """A path was invalid, escaped the configured root, or was not a regular file."""


class SecurePathUnavailable(RuntimeError):
    """The required Linux openat2 syscall is unavailable; no unsafe fallback is used."""


# openat2 is syscall 437 on the supported Linux architectures below.
_OPENAT2_SYSCALL = {
    "x86_64": 437,
    "amd64": 437,
    "aarch64": 437,
    "arm64": 437,
    "riscv64": 437,
}
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_FLAGS = (
    _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS
)


def _relative_path(value: Union[str, os.PathLike[str]]) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str):
        raise SecurePathError(errno.EINVAL, "path must be text")
    if (
        not raw
        or raw.startswith("/")
        or "\x00" in raw
        or "\\" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise SecurePathError(errno.EINVAL, "path must be a normalized relative path")
    return raw


class SecureRoot:
    """Open regular files beneath a preconfigured root without following symlinks.

    Linux openat2 resolves the complete relative path from a root directory
    descriptor with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS. The returned file
    descriptor refers to the resolved inode, so later path replacement cannot
    redirect an operation already opened by the caller.

    The root path is trusted administrator configuration. Callers must still
    enforce PACA++ policy grants before asking this class to open a path.
    """

    def __init__(self, root: Union[str, os.PathLike[str]]) -> None:
        if os.name != "posix" or not hasattr(os, "O_PATH") or not hasattr(os, "O_NOFOLLOW"):
            raise SecurePathUnavailable("SecureRoot requires Linux openat2 support")
        machine = os.uname().machine.lower()
        syscall_number = _OPENAT2_SYSCALL.get(machine)
        if syscall_number is None:
            raise SecurePathUnavailable(f"unsupported Linux architecture: {machine}")
        self._syscall_number = syscall_number
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long
        root_flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            self._root_fd = os.open(os.fspath(root), root_flags)
        except OSError as exc:
            raise SecurePathError(exc.errno, "could not open trusted filesystem root") from exc
        self._closed = False

    def open_fd(
        self,
        relative_path: Union[str, os.PathLike[str]],
        flags: int = os.O_RDONLY,
        mode: int = 0o600,
    ) -> int:
        """Open a regular file beneath the root and return its owned file descriptor.

        For a new file, pass O_CREAT | O_EXCL. File descriptors are owned by the
        caller and must be closed. O_TRUNC is applied by the kernel as part of
        the constrained open, not after a separate path-validation step.
        """
        if self._closed:
            raise SecurePathError(errno.EBADF, "SecureRoot is closed")
        relative = _relative_path(relative_path)
        allowed = (
            os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_EXCL
            | os.O_TRUNC | os.O_APPEND | os.O_CLOEXEC
        )
        if isinstance(flags, bool) or not isinstance(flags, int) or flags & ~allowed:
            raise SecurePathError(errno.EINVAL, "unsupported open flags")
        if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o777:
            raise SecurePathError(errno.EINVAL, "file mode must be between 000 and 777")
        if flags & os.O_EXCL and not flags & os.O_CREAT:
            raise SecurePathError(errno.EINVAL, "O_EXCL requires O_CREAT")

        effective_flags = flags | os.O_CLOEXEC
        effective_mode = mode if flags & os.O_CREAT else 0
        how = struct.pack(
            "=QQQ",
            effective_flags,
            effective_mode,
            _RESOLVE_FLAGS,
        )
        how_buffer = ctypes.create_string_buffer(how)
        path_bytes = os.fsencode(relative)
        result = self._libc.syscall(
            ctypes.c_long(self._syscall_number),
            ctypes.c_int(self._root_fd),
            ctypes.c_char_p(path_bytes),
            ctypes.byref(how_buffer),
            ctypes.c_size_t(len(how)),
        )
        if result < 0:
            error_number = ctypes.get_errno()
            if error_number in {errno.ENOSYS, errno.E2BIG, errno.EINVAL}:
                raise SecurePathUnavailable(
                    "kernel openat2 with required resolution flags is unavailable"
                )
            raise SecurePathError(error_number, os.strerror(error_number), relative)

        fd = int(result)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SecurePathError(errno.EINVAL, "target is not a regular file", relative)
        except Exception:
            os.close(fd)
            raise
        return fd

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> "SecureRoot":
        if self._closed:
            raise SecurePathError(errno.EBADF, "SecureRoot is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


__all__ = ["SecurePathError", "SecurePathUnavailable", "SecureRoot"]
