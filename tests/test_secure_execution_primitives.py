from __future__ import annotations

import errno
import os
import ssl
import socket
import sys

import pytest

import paca.secure_network as secure_network
from paca.secure_io import SecurePathError, SecurePathUnavailable, SecureRoot
from paca.secure_network import (
    UnsafeNetworkDestination,
    connect_pinned,
    resolve_public_endpoints,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="these execution-boundary tests require Linux openat2",
)


def _open_root(path):
    try:
        return SecureRoot(path)
    except SecurePathUnavailable as exc:
        pytest.skip(str(exc))


def test_secure_root_opens_file_beneath_root(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "report.txt").write_text("authorised content", encoding="utf-8")

    with _open_root(root) as secure:
        fd = secure.open_fd("docs/report.txt", os.O_RDONLY)
        try:
            assert os.read(fd, 100) == b"authorised content"
        finally:
            os.close(fd)


def test_secure_root_rejects_parent_and_symlink_escapes(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("not authorised", encoding="utf-8")
    (root / "escape-file").symlink_to(secret)
    (root / "escape-dir").symlink_to(outside, target_is_directory=True)

    with _open_root(root) as secure:
        with pytest.raises(SecurePathError):
            secure.open_fd("../outside/secret.txt", os.O_RDONLY)
        with pytest.raises(SecurePathError):
            secure.open_fd("escape-file", os.O_RDONLY)
        with pytest.raises(SecurePathError):
            secure.open_fd("escape-dir/secret.txt", os.O_RDONLY)


def test_secure_root_creates_file_with_exclusive_open(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    with _open_root(root) as secure:
        fd = secure.open_fd(
            "created.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600
        )
        try:
            os.write(fd, b"created safely")
        finally:
            os.close(fd)
        with pytest.raises(SecurePathError):
            secure.open_fd("created.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL)


def _resolver_for(*addresses):
    def resolver(host, port, type):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
            for address in addresses
        ]
    return resolver


def test_network_resolver_accepts_only_public_addresses():
    endpoints = resolve_public_endpoints(
        "example.com", 443, resolver=_resolver_for("93.184.216.34")
    )
    assert len(endpoints) == 1
    assert endpoints[0].address == "93.184.216.34"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.2", "::1", "fc00::1"],
)
def test_network_resolver_rejects_non_public_addresses(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def resolver(host, port, type):
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    with pytest.raises(UnsafeNetworkDestination):
        resolve_public_endpoints("example.com", 443, resolver=resolver)


def test_network_resolver_rejects_mixed_public_and_private_answers():
    with pytest.raises(UnsafeNetworkDestination):
        resolve_public_endpoints(
            "example.com",
            443,
            resolver=_resolver_for("93.184.216.34", "10.0.0.5"),
        )


def test_connect_pinned_uses_the_validated_numeric_address_without_second_dns(monkeypatch):
    calls = []
    connected = []

    def resolver(host, port, type):
        calls.append((host, port))
        return _resolver_for("93.184.216.34")(host, port, type)

    class FakeSocket:
        def __init__(self, family, socktype, protocol):
            self.family = family
            self.socktype = socktype
            self.protocol = protocol
            self.timeout = None
            self.closed = False

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, sockaddr):
            connected.append(sockaddr)

        def close(self):
            self.closed = True

    monkeypatch.setattr(secure_network.socket, "socket", FakeSocket)
    result = connect_pinned("example.com", 443, resolver=resolver)

    assert isinstance(result, FakeSocket)
    assert calls == [("example.com", 443)]
    assert connected == [("93.184.216.34", 443)]

def test_tls_pinned_rejects_context_without_chain_and_hostname_verification(monkeypatch):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connections = []
    monkeypatch.setattr(
        secure_network,
        "connect_pinned",
        lambda *args, **kwargs: connections.append((args, kwargs)),
    )

    with pytest.raises(UnsafeNetworkDestination, match="certificate-chain and hostname"):
        secure_network.connect_tls_pinned(
            "example.com",
            context=context,
            resolver=_resolver_for("93.184.216.34"),
        )
    assert connections == []


@pytest.mark.parametrize("timeout", [-1, float("nan"), float("inf"), True])
def test_connect_pinned_rejects_invalid_timeout(timeout):
    with pytest.raises(UnsafeNetworkDestination, match="timeout"):
        connect_pinned(
            "example.com",
            443,
            timeout=timeout,
            resolver=_resolver_for("93.184.216.34"),
        )
