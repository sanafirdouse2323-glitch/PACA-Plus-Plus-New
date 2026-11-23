"""Connection-time network destination validation and IP-pinned sockets.

This module performs DNS resolution once, rejects any answer that is not globally
routable, and connects to the validated numeric socket address. It deliberately
does not implement HTTP redirects or proxying: callers must revalidate every
redirect target and must not hand the socket to a client that resolves the host
again. HTTPS callers should use connect_tls_pinned to preserve SNI and certificate
hostname verification.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple, Union


class UnsafeNetworkDestination(ValueError):
    """A network target is malformed, private, reserved, or otherwise unsafe."""


@dataclass(frozen=True)
class ResolvedEndpoint:
    family: int
    socktype: int
    protocol: int
    sockaddr: tuple
    address: str


Resolver = Callable[..., Iterable[tuple]]


def _normalise_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise UnsafeNetworkDestination("destination host must be a non-empty hostname")
    if any(char in host for char in "/\\?#@\x00") or "%" in host:
        raise UnsafeNetworkDestination("destination must be a hostname or IP address, not a URL")
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise UnsafeNetworkDestination("destination hostname is not valid IDNA") from exc


def resolve_public_endpoints(
    host: str,
    port: int,
    resolver: Resolver = socket.getaddrinfo,
) -> Tuple[ResolvedEndpoint, ...]:
    """Resolve once and reject the whole answer set if any address is non-public.

    Rejecting mixed public/private DNS answers avoids selecting a public answer
    while leaving an internal answer available for a later re-resolution.
    """
    normalized = _normalise_host(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise UnsafeNetworkDestination("destination port must be between 1 and 65535")
    try:
        records = tuple(resolver(normalized, port, type=socket.SOCK_STREAM))
    except OSError as exc:
        raise UnsafeNetworkDestination("destination DNS resolution failed") from exc
    if not records:
        raise UnsafeNetworkDestination("destination has no resolved addresses")

    endpoints = []
    seen = set()
    for record in records:
        if len(record) < 5:
            raise UnsafeNetworkDestination("resolver returned a malformed address record")
        family, socktype, protocol, _canonical_name, sockaddr = record[:5]
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
            raise UnsafeNetworkDestination("resolver returned an unsupported socket address")
        if not isinstance(sockaddr, tuple) or not sockaddr:
            raise UnsafeNetworkDestination("resolver returned a malformed socket address")
        raw_address = sockaddr[0]
        try:
            address = ipaddress.ip_address(str(raw_address).split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeNetworkDestination("resolver did not return a numeric IP address") from exc
        if not address.is_global:
            raise UnsafeNetworkDestination(
                f"destination resolved to a non-public address: {address}"
            )
        key = (family, socktype, protocol, sockaddr)
        if key not in seen:
            seen.add(key)
            endpoints.append(
                ResolvedEndpoint(family, socktype, protocol, tuple(sockaddr), str(address))
            )
    if not endpoints:
        raise UnsafeNetworkDestination("destination has no usable public stream address")
    return tuple(endpoints)


def connect_pinned(
    host: str,
    port: int,
    timeout: Optional[float] = 10.0,
    resolver: Resolver = socket.getaddrinfo,
) -> socket.socket:
    """Connect to a vetted numeric IP without performing a second DNS lookup.

    The returned connected socket is pinned to one address from the validated
    DNS answer set. Do not pass the hostname to another transport client for a
    fresh connection. Re-run this function for each HTTP redirect target.
    """
    normalized = _normalise_host(host)
    endpoints = resolve_public_endpoints(normalized, port, resolver=resolver)
    last_error: Optional[OSError] = None
    for endpoint in endpoints:
        connection = socket.socket(
            endpoint.family, endpoint.socktype, endpoint.protocol
        )
        try:
            connection.settimeout(timeout)
            connection.connect(endpoint.sockaddr)
            return connection
        except OSError as exc:
            last_error = exc
            connection.close()
    if last_error is not None:
        raise last_error
    raise UnsafeNetworkDestination("no vetted endpoint could be connected")


def connect_tls_pinned(
    host: str,
    port: int = 443,
    context: Optional[ssl.SSLContext] = None,
    timeout: Optional[float] = 10.0,
    resolver: Resolver = socket.getaddrinfo,
) -> ssl.SSLSocket:
    """Create TLS over an IP-pinned socket while verifying the original hostname."""
    normalized = _normalise_host(host)
    tls_context = context or ssl.create_default_context()
    connection = connect_pinned(
        normalized, port, timeout=timeout, resolver=resolver
    )
    try:
        return tls_context.wrap_socket(connection, server_hostname=normalized)
    except Exception:
        connection.close()
        raise


__all__ = [
    "ResolvedEndpoint",
    "UnsafeNetworkDestination",
    "connect_pinned",
    "connect_tls_pinned",
    "resolve_public_endpoints",
]
