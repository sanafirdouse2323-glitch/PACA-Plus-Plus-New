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
import math
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple


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
        normalized = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise UnsafeNetworkDestination("destination hostname is not valid IDNA") from exc
    if not normalized or len(normalized) > 253:
        raise UnsafeNetworkDestination("destination hostname is empty or too long")
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass
    # Reject non-standard numeric IPv4 forms (for example integer or
    # shortened dotted forms) instead of letting libc reinterpret them.
    if re.fullmatch(r"[0-9.]+", normalized):
        raise UnsafeNetworkDestination("destination IP address is not in canonical form")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise UnsafeNetworkDestination("destination hostname contains an invalid DNS label")
    if (
        normalized == "localhost"
        or normalized.endswith((".localhost", ".local", ".internal"))
        or normalized == "metadata"
        or normalized.startswith("metadata.")
    ):
        raise UnsafeNetworkDestination("destination hostname is reserved for local or internal use")
    return normalized


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
        expected_length = 2 if family == socket.AF_INET else 4
        if len(sockaddr) != expected_length or sockaddr[1] != port:
            raise UnsafeNetworkDestination(
                "resolver returned an address tuple with an unexpected port or shape"
            )
        raw_address = sockaddr[0]
        try:
            address = ipaddress.ip_address(str(raw_address).split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeNetworkDestination("resolver did not return a numeric IP address") from exc
        # The well-known NAT64 prefix is globally classified by ipaddress even
        # when its embedded IPv4 target is private (for example 64:ff9b::7f00:1
        # represents 127.0.0.1). This helper has no trusted translator-policy
        # configuration, so reject the entire translation prefix rather than
        # treating the IPv6 outer address as sufficient evidence of a public
        # destination.
        if isinstance(address, ipaddress.IPv6Address):
            if address in ipaddress.ip_network("64:ff9b::/96"):
                raise UnsafeNetworkDestination(
                    "destination uses the well-known NAT64 translation prefix"
                )
            if address.ipv4_mapped is not None:
                address = address.ipv4_mapped
        if address.version != (4 if family == socket.AF_INET else 6):
            raise UnsafeNetworkDestination(
                "resolver address family does not match the numeric address"
            )
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
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout < 0
    ):
        raise UnsafeNetworkDestination("connection timeout must be a finite non-negative number or None")
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
    tls_context = context if context is not None else ssl.create_default_context()
    if not isinstance(tls_context, ssl.SSLContext):
        raise TypeError("context must be an ssl.SSLContext")
    if (
        tls_context.check_hostname is not True
        or tls_context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise UnsafeNetworkDestination(
            "TLS context must require certificate-chain and hostname verification"
        )
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
