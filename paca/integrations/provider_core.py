"""Shared OAuth, HTTP and provenance-capture primitives for provider adapters."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..memory import TrustedConnectorAdapter
from ..provenance import Arg


class ProviderConnectorError(RuntimeError):
    """A provider request failed or returned an unsafe response."""


class ProviderAuthenticationError(ProviderConnectorError):
    """Provider OAuth/API-key authentication or scope validation failed."""


class ProviderScopeError(ProviderAuthenticationError):
    """The configured consented scopes do not authorize the requested method."""


class ProviderResponseTooLarge(ProviderConnectorError):
    """A provider response exceeded the configured byte limit."""


class ProviderProtocolError(ProviderConnectorError):
    """A provider returned an invalid or unexpected response."""


@dataclass(frozen=True, repr=False)
class OAuthAccessToken:
    access_token: str = field(repr=False)
    token_type: str
    scopes: frozenset[str]
    expires_at: float

    def __repr__(self) -> str:
        return (
            "OAuthAccessToken(access_token=<redacted>, "
            f"token_type={self.token_type!r}, scopes={sorted(self.scopes)!r}, "
            f"expires_at={self.expires_at!r})"
        )


class OAuth2RefreshTokenProvider:
    """Refresh OAuth 2.0 access tokens using a fixed, trusted HTTPS token URL.

    The client secret and refresh token are deployment secrets. A rotated refresh
    token is delivered to on_refresh_token so the application can persist it to
    its secret store before the in-memory value is replaced. No token is logged
    or included in repr/error strings.
    """

    def __init__(
        self,
        token_url: str,
        *,
        client_id: str,
        client_secret: str | None,
        refresh_token: str,
        granted_scopes: Iterable[str],
        include_scope_parameter: bool = False,
        on_refresh_token: Callable[[str], None] | None = None,
        client: Any = None,
        timeout_seconds: float = 15.0,
        refresh_skew_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        parsed = urlparse(token_url) if isinstance(token_url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError(
                "OAuth token endpoint must be a fixed HTTPS URL without userinfo or fragment"
            )
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("OAuth client_id must be non-empty")
        if client_secret is not None and (
            not isinstance(client_secret, str) or not client_secret
        ):
            raise ValueError("OAuth client_secret must be non-empty when supplied")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise ValueError("OAuth refresh_token must be non-empty")
        if isinstance(granted_scopes, (str, bytes)):
            raise TypeError(
                "granted_scopes must be an iterable of complete scope strings"
            )
        scopes = frozenset(granted_scopes)
        if not scopes or any(
            not isinstance(scope, str) or not scope.strip() for scope in scopes
        ):
            raise ValueError("granted_scopes must contain non-empty scope names")
        for name, value in (
            ("timeout_seconds", timeout_seconds),
            ("refresh_skew_seconds", refresh_skew_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be finite and positive")
        if not isinstance(include_scope_parameter, bool):
            raise TypeError("include_scope_parameter must be a boolean")
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "provider connectors require the optional 'providers' dependency"
            ) from exc
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._granted_scopes = scopes
        self._include_scope_parameter = include_scope_parameter
        self._on_refresh_token = on_refresh_token
        self._client = client or httpx.Client(
            timeout=float(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self._refresh_skew = float(refresh_skew_seconds)
        self._clock = clock
        self._lock = threading.RLock()
        self._cached: OAuthAccessToken | None = None

    def __repr__(self) -> str:
        return (
            "OAuth2RefreshTokenProvider(token_url=<configured>, "
            "client_id=<redacted>, client_secret=<redacted>, "
            "refresh_token=<redacted>, "
            f"granted_scopes={sorted(self._granted_scopes)!r})"
        )

    @property
    def granted_scopes(self) -> frozenset[str]:
        return self._granted_scopes

    def get_access_token(self, required_scopes: Iterable[str] = ()) -> OAuthAccessToken:
        requested = frozenset(required_scopes)
        if any(not isinstance(scope, str) or not scope for scope in requested):
            raise ValueError("required scopes must be non-empty strings")
        if not requested.issubset(self._granted_scopes):
            missing = sorted(requested - self._granted_scopes)
            raise ProviderScopeError(
                "configured OAuth consent does not include required scopes: "
                + ", ".join(missing)
            )
        now = float(self._clock())
        with self._lock:
            cached = self._cached
            if (
                cached is not None
                and cached.expires_at > now + self._refresh_skew
                and requested.issubset(cached.scopes)
            ):
                return cached

            form: dict[str, str] = {
                "client_id": self._client_id,
                "refresh_token": self._refresh_token,
                "grant_type": "refresh_token",
            }
            if self._client_secret is not None:
                form["client_secret"] = self._client_secret
            if self._include_scope_parameter:
                form["scope"] = " ".join(sorted(requested or self._granted_scopes))
            try:
                with self._client.stream(
                    "POST",
                    self._token_url,
                    data=form,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise ProviderAuthenticationError(
                            "OAuth token endpoint redirects are refused"
                        )
                    if response.status_code != 200:
                        raise ProviderAuthenticationError(
                            f"OAuth token endpoint rejected refresh (HTTP {response.status_code})"
                        )
                    token_body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(token_body) + len(chunk) > 262_144:
                            raise ProviderResponseTooLarge(
                                "OAuth token response exceeded the byte limit"
                            )
                        token_body.extend(chunk)
            except ProviderConnectorError:
                raise
            except Exception:  # noqa: BLE001 - normalize all optional HTTP transport failures without exposing response details.
                raise ProviderAuthenticationError(
                    "OAuth token endpoint request failed"
                ) from None
            try:
                payload = json.loads(bytes(token_body))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProviderProtocolError(
                    "OAuth token endpoint returned invalid JSON"
                ) from None
            if not isinstance(payload, dict):
                raise ProviderProtocolError(
                    "OAuth token endpoint returned an invalid object"
                )
            token = payload.get("access_token")
            token_type = payload.get("token_type", "Bearer")
            expires_in = payload.get("expires_in")
            if (
                not isinstance(token, str)
                or not token
                or not isinstance(token_type, str)
                or token_type.lower() != "bearer"
                or isinstance(expires_in, bool)
                or not isinstance(expires_in, (int, float))
                or not math.isfinite(expires_in)
                or expires_in <= 0
            ):
                raise ProviderProtocolError(
                    "OAuth token response is missing valid bearer-token fields"
                )
            returned_scopes = payload.get("scope")
            if returned_scopes is None:
                scopes = self._granted_scopes
            elif isinstance(returned_scopes, str):
                scopes = frozenset(returned_scopes.split())
            else:
                raise ProviderProtocolError(
                    "OAuth token response has invalid scope metadata"
                )
            if not scopes.issubset(self._granted_scopes):
                raise ProviderScopeError(
                    "OAuth token response claims scopes outside the configured consent grant"
                )
            if not requested.issubset(scopes):
                missing = sorted(requested - scopes)
                raise ProviderScopeError(
                    "refreshed OAuth token lacks required scopes: " + ", ".join(missing)
                )
            rotated = payload.get("refresh_token")
            if rotated is not None:
                if not isinstance(rotated, str) or not rotated:
                    raise ProviderProtocolError(
                        "OAuth token response contains an invalid rotated refresh token"
                    )
                if self._on_refresh_token is None:
                    raise ProviderAuthenticationError(
                        "OAuth server rotated the refresh token but no secure persistence callback is configured"
                    )
                try:
                    self._on_refresh_token(rotated)
                except Exception:  # noqa: BLE001 - application secret-store callbacks may raise custom errors; rotation must fail closed.
                    raise ProviderAuthenticationError(
                        "rotated OAuth refresh token could not be persisted securely"
                    ) from None
                self._refresh_token = rotated
            access = OAuthAccessToken(
                access_token=token,
                token_type="Bearer",
                scopes=scopes,
                expires_at=float(self._clock()) + float(expires_in),
            )
            self._cached = access
            return access

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


@dataclass(frozen=True, repr=False)
class ProviderCapture:
    """A provider record plus the exact source identity/version to be captured."""

    provider: str
    connector_id: str
    object_id: str
    version_id: str
    provider_version: str
    value: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("provider", "connector_id", "object_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.provider_version, str):
            raise TypeError("provider_version must be a string")
        if not isinstance(self.version_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.version_id
        ):
            raise ValueError("version_id must be a lowercase SHA-256 digest")
        if not isinstance(self.value, Mapping):
            raise TypeError("provider capture value must be a mapping")

    def __repr__(self) -> str:
        return (
            "ProviderCapture("
            f"provider={self.provider!r}, connector_id={self.connector_id!r}, "
            f"object_id={self.object_id!r}, version_id={self.version_id!r}, "
            f"provider_version={self.provider_version!r}, value=<redacted>)"
        )

    def persist(
        self,
        connector: TrustedConnectorAdapter,
        *,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        if not isinstance(connector, TrustedConnectorAdapter):
            raise TypeError("provider capture requires a TrustedConnectorAdapter")
        if (
            connector.connector_id != self.connector_id
            or connector.integrity != "untrusted"
            or connector.source_class != "external_content"
        ):
            raise ProviderAuthenticationError(
                "provider capture must use its fixed-identity untrusted external-content connector"
            )
        if (
            self.provider == "qdrant"
            and self.value.get("tenant_id") != connector.tenant
        ):
            raise ProviderAuthenticationError(
                "Qdrant capture tenant does not match the authenticated memory connector tenant"
            )
        # Snapshot the provider record before persistence. The record digest is
        # checked against the digest captured by the connector, so a caller cannot
        # mutate a nested response field and persist altered content under the
        # original source-version identifier.
        try:
            record_bytes = json.dumps(
                dict(self.value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise ProviderProtocolError(
                "provider capture is not canonical JSON"
            ) from None
        record_digest = hashlib.sha256(record_bytes).hexdigest()
        if not hmac.compare_digest(record_digest, self.version_id):
            raise ProviderAuthenticationError(
                "provider capture content changed after capture"
            )
        record_snapshot = json.loads(record_bytes)
        captured_value = {
            "provider": self.provider,
            "provider_version": self.provider_version,
            "record": record_snapshot,
        }
        return connector.ingest(
            captured_value,
            object_id=self.object_id,
            version_id=self.version_id,
            purpose=purpose,
            capability_token=capability_token,
        )


@dataclass(frozen=True)
class ProviderPage:
    items: tuple[ProviderCapture, ...]
    next_cursor: str | None


class _ProviderHTTPClient:
    def __init__(
        self,
        *,
        client: Any = None,
        timeout_seconds: float = 15.0,
        max_response_bytes: int = 2_097_152,
        allow_insecure_localhost: bool = False,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive")
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1_024 <= max_response_bytes <= 16_777_216
        ):
            raise ValueError("max_response_bytes is outside the supported range")
        if not isinstance(allow_insecure_localhost, bool):
            raise TypeError("allow_insecure_localhost must be a boolean")
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "provider connectors require the optional 'providers' dependency"
            ) from exc
        self._client = client or httpx.Client(
            timeout=float(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self.max_response_bytes = max_response_bytes
        self.allow_insecure_localhost = allow_insecure_localhost

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        local_http = (
            self.allow_insecure_localhost
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if (
            (parsed.scheme != "https" and not local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ProviderConnectorError(
                "provider request URL must use an approved HTTPS origin"
            )

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_url(url)
        try:
            with self._client.stream(
                method,
                url,
                headers=dict(headers),
                params=params,
                json=json_body,
                follow_redirects=False,
            ) as response:
                if 300 <= response.status_code < 400:
                    raise ProviderConnectorError("provider redirects are refused")
                if response.status_code < 200 or response.status_code >= 300:
                    raise ProviderConnectorError(
                        f"provider request failed (HTTP {response.status_code})"
                    )
                content_type = response.headers.get("content-type", "").lower()
                if (
                    "application/json" not in content_type
                    and "+json" not in content_type
                ):
                    raise ProviderProtocolError("provider response was not JSON")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunks) + len(chunk) > self.max_response_bytes:
                        raise ProviderResponseTooLarge(
                            "provider response exceeded the configured byte limit"
                        )
                    chunks.extend(chunk)
        except ProviderConnectorError:
            raise
        except Exception:  # noqa: BLE001 - normalize optional HTTP transport failures and keep provider details private.
            raise ProviderConnectorError("provider HTTP request failed") from None
        try:
            payload = json.loads(bytes(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderProtocolError(
                "provider response contained invalid JSON"
            ) from None
        if not isinstance(payload, dict):
            raise ProviderProtocolError("provider response JSON must be an object")
        return payload

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


def _version_id(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_scope(token_provider: OAuth2RefreshTokenProvider, scope: str) -> str:
    if not isinstance(token_provider, OAuth2RefreshTokenProvider):
        raise TypeError("provider requires an OAuth2RefreshTokenProvider")
    return token_provider.get_access_token((scope,)).access_token
