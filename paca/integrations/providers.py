"""Provider-backed, read-only connectors for PACA trusted ingress.

Each provider adapter uses a fixed HTTPS origin, explicit least-privilege scope,
bounded JSON responses and an injected OAuth/API-key credential provider. Fetched
provider data is returned as ProviderCapture objects and can only become PACA
memory through persist(), which requires a fixed-identity untrusted connector.

No provider write method is included: remote mutations require a separate
destination-side commit-fencing/idempotency protocol.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote, urlparse

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
        client_secret: Optional[str],
        refresh_token: str,
        granted_scopes: Iterable[str],
        include_scope_parameter: bool = False,
        on_refresh_token: Optional[Callable[[str], None]] = None,
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
            raise ValueError("OAuth token endpoint must be a fixed HTTPS URL without userinfo or fragment")
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("OAuth client_id must be non-empty")
        if client_secret is not None and (not isinstance(client_secret, str) or not client_secret):
            raise ValueError("OAuth client_secret must be non-empty when supplied")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise ValueError("OAuth refresh_token must be non-empty")
        if isinstance(granted_scopes, (str, bytes)):
            raise TypeError("granted_scopes must be an iterable of complete scope strings")
        scopes = frozenset(granted_scopes)
        if not scopes or any(not isinstance(scope, str) or not scope.strip() for scope in scopes):
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
        self._cached: Optional[OAuthAccessToken] = None

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
                "configured OAuth consent does not include required scopes: " + ", ".join(missing)
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

            form: Dict[str, str] = {
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
                        raise ProviderAuthenticationError("OAuth token endpoint redirects are refused")
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
            except Exception:
                raise ProviderAuthenticationError(
                    "OAuth token endpoint request failed"
                ) from None
            try:
                payload = json.loads(bytes(token_body))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProviderProtocolError("OAuth token endpoint returned invalid JSON") from None
            if not isinstance(payload, dict):
                raise ProviderProtocolError("OAuth token endpoint returned an invalid object")
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
                raise ProviderProtocolError("OAuth token response is missing valid bearer-token fields")
            returned_scopes = payload.get("scope")
            if returned_scopes is None:
                scopes = self._granted_scopes
            elif isinstance(returned_scopes, str):
                scopes = frozenset(returned_scopes.split())
            else:
                raise ProviderProtocolError("OAuth token response has invalid scope metadata")
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
                    raise ProviderProtocolError("OAuth token response contains an invalid rotated refresh token")
                if self._on_refresh_token is None:
                    raise ProviderAuthenticationError(
                        "OAuth server rotated the refresh token but no secure persistence callback is configured"
                    )
                try:
                    self._on_refresh_token(rotated)
                except Exception:
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
        captured_value = {
            "provider": self.provider,
            "provider_version": self.provider_version,
            "record": dict(self.value),
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
    items: Tuple[ProviderCapture, ...]
    next_cursor: Optional[str]


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
            raise ProviderConnectorError("provider request URL must use an approved HTTPS origin")

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
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
                if "application/json" not in content_type and "+json" not in content_type:
                    raise ProviderProtocolError("provider response was not JSON")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunks) + len(chunk) > self.max_response_bytes:
                        raise ProviderResponseTooLarge("provider response exceeded the configured byte limit")
                    chunks.extend(chunk)
        except ProviderConnectorError:
            raise
        except Exception:
            raise ProviderConnectorError("provider HTTP request failed") from None
        try:
            payload = json.loads(bytes(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderProtocolError("provider response contained invalid JSON") from None
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


class GmailConnector:
    """Read-only Gmail messages.list/messages.get connector."""

    SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"

    def __init__(
        self,
        token_provider: OAuth2RefreshTokenProvider,
        *,
        account_id: str,
        client: Any = None,
        max_response_bytes: int = 2_097_152,
    ) -> None:
        if not isinstance(account_id, str) or not account_id:
            raise ValueError("account_id must be non-empty")
        self.token_provider = token_provider
        self.account_id = account_id
        self.connector_id = "gmail:" + account_id
        self.http = _ProviderHTTPClient(client=client, max_response_bytes=max_response_bytes)

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": "Bearer " + _require_scope(self.token_provider, self.SCOPE)}

    def list_messages(
        self,
        *,
        query: Optional[str] = None,
        max_results: int = 100,
        page_token: Optional[str] = None,
        label_ids: Sequence[str] = (),
    ) -> ProviderPage:
        if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 500:
            raise ValueError("Gmail max_results must be between 1 and 500")
        params: Dict[str, Any] = {"maxResults": max_results}
        if query is not None:
            if not isinstance(query, str) or len(query) > 2_048:
                raise ValueError("Gmail query must be a bounded string")
            params["q"] = query
        if page_token is not None:
            if not isinstance(page_token, str) or not page_token or len(page_token) > 4_096:
                raise ValueError("Gmail page_token must be a bounded non-empty string")
            params["pageToken"] = page_token
        labels = tuple(label_ids)
        if len(labels) > 50 or any(not isinstance(x, str) or not x or len(x) > 256 for x in labels):
            raise ValueError("Gmail label_ids must be bounded non-empty strings")
        if labels:
            params["labelIds"] = list(labels)
        response = self.http.request_json("GET", self.BASE_URL + "/messages", headers=self._headers(), params=params)
        messages = response.get("messages", [])
        if not isinstance(messages, list):
            raise ProviderProtocolError("Gmail messages field was not a list")
        captures = []
        for item in messages:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ProviderProtocolError("Gmail returned a message without a valid identifier")
            message_id = item["id"]
            captures.append(
                ProviderCapture(
                    provider="gmail",
                    connector_id=self.connector_id,
                    object_id=f"gmail:{self.account_id}:message:{message_id}",
                    version_id=_version_id(item),
                    provider_version=str(item.get("threadId", "")),
                    value=item,
                )
            )
        next_cursor = response.get("nextPageToken")
        if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor) > 4_096):
            raise ProviderProtocolError("Gmail returned an invalid nextPageToken")
        return ProviderPage(tuple(captures), next_cursor)

    def get_message(self, message_id: str) -> ProviderCapture:
        if not isinstance(message_id, str) or not message_id or len(message_id) > 512:
            raise ValueError("Gmail message_id must be a bounded non-empty string")
        url = self.BASE_URL + "/messages/" + quote(message_id, safe="")
        response = self.http.request_json(
            "GET",
            url,
            headers=self._headers(),
            params={"format": "full"},
        )
        actual_id = response.get("id")
        if actual_id != message_id:
            raise ProviderProtocolError("Gmail returned a different message identifier")
        return ProviderCapture(
            provider="gmail",
            connector_id=self.connector_id,
            object_id=f"gmail:{self.account_id}:message:{message_id}",
            version_id=_version_id(response),
            provider_version=str(response.get("historyId", "")),
            value=response,
        )

    def close(self) -> None:
        self.http.close()


class MicrosoftGraphMailConnector:
    """Read-only Microsoft Graph /me/messages connector with safe nextLink handling."""

    BASE_URL = "https://graph.microsoft.com/v1.0"
    BASIC_SCOPE = "Mail.ReadBasic"
    READ_SCOPE = "Mail.Read"
    SELECT_BASIC = (
        "id", "conversationId", "subject", "from", "toRecipients",
        "receivedDateTime", "sentDateTime", "internetMessageId",
        "parentFolderId", "categories", "hasAttachments",
        "importance", "isRead", "changeKey",
    )
    SELECT_FULL = SELECT_BASIC + ("body", "uniqueBody")

    def __init__(
        self,
        token_provider: OAuth2RefreshTokenProvider,
        *,
        tenant_id: str,
        user_id: str,
        read_body: bool = False,
        client: Any = None,
        max_response_bytes: int = 2_097_152,
    ) -> None:
        for name, value in (("tenant_id", tenant_id), ("user_id", user_id)):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"{name} must be a bounded non-empty string")
        if not isinstance(token_provider, OAuth2RefreshTokenProvider):
            raise TypeError("Microsoft Graph requires an OAuth2RefreshTokenProvider")
        if not isinstance(read_body, bool):
            raise TypeError("read_body must be a boolean")
        self.token_provider = token_provider
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.read_body = read_body
        self.required_scope = self.READ_SCOPE if read_body else self.BASIC_SCOPE
        self.selected_fields = self.SELECT_FULL if read_body else self.SELECT_BASIC
        self.connector_id = f"microsoft-graph:{tenant_id}:{user_id}"
        self.http = _ProviderHTTPClient(client=client, max_response_bytes=max_response_bytes)

    def _headers(self) -> Dict[str, str]:
        token = _require_scope(self.token_provider, self.required_scope)
        return {"Authorization": "Bearer " + token}

    def _messages_url(self) -> str:
        return self.BASE_URL + "/me/messages"

    @staticmethod
    def _validate_next_link(next_link: str) -> str:
        parsed = urlparse(next_link) if isinstance(next_link, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != "graph.microsoft.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.path != "/v1.0/me/messages"
        ):
            raise ProviderProtocolError("Microsoft Graph returned an unsafe @odata.nextLink")
        return next_link

    def list_messages(
        self,
        *,
        top: int = 50,
        skip_token_url: Optional[str] = None,
        filter_query: Optional[str] = None,
    ) -> ProviderPage:
        if isinstance(top, bool) or not isinstance(top, int) or not 1 <= top <= 1_000:
            raise ValueError("Microsoft Graph top must be between 1 and 1000")
        url = self._messages_url()
        params: Optional[Dict[str, Any]]
        if skip_token_url is not None:
            url = self._validate_next_link(skip_token_url)
            params = None
        else:
            params = {
                "$top": top,
                "$select": ",".join(self.selected_fields),
            }
            if filter_query is not None:
                if not isinstance(filter_query, str) or len(filter_query) > 2_048:
                    raise ValueError("Microsoft Graph filter_query must be a bounded string")
                params["$filter"] = filter_query
        response = self.http.request_json("GET", url, headers=self._headers(), params=params)
        items = response.get("value", [])
        if not isinstance(items, list):
            raise ProviderProtocolError("Microsoft Graph value field was not a list")
        captures = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ProviderProtocolError("Microsoft Graph returned a message without an identifier")
            msg_id = item["id"]
            captures.append(
                ProviderCapture(
                    provider="microsoft_graph",
                    connector_id=self.connector_id,
                    object_id=f"graph:{self.tenant_id}:{self.user_id}:message:{msg_id}",
                    version_id=_version_id(item),
                    provider_version=str(item.get("@odata.etag") or item.get("changeKey") or ""),
                    value=item,
                )
            )
        next_link = response.get("@odata.nextLink")
        if next_link is not None:
            next_link = self._validate_next_link(next_link)
        return ProviderPage(tuple(captures), next_link)

    def get_message(self, message_id: str) -> ProviderCapture:
        if not isinstance(message_id, str) or not message_id or len(message_id) > 512:
            raise ValueError("Microsoft Graph message_id must be a bounded non-empty string")
        url = self._messages_url() + "/" + quote(message_id, safe="")
        response = self.http.request_json(
            "GET",
            url,
            headers=self._headers(),
            params={"$select": ",".join(self.SELECT)},
        )
        if response.get("id") != message_id:
            raise ProviderProtocolError("Microsoft Graph returned a different message identifier")
        return ProviderCapture(
            provider="microsoft_graph",
            connector_id=self.connector_id,
            object_id=f"graph:{self.tenant_id}:{self.user_id}:message:{message_id}",
            version_id=_version_id(response),
            provider_version=str(response.get("@odata.etag") or response.get("changeKey") or ""),
            value=response,
        )

    def close(self) -> None:
        self.http.close()


class SlackHistoryConnector:
    """Read-only Slack conversations.history connector."""

    BASE_URL = "https://slack.com/api/conversations.history"
    HISTORY_SCOPES = frozenset({
        "channels:history", "groups:history", "im:history", "mpim:history",
    })

    def __init__(
        self,
        token_provider: OAuth2RefreshTokenProvider,
        *,
        workspace_id: str,
        history_scope: str = "channels:history",
        client: Any = None,
        max_response_bytes: int = 2_097_152,
    ) -> None:
        if not isinstance(workspace_id, str) or not workspace_id:
            raise ValueError("workspace_id must be non-empty")
        if history_scope not in self.HISTORY_SCOPES:
            raise ValueError("history_scope must be one of the approved Slack history scopes")
        if not isinstance(token_provider, OAuth2RefreshTokenProvider):
            raise TypeError("Slack history requires an OAuth2RefreshTokenProvider")
        self.token_provider = token_provider
        self.workspace_id = workspace_id
        self.history_scope = history_scope
        self.connector_id = "slack:" + workspace_id
        self.http = _ProviderHTTPClient(client=client, max_response_bytes=max_response_bytes)

    def history(
        self,
        channel_id: str,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        oldest: Optional[str] = None,
        latest: Optional[str] = None,
        inclusive: bool = False,
    ) -> ProviderPage:
        if not isinstance(channel_id, str) or not channel_id or len(channel_id) > 256:
            raise ValueError("Slack channel_id must be bounded and non-empty")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("Slack history limit must be between 1 and 200")
        if not isinstance(inclusive, bool):
            raise TypeError("inclusive must be a boolean")
        body: Dict[str, Any] = {"channel": channel_id, "limit": limit, "inclusive": inclusive}
        for name, value in (("cursor", cursor), ("oldest", oldest), ("latest", latest)):
            if value is not None:
                if not isinstance(value, str) or not value or len(value) > 4_096:
                    raise ValueError(f"Slack {name} must be a bounded non-empty string")
                body[name] = value
        token = _require_scope(self.token_provider, self.history_scope)
        response = self.http.request_json(
            "POST",
            self.BASE_URL,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json; charset=utf-8",
            },
            json_body=body,
        )
        if response.get("ok") is not True:
            # Slack returns a provider error string; do not include arbitrary
            # response payloads or request credentials in exception text.
            error = response.get("error")
            safe_error = error if isinstance(error, str) and re.fullmatch(r"[a-z0-9_]{1,80}", error) else "provider_error"
            raise ProviderConnectorError("Slack conversations.history failed: " + safe_error)
        messages = response.get("messages", [])
        if not isinstance(messages, list):
            raise ProviderProtocolError("Slack messages field was not a list")
        captures = []
        for item in messages:
            if not isinstance(item, dict) or not isinstance(item.get("ts"), str):
                raise ProviderProtocolError("Slack returned a message without a timestamp")
            ts = item["ts"]
            captures.append(
                ProviderCapture(
                    provider="slack",
                    connector_id=self.connector_id,
                    object_id=f"slack:{self.workspace_id}:{channel_id}:{ts}",
                    version_id=_version_id(item),
                    provider_version=str(item.get("edited", {}).get("ts", ts)) if isinstance(item.get("edited"), dict) else ts,
                    value={"channel": channel_id, **item},
                )
            )
        metadata = response.get("response_metadata", {})
        if metadata is not None and not isinstance(metadata, dict):
            raise ProviderProtocolError("Slack response_metadata was malformed")
        next_cursor = metadata.get("next_cursor") if isinstance(metadata, dict) else None
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ProviderProtocolError("Slack next_cursor was invalid")
        return ProviderPage(tuple(captures), next_cursor or None)

    def close(self) -> None:
        self.http.close()


class QdrantVectorConnector:
    """Read-only Qdrant search connector using an injected API-key provider."""

    def __init__(
        self,
        base_url: str,
        *,
        cluster_id: str,
        api_key_provider: Callable[[], str],
        client: Any = None,
        max_response_bytes: int = 2_097_152,
        allow_insecure_localhost: bool = False,
    ) -> None:
        parsed = urlparse(base_url) if isinstance(base_url, str) else None
        local_http = (
            allow_insecure_localhost
            and parsed is not None
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if (
            parsed is None
            or (parsed.scheme != "https" and not local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Qdrant base_url must be a fixed HTTPS origin")
        if not isinstance(cluster_id, str) or not cluster_id:
            raise ValueError("cluster_id must be non-empty")
        if not callable(api_key_provider):
            raise TypeError("api_key_provider must be a callable secret provider")
        self.base_url = base_url.rstrip("/")
        self.cluster_id = cluster_id
        self.connector_id = "qdrant:" + cluster_id
        self.api_key_provider = api_key_provider
        self.http = _ProviderHTTPClient(
            client=client,
            max_response_bytes=max_response_bytes,
            allow_insecure_localhost=allow_insecure_localhost,
        )

    def search(
        self,
        collection: str,
        vector: Sequence[float],
        *,
        limit: int = 10,
        query_filter: Optional[Mapping[str, Any]] = None,
        with_payload: bool = True,
    ) -> ProviderPage:
        if not isinstance(collection, str) or not collection or len(collection) > 256:
            raise ValueError("Qdrant collection must be bounded and non-empty")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("Qdrant search limit must be between 1 and 200")
        if not isinstance(with_payload, bool):
            raise TypeError("with_payload must be a boolean")
        if not isinstance(vector, Sequence) or isinstance(vector, (str, bytes)) or not vector or len(vector) > 65_536:
            raise ValueError("Qdrant vector must be a bounded non-empty sequence")
        values = []
        for value in vector:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("Qdrant vector entries must be finite numbers")
            values.append(float(value))
        body: Dict[str, Any] = {
            "vector": values,
            "limit": limit,
            "with_payload": with_payload,
            "with_vector": False,
        }
        if query_filter is not None:
            if not isinstance(query_filter, Mapping):
                raise TypeError("Qdrant query_filter must be a mapping")
            try:
                encoded_filter = json.dumps(
                    query_filter, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError):
                raise ValueError("Qdrant filter must be canonical JSON") from None
            if len(encoded_filter) > 32_768:
                raise ValueError("Qdrant query_filter is too large")
            body["filter"] = dict(query_filter)
        key = self.api_key_provider()
        if not isinstance(key, str) or not key:
            raise ProviderAuthenticationError("Qdrant API key provider returned no key")
        url = self.base_url + "/collections/" + quote(collection, safe="") + "/points/search"
        response = self.http.request_json(
            "POST",
            url,
            headers={"api-key": key, "Content-Type": "application/json"},
            json_body=body,
        )
        result = response.get("result", [])
        if not isinstance(result, list):
            raise ProviderProtocolError("Qdrant result field was not a list")
        captures = []
        for item in result:
            if not isinstance(item, dict) or "id" not in item:
                raise ProviderProtocolError("Qdrant returned a point without an identifier")
            point_id = str(item["id"])
            captures.append(
                ProviderCapture(
                    provider="qdrant",
                    connector_id=self.connector_id,
                    object_id=f"qdrant:{self.cluster_id}:{collection}:{point_id}",
                    version_id=_version_id(item),
                    provider_version=str(item.get("version", "")),
                    value={"collection": collection, **item},
                )
            )
        return ProviderPage(tuple(captures), None)

    def close(self) -> None:
        self.http.close()


__all__ = [
    "GmailConnector",
    "MicrosoftGraphMailConnector",
    "OAuth2RefreshTokenProvider",
    "OAuthAccessToken",
    "ProviderAuthenticationError",
    "ProviderCapture",
    "ProviderConnectorError",
    "ProviderPage",
    "ProviderProtocolError",
    "ProviderResponseTooLarge",
    "ProviderScopeError",
    "QdrantVectorConnector",
    "SlackHistoryConnector",
]
