"""Read-only Microsoft Graph mail connector."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlparse

from .provider_core import (
    OAuth2RefreshTokenProvider,
    ProviderCapture,
    ProviderPage,
    ProviderProtocolError,
    _ProviderHTTPClient,
    _require_scope,
    _version_id,
)


class MicrosoftGraphMailConnector:
    """Read-only Microsoft Graph /me/messages connector with safe nextLink handling."""

    BASE_URL = "https://graph.microsoft.com/v1.0"
    BASIC_SCOPE = "Mail.ReadBasic"
    READ_SCOPE = "Mail.Read"
    SELECT_BASIC = (
        "id",
        "conversationId",
        "subject",
        "from",
        "toRecipients",
        "receivedDateTime",
        "sentDateTime",
        "internetMessageId",
        "parentFolderId",
        "categories",
        "hasAttachments",
        "importance",
        "isRead",
        "changeKey",
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
        self.http = _ProviderHTTPClient(
            client=client, max_response_bytes=max_response_bytes
        )

    def _headers(self) -> dict[str, str]:
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
            raise ProviderProtocolError(
                "Microsoft Graph returned an unsafe @odata.nextLink"
            )
        return next_link

    def list_messages(
        self,
        *,
        top: int = 50,
        skip_token_url: str | None = None,
        filter_query: str | None = None,
    ) -> ProviderPage:
        if isinstance(top, bool) or not isinstance(top, int) or not 1 <= top <= 1_000:
            raise ValueError("Microsoft Graph top must be between 1 and 1000")
        url = self._messages_url()
        params: dict[str, Any] | None
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
                    raise ValueError(
                        "Microsoft Graph filter_query must be a bounded string"
                    )
                params["$filter"] = filter_query
        response = self.http.request_json(
            "GET", url, headers=self._headers(), params=params
        )
        items = response.get("value", [])
        if not isinstance(items, list):
            raise ProviderProtocolError("Microsoft Graph value field was not a list")
        captures = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ProviderProtocolError(
                    "Microsoft Graph returned a message without an identifier"
                )
            msg_id = item["id"]
            captures.append(
                ProviderCapture(
                    provider="microsoft_graph",
                    connector_id=self.connector_id,
                    object_id=f"graph:{self.tenant_id}:{self.user_id}:message:{msg_id}",
                    version_id=_version_id(item),
                    provider_version=str(
                        item.get("@odata.etag") or item.get("changeKey") or ""
                    ),
                    value=item,
                )
            )
        next_link = response.get("@odata.nextLink")
        if next_link is not None:
            next_link = self._validate_next_link(next_link)
        return ProviderPage(tuple(captures), next_link)

    def get_message(self, message_id: str) -> ProviderCapture:
        if not isinstance(message_id, str) or not message_id or len(message_id) > 512:
            raise ValueError(
                "Microsoft Graph message_id must be a bounded non-empty string"
            )
        url = self._messages_url() + "/" + quote(message_id, safe="")
        response = self.http.request_json(
            "GET",
            url,
            headers=self._headers(),
            params={"$select": ",".join(self.selected_fields)},
        )
        if response.get("id") != message_id:
            raise ProviderProtocolError(
                "Microsoft Graph returned a different message identifier"
            )
        return ProviderCapture(
            provider="microsoft_graph",
            connector_id=self.connector_id,
            object_id=f"graph:{self.tenant_id}:{self.user_id}:message:{message_id}",
            version_id=_version_id(response),
            provider_version=str(
                response.get("@odata.etag") or response.get("changeKey") or ""
            ),
            value=response,
        )

    def close(self) -> None:
        self.http.close()

