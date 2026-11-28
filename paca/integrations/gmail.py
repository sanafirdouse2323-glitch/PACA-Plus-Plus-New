"""Read-only Gmail API connector."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from .provider_core import (
    OAuth2RefreshTokenProvider,
    ProviderCapture,
    ProviderPage,
    ProviderProtocolError,
    _ProviderHTTPClient,
    _require_scope,
    _version_id,
)


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
        self.http = _ProviderHTTPClient(
            client=client, max_response_bytes=max_response_bytes
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + _require_scope(self.token_provider, self.SCOPE)
        }

    def list_messages(
        self,
        *,
        query: str | None = None,
        max_results: int = 100,
        page_token: str | None = None,
        label_ids: Sequence[str] = (),
    ) -> ProviderPage:
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= 500
        ):
            raise ValueError("Gmail max_results must be between 1 and 500")
        params: dict[str, Any] = {"maxResults": max_results}
        if query is not None:
            if not isinstance(query, str) or len(query) > 2_048:
                raise ValueError("Gmail query must be a bounded string")
            params["q"] = query
        if page_token is not None:
            if (
                not isinstance(page_token, str)
                or not page_token
                or len(page_token) > 4_096
            ):
                raise ValueError("Gmail page_token must be a bounded non-empty string")
            params["pageToken"] = page_token
        labels = tuple(label_ids)
        if len(labels) > 50 or any(
            not isinstance(x, str) or not x or len(x) > 256 for x in labels
        ):
            raise ValueError("Gmail label_ids must be bounded non-empty strings")
        if labels:
            params["labelIds"] = list(labels)
        response = self.http.request_json(
            "GET", self.BASE_URL + "/messages", headers=self._headers(), params=params
        )
        messages = response.get("messages", [])
        if not isinstance(messages, list):
            raise ProviderProtocolError("Gmail messages field was not a list")
        captures = []
        for item in messages:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ProviderProtocolError(
                    "Gmail returned a message without a valid identifier"
                )
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
        if next_cursor is not None and (
            not isinstance(next_cursor, str) or len(next_cursor) > 4_096
        ):
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

