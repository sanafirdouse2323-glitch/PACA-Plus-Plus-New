"""Read-only Slack conversation history connector."""

from __future__ import annotations

import re
from typing import Any

from .provider_core import (
    OAuth2RefreshTokenProvider,
    ProviderCapture,
    ProviderConnectorError,
    ProviderPage,
    ProviderProtocolError,
    _ProviderHTTPClient,
    _require_scope,
    _version_id,
)


class SlackHistoryConnector:
    """Read-only Slack conversations.history connector."""

    BASE_URL = "https://slack.com/api/conversations.history"
    HISTORY_SCOPES = frozenset(
        {
            "channels:history",
            "groups:history",
            "im:history",
            "mpim:history",
        }
    )

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
            raise ValueError(
                "history_scope must be one of the approved Slack history scopes"
            )
        if not isinstance(token_provider, OAuth2RefreshTokenProvider):
            raise TypeError("Slack history requires an OAuth2RefreshTokenProvider")
        self.token_provider = token_provider
        self.workspace_id = workspace_id
        self.history_scope = history_scope
        self.connector_id = "slack:" + workspace_id
        self.http = _ProviderHTTPClient(
            client=client, max_response_bytes=max_response_bytes
        )

    def history(
        self,
        channel_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        oldest: str | None = None,
        latest: str | None = None,
        inclusive: bool = False,
    ) -> ProviderPage:
        if not isinstance(channel_id, str) or not channel_id or len(channel_id) > 256:
            raise ValueError("Slack channel_id must be bounded and non-empty")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("Slack history limit must be between 1 and 200")
        if not isinstance(inclusive, bool):
            raise TypeError("inclusive must be a boolean")
        body: dict[str, Any] = {
            "channel": channel_id,
            "limit": limit,
            "inclusive": inclusive,
        }
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
            safe_error = (
                error
                if isinstance(error, str) and re.fullmatch(r"[a-z0-9_]{1,80}", error)
                else "provider_error"
            )
            raise ProviderConnectorError(
                "Slack conversations.history failed: " + safe_error
            )
        messages = response.get("messages", [])
        if not isinstance(messages, list):
            raise ProviderProtocolError("Slack messages field was not a list")
        captures = []
        for item in messages:
            if not isinstance(item, dict) or not isinstance(item.get("ts"), str):
                raise ProviderProtocolError(
                    "Slack returned a message without a timestamp"
                )
            ts = item["ts"]
            captured_value = {**item, "channel": channel_id}
            captures.append(
                ProviderCapture(
                    provider="slack",
                    connector_id=self.connector_id,
                    object_id=f"slack:{self.workspace_id}:{channel_id}:{ts}",
                    version_id=_version_id(captured_value),
                    provider_version=str(item.get("edited", {}).get("ts", ts))
                    if isinstance(item.get("edited"), dict)
                    else ts,
                    value=captured_value,
                )
            )
        metadata = response.get("response_metadata", {})
        if metadata is not None and not isinstance(metadata, dict):
            raise ProviderProtocolError("Slack response_metadata was malformed")
        next_cursor = (
            metadata.get("next_cursor") if isinstance(metadata, dict) else None
        )
        if next_cursor is not None and (
            not isinstance(next_cursor, str) or len(next_cursor) > 4_096
        ):
            raise ProviderProtocolError("Slack next_cursor was invalid")
        return ProviderPage(tuple(captures), next_cursor or None)

    def close(self) -> None:
        self.http.close()
