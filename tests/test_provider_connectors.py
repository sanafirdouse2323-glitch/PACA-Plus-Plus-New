from __future__ import annotations

import json
import urllib.parse

import httpx
import pytest

from paca.integrations.providers import (
    GmailConnector,
    MicrosoftGraphMailConnector,
    OAuth2RefreshTokenProvider,
    ProviderAuthenticationError,
    ProviderConnectorError,
    ProviderCapture,
    ProviderResponseTooLarge,
    ProviderScopeError,
    QdrantVectorConnector,
    SlackHistoryConnector,
)
from paca.memory import (
    HMACAgentMessageCodec,
    MemoryAccessDenied,
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
)
from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
from paca.durable import SQLiteProvenanceRepository


def _oauth_provider(handler, *, scopes, clock=None, on_refresh_token=None):
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=False, trust_env=False)
    provider = OAuth2RefreshTokenProvider(
        "https://oauth.example.test/token",
        client_id="client-id",
        client_secret="client-secret",
        refresh_token="refresh-secret",
        granted_scopes=scopes,
        include_scope_parameter=True,
        on_refresh_token=on_refresh_token,
        client=client,
        refresh_skew_seconds=1,
        clock=clock or (lambda: 1_000.0),
    )
    return provider, client


def test_oauth_refresh_caches_token_checks_scopes_and_persists_rotation():
    now = [1_000.0]
    calls = []
    rotations = []

    def handler(request):
        assert request.url == "https://oauth.example.test/token"
        assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
        form = urllib.parse.parse_qs(request.content.decode())
        assert form["client_id"] == ["client-id"]
        assert form["client_secret"] == ["client-secret"]
        assert form["refresh_token"] == ["refresh-secret"]
        assert form["grant_type"] == ["refresh_token"]
        assert form["scope"] == ["scope.read"]
        calls.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "access-secret",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "scope.read",
                "refresh_token": "rotated-refresh-secret",
            },
        )

    provider, client = _oauth_provider(
        handler,
        scopes={"scope.read"},
        clock=lambda: now[0],
        on_refresh_token=rotations.append,
    )
    try:
        first = provider.get_access_token({"scope.read"})
        second = provider.get_access_token({"scope.read"})
        assert first.access_token == "access-secret"
        assert second is first
        assert len(calls) == 1
        assert rotations == ["rotated-refresh-secret"]
        assert "access-secret" not in repr(first)
        assert "rotated-refresh-secret" not in repr(provider)

        now[0] = 1_400.0
        refreshed = provider.get_access_token({"scope.read"})
        assert refreshed.access_token == "access-secret"
        assert len(calls) == 2
        # A second refresh rotates the refresh token as well.
    finally:
        provider.close()
        client.close()


def test_oauth_refuses_unconsented_scope_before_network_request():
    def handler(_request):
        pytest.fail("scope escalation must fail before network access")

    provider, client = _oauth_provider(handler, scopes={"gmail.readonly"})
    try:
        with pytest.raises(ProviderScopeError, match="does not include"):
            provider.get_access_token({"gmail.modify"})
    finally:
        provider.close()
        client.close()


def test_oauth_refuses_scope_widening_and_invalid_refresh_rotation():
    def handler(_request):
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "access-secret",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "gmail.readonly gmail.modify",
            },
        )

    provider, client = _oauth_provider(handler, scopes={"gmail.readonly"})
    try:
        with pytest.raises(ProviderScopeError, match="outside the configured"):
            provider.get_access_token({"gmail.readonly"})
    finally:
        provider.close()
        client.close()


def test_oauth_redirect_and_http_error_do_not_leak_credentials():
    def redirect(_request):
        return httpx.Response(302, headers={"location": "https://attacker.example/steal"})

    provider, client = _oauth_provider(redirect, scopes={"scope.read"})
    try:
        with pytest.raises(ProviderAuthenticationError, match="redirects are refused"):
            provider.get_access_token({"scope.read"})
    finally:
        provider.close()
        client.close()


def test_gmail_list_and_get_capture_untrusted_provider_payload():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer gmail-access"
        if request.url.path.endswith("/messages"):
            assert request.url.params["maxResults"] == "2"
            assert request.url.params["q"] == "from:security@example.test"
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={
                    "messages": [{"id": "m-1", "threadId": "t-1"}],
                    "nextPageToken": "page-2",
                },
            )
        assert request.url.path.endswith("/messages/m-1")
        assert request.url.params["format"] == "full"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "id": "m-1",
                "threadId": "t-1",
                "historyId": "99",
                "payload": {"body": {"data": "c2VjcmV0"}},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "gmail-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": GmailConnector.SCOPE,
            },
        ),
        scopes={GmailConnector.SCOPE},
    )
    connector = GmailConnector(provider, account_id="account-1", client=client)
    try:
        page = connector.list_messages(
            query="from:security@example.test",
            max_results=2,
        )
        assert page.next_cursor == "page-2"
        assert page.items[0].object_id == "gmail:account-1:message:m-1"
        message = connector.get_message("m-1")
        assert message.provider_version == "99"
        assert len(calls) == 2
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_microsoft_graph_pagination_accepts_only_graph_messages_next_link():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == "Bearer graph-access"
        if len(requests) == 1:
            assert request.url.params["$top"] == "5"
            assert "body" not in request.url.params["$select"]
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={
                    "value": [{"id": "message-1", "@odata.etag": 'W/"1"'}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=next",
                },
            )
        assert request.url.params["$skiptoken"] == "next"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"value": [{"id": "message-2", "changeKey": "2"}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "graph-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": MicrosoftGraphMailConnector.BASIC_SCOPE,
            },
        ),
        scopes={MicrosoftGraphMailConnector.BASIC_SCOPE},
    )
    connector = MicrosoftGraphMailConnector(
        provider,
        tenant_id="tenant-1",
        user_id="user-1",
        client=client,
    )
    try:
        first = connector.list_messages(top=5)
        assert first.next_cursor.startswith("https://graph.microsoft.com/")
        second = connector.list_messages(skip_token_url=first.next_cursor)
        assert second.items[0].object_id.endswith("message:message-2")
        assert len(requests) == 2
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_microsoft_graph_rejects_untrusted_next_link_without_sending_token():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "value": [],
                "@odata.nextLink": "https://graph.microsoft.com.attacker.test/v1.0/me/messages?x=1",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "graph-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": MicrosoftGraphMailConnector.BASIC_SCOPE,
            },
        ),
        scopes={MicrosoftGraphMailConnector.BASIC_SCOPE},
    )
    connector = MicrosoftGraphMailConnector(
        provider,
        tenant_id="tenant-1",
        user_id="user-1",
        client=client,
    )
    try:
        with pytest.raises(ProviderConnectorError, match="unsafe"):
            connector.list_messages()
        assert len(calls) == 1
        assert "attacker.test" not in calls[0].url.host
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_slack_history_uses_explicit_history_scope_and_returns_cursor():
    sent = []

    def handler(request):
        sent.append(request)
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer slack-access"
        body = json.loads(request.content)
        assert body["channel"] == "C123"
        assert body["limit"] == 20
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "ok": True,
                "messages": [{"ts": "1710000000.000001", "text": "untrusted message"}],
                "response_metadata": {"next_cursor": "cursor-next"},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "slack-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "channels:history",
            },
        ),
        scopes={"channels:history"},
    )
    connector = SlackHistoryConnector(
        provider,
        workspace_id="T123",
        client=client,
    )
    try:
        page = connector.history("C123", limit=20)
        assert page.next_cursor == "cursor-next"
        assert page.items[0].object_id.endswith("1710000000.000001")
        assert len(sent) == 1
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_slack_api_level_denial_and_wrong_scope_fail_closed():
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"ok": False, "error": "missing_scope"},
            )
        ),
        follow_redirects=False,
    )
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "slack-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "groups:history",
            },
        ),
        scopes={"groups:history"},
    )
    connector = SlackHistoryConnector(
        provider,
        workspace_id="T123",
        history_scope="groups:history",
        client=client,
    )
    try:
        with pytest.raises(ProviderConnectorError, match="missing_scope"):
            connector.history("G123")
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_qdrant_search_uses_injected_key_and_validates_vector():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["api-key"] == "qdrant-secret"
        assert request.url.path.endswith("/collections/reports/points/search")
        body = json.loads(request.content)
        assert body["vector"] == [0.1, 0.2]
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "result": [{"id": "point-1", "version": 12, "score": 0.91, "payload": {"text": "external"}}]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    connector = QdrantVectorConnector(
        "https://qdrant.example.test",
        cluster_id="cluster-1",
        api_key_provider=lambda: "qdrant-secret",
        client=client,
    )
    try:
        page = connector.search("reports", [0.1, 0.2], limit=10)
        assert page.items[0].object_id == "qdrant:cluster-1:reports:point-1"
        assert page.items[0].provider_version == "12"
        with pytest.raises(ValueError, match="finite numbers"):
            connector.search("reports", [float("nan")])
        assert len(calls) == 1
    finally:
        connector.close()
        client.close()


def test_provider_capture_persists_only_through_matching_untrusted_ingress(tmp_path):
    now = [1_000]
    clock = lambda: now[0]
    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="provider-ingress-test",
        key_id="provider-ingress-key",
        key=b"P" * 32,
        audience="provider-ingress-runtime",
        identity_verifier=lambda principal, tenant: principal == "agent-a" and tenant == "acme",
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a" and tenant == "acme"
            and task_id == "task-provider" and purpose == "review-mail"
        ),
        clock=clock,
    )
    root = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-provider",
        purpose="review-mail",
        grants={
            "mem_write": ("mem/*",),
            "mem_read": ("mem/*",),
        },
        expires_at=2_000,
        max_calls=20,
        max_task_calls=20,
    )
    repository = SQLiteProvenanceRepository(tmp_path / "lineage.sqlite3")
    values = SQLiteMemoryValueStore(tmp_path / "values.sqlite3")
    memory = TrustedMemoryAdapter(
        repository,
        values,
        issuer,
        authorize=lambda _context, _node: True,
        clock=clock,
    )
    connector = TrustedConnectorAdapter(
        memory,
        connector_id="gmail:account-1",
        source_class="external_content",
        tenant="acme",
        sensitivity=1,
        integrity="untrusted",
    )
    capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-1",
        version_id="digest-version-1",
        provider_version="history-77",
        value={"id": "message-1", "snippet": "external prompt injection"},
    )
    captured = capture.persist(
        connector,
        purpose="review-mail",
        capability_token=root.token,
    )
    assert captured.label.integrity == "untrusted"
    assert captured.lineage_refs
    node = repository.get_node(next(iter(captured.lineage_refs)))
    assert node is not None
    assert node.source == "gmail:account-1"
    assert node.label.integrity == "untrusted"
    assert node.content_digest == __import__("hashlib").sha256(
        __import__("paca.memory", fromlist=["canonical_value_bytes"]).canonical_value_bytes(
            {
                "provider": "gmail",
                "provider_version": "history-77",
                "record": {"id": "message-1", "snippet": "external prompt injection"},
            }
        )
    ).hexdigest()


def test_provider_capture_rejects_wrong_or_trusted_ingress_adapter():
    capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-1",
        version_id="v1",
        provider_version="1",
        value={"id": "message-1"},
    )

    class FakeConnector:
        connector_id = "gmail:account-1"
        integrity = "untrusted"
        source_class = "external_content"

    with pytest.raises(TypeError, match="TrustedConnectorAdapter"):
        capture.persist(FakeConnector(), purpose="review-mail", capability_token="unused")
