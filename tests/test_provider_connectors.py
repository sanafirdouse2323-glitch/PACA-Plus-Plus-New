from __future__ import annotations

import hashlib
import json
import urllib.parse

import httpx
import pytest

from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
from paca.durable import SQLiteProvenanceRepository
from paca.integrations.providers import (
    GmailConnector,
    MicrosoftGraphMailConnector,
    OAuth2RefreshTokenProvider,
    ProviderAuthenticationError,
    ProviderCapture,
    ProviderConnectorError,
    ProviderProtocolError,
    ProviderResponseTooLarge,
    ProviderScopeError,
    QdrantVectorConnector,
    SlackHistoryConnector,
)
from paca.memory import (
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
    canonical_value_bytes,
)


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
        assert request.headers["content-type"].startswith(
            "application/x-www-form-urlencoded"
        )
        form = urllib.parse.parse_qs(request.content.decode())
        assert form["client_id"] == ["client-id"]
        assert form["client_secret"] == ["client-secret"]
        assert form["refresh_token"] == [
            "refresh-secret" if not calls else "rotated-refresh-secret"
        ]
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
                "refresh_token": (
                    "rotated-refresh-secret"
                    if len(calls) == 1
                    else "second-rotated-refresh-secret"
                ),
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
        assert rotations == [
            "rotated-refresh-secret",
            "second-rotated-refresh-secret",
        ]
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
        return httpx.Response(
            302, headers={"location": "https://attacker.example/steal"}
        )

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

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
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

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
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


def test_microsoft_graph_body_fields_require_explicit_mail_read_scope():
    requests = []

    def oauth_handler(_request):
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "graph-full-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": MicrosoftGraphMailConnector.READ_SCOPE,
            },
        )

    def graph_handler(request):
        requests.append(request)
        selected = set(request.url.params["$select"].split(","))
        assert "body" in selected and "uniqueBody" in selected
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "value": [
                    {
                        "id": "message-with-body",
                        "body": {"contentType": "text", "content": "untrusted content"},
                    }
                ]
            },
        )

    client = httpx.Client(
        transport=httpx.MockTransport(graph_handler), follow_redirects=False
    )
    provider, token_client = _oauth_provider(
        oauth_handler,
        scopes={MicrosoftGraphMailConnector.READ_SCOPE},
    )
    connector = MicrosoftGraphMailConnector(
        provider,
        tenant_id="tenant-1",
        user_id="user-1",
        read_body=True,
        client=client,
    )
    try:
        page = connector.list_messages()
        assert page.items[0].value["body"]["content"] == "untrusted content"
        assert len(requests) == 1
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_microsoft_graph_body_scope_is_not_silently_escalated():
    def handler(_request):
        pytest.fail(
            "Mail.Read must not be requested with a Mail.ReadBasic consent grant"
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    provider, token_client = _oauth_provider(
        handler,
        scopes={MicrosoftGraphMailConnector.BASIC_SCOPE},
    )
    connector = MicrosoftGraphMailConnector(
        provider,
        tenant_id="tenant-1",
        user_id="user-1",
        read_body=True,
        client=client,
    )
    try:
        with pytest.raises(ProviderScopeError, match="does not include"):
            connector.list_messages()
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

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
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
                "messages": [
                    {
                        "ts": "1710000000.000001",
                        "text": "untrusted message",
                        "channel": "C-ATTACKER-SUPPLIED",
                    }
                ],
                "response_metadata": {"next_cursor": "cursor-next"},
            },
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
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
        assert page.items[0].value["channel"] == "C123"
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


def test_qdrant_search_enforces_tenant_filter_and_validates_returned_payload():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["api-key"] == "qdrant-secret"
        assert request.url.path.endswith("/collections/reports/points/search")
        body = json.loads(request.content)
        assert body["vector"] == [0.1, 0.2]
        assert body["with_payload"] is True
        assert body["filter"]["must"][0] == {
            "key": "tenant_id",
            "match": {"value": "tenant-acme"},
        }
        assert body["filter"]["must"][1] == {
            "must": [{"key": "kind", "match": {"value": "report"}}],
        }
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "result": [
                    {
                        "id": "point-1",
                        "version": 12,
                        "score": 0.91,
                        "payload": {"text": "external", "tenant_id": "tenant-acme"},
                    }
                ]
            },
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    connector = QdrantVectorConnector(
        "https://qdrant.example.test",
        cluster_id="cluster-1",
        tenant_id="tenant-acme",
        api_key_provider=lambda: "qdrant-secret",
        client=client,
    )
    try:
        page = connector.search(
            "reports",
            [0.1, 0.2],
            limit=10,
            query_filter={"must": [{"key": "kind", "match": {"value": "report"}}]},
        )
        assert page.items[0].object_id == "qdrant:cluster-1:reports:point-1"
        assert page.items[0].provider_version == "12"
        assert page.items[0].value["tenant_id"] == "tenant-acme"
        with pytest.raises(ValueError, match="finite numbers"):
            connector.search("reports", [float("nan")])
        with pytest.raises(ValueError, match="with_payload=True"):
            connector.search("reports", [0.1], with_payload=False)
        assert len(calls) == 1
    finally:
        connector.close()
        client.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"tenant_id": "tenant-other", "text": "foreign point"},
        {"text": "missing tenant marker"},
    ],
)
def test_qdrant_rejects_foreign_or_unverifiable_tenant_results(payload):
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"result": [{"id": "foreign-point", "payload": payload}]},
            )
        ),
        follow_redirects=False,
    )
    connector = QdrantVectorConnector(
        "https://qdrant.example.test",
        cluster_id="cluster-1",
        tenant_id="tenant-acme",
        api_key_provider=lambda: "qdrant-secret",
        client=client,
    )
    try:
        with pytest.raises(ProviderProtocolError, match="tenant"):
            connector.search("reports", [0.1, 0.2])
    finally:
        connector.close()
        client.close()


def test_qdrant_caller_filter_cannot_negate_mandatory_tenant_condition():
    observed = []

    def handler(request):
        body = json.loads(request.content)
        observed.append(body["filter"])
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"result": []},
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    connector = QdrantVectorConnector(
        "https://qdrant.example.test",
        cluster_id="cluster-1",
        tenant_id="tenant-acme",
        api_key_provider=lambda: "qdrant-secret",
        client=client,
    )
    try:
        page = connector.search(
            "reports",
            [0.1, 0.2],
            query_filter={
                "must_not": [
                    {"key": "tenant_id", "match": {"value": "tenant-acme"}},
                ],
            },
        )
        assert page.items == ()
        assert observed == [
            {
                "must": [
                    {"key": "tenant_id", "match": {"value": "tenant-acme"}},
                    {
                        "must_not": [
                            {"key": "tenant_id", "match": {"value": "tenant-acme"}},
                        ],
                    },
                ],
            }
        ]
    finally:
        connector.close()
        client.close()


def test_provider_capture_persists_only_through_matching_untrusted_ingress(tmp_path):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="provider-ingress-test",
        key_id="provider-ingress-key",
        key=b"P" * 32,
        audience="provider-ingress-runtime",
        identity_verifier=lambda principal, tenant: (
            principal == "agent-a" and tenant == "acme"
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and task_id == "task-provider"
            and purpose == "review-mail"
        ),
        clock=clock,
    )
    provider_object_id = "gmail:account-1:message:message-1"
    root = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-provider",
        purpose="review-mail",
        grants={
            "mem_write": (provider_object_id,),
            "mem_read": (provider_object_id,),
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
    capture_value = {"id": "message-1", "snippet": "external prompt injection"}
    capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id=provider_object_id,
        version_id=hashlib.sha256(canonical_value_bytes(capture_value)).hexdigest(),
        provider_version="history-77",
        value=capture_value,
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
    assert (
        node.content_digest
        == hashlib.sha256(
            canonical_value_bytes(
                {
                    "provider": "gmail",
                    "provider_version": "history-77",
                    "record": {
                        "id": "message-1",
                        "snippet": "external prompt injection",
                    },
                }
            )
        ).hexdigest()
    )

    mutable_value = {"id": "message-2", "snippet": "original provider text"}
    mutable_capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-2",
        version_id=hashlib.sha256(canonical_value_bytes(mutable_value)).hexdigest(),
        provider_version="history-78",
        value=mutable_value,
    )
    mutable_value["snippet"] = "tampered after capture"
    with pytest.raises(ProviderAuthenticationError, match="changed after capture"):
        mutable_capture.persist(
            connector,
            purpose="review-mail",
            capability_token=root.token,
        )

    trusted_connector = TrustedConnectorAdapter(
        memory,
        connector_id="gmail:account-1",
        source_class="external_content",
        tenant="acme",
        sensitivity=1,
        integrity="trusted",
    )
    with pytest.raises(ProviderAuthenticationError, match="untrusted external-content"):
        capture.persist(
            trusted_connector,
            purpose="review-mail",
            capability_token=root.token,
        )

    # A connector ID is not sufficient to relabel a Qdrant record for a
    # different tenant: the verified Qdrant tenant must match the memory adapter.
    qdrant_value = {"tenant_id": "globex", "payload": {"text": "foreign"}}
    qdrant_capture = ProviderCapture(
        provider="qdrant",
        connector_id="qdrant:cluster-1:tenant:acme",
        object_id="qdrant:cluster-1:reports:foreign-point",
        version_id=hashlib.sha256(canonical_value_bytes(qdrant_value)).hexdigest(),
        provider_version="1",
        value=qdrant_value,
    )
    qdrant_memory_connector = TrustedConnectorAdapter(
        memory,
        connector_id="qdrant:cluster-1:tenant:acme",
        source_class="external_content",
        tenant="acme",
        sensitivity=1,
        integrity="untrusted",
    )
    with pytest.raises(ProviderAuthenticationError, match="capture tenant"):
        qdrant_capture.persist(
            qdrant_memory_connector,
            purpose="review-mail",
            capability_token=root.token,
        )


def test_provider_http_client_rejects_redirect_and_oversized_json():
    from paca.integrations.providers import _ProviderHTTPClient

    redirect_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                302, headers={"location": "https://attacker.example/collect"}
            )
        ),
        follow_redirects=False,
    )
    wrapper = _ProviderHTTPClient(client=redirect_client)
    try:
        with pytest.raises(ProviderConnectorError, match="redirects are refused"):
            wrapper.request_json(
                "GET",
                "https://provider.example.test/data",
                headers={},
            )
    finally:
        wrapper.close()
        redirect_client.close()

    large_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"payload":"' + (b"x" * 2_000) + b'"}',
            )
        ),
        follow_redirects=False,
    )
    wrapper = _ProviderHTTPClient(client=large_client, max_response_bytes=1_024)
    try:
        with pytest.raises(ProviderResponseTooLarge):
            wrapper.request_json(
                "GET",
                "https://provider.example.test/data",
                headers={},
            )
    finally:
        wrapper.close()
        large_client.close()


def test_provider_capture_repr_redacts_provider_content():
    capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-1",
        version_id=hashlib.sha256(
            canonical_value_bytes({"body": "sensitive message body"})
        ).hexdigest(),
        provider_version="1",
        value={"body": "sensitive message body"},
    )
    assert "sensitive message body" not in repr(capture)
    assert "value=<redacted>" in repr(capture)


def test_provider_capture_rejects_wrong_or_trusted_ingress_adapter():
    capture = ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-1",
        version_id=hashlib.sha256(
            canonical_value_bytes({"id": "message-1"})
        ).hexdigest(),
        provider_version="1",
        value={"id": "message-1"},
    )

    class FakeConnector:
        connector_id = "gmail:account-1"
        integrity = "untrusted"
        source_class = "external_content"

    with pytest.raises(TypeError, match="TrustedConnectorAdapter"):
        capture.persist(
            FakeConnector(), purpose="review-mail", capability_token="unused"
        )


@pytest.mark.parametrize(
    ("read_body", "expected_scope", "body_selected"),
    [
        (False, MicrosoftGraphMailConnector.BASIC_SCOPE, False),
        (True, MicrosoftGraphMailConnector.READ_SCOPE, True),
    ],
)
def test_microsoft_graph_get_message_uses_the_configured_least_privilege_scope(
    read_body, expected_scope, body_selected
):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        assert request.url.path.endswith("/me/messages/message-1")
        selected = set(request.url.params["$select"].split(","))
        assert ("body" in selected) is body_selected
        assert ("uniqueBody" in selected) is body_selected
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "id": "message-1",
                "subject": "untrusted",
                "body": {"content": "external"},
            },
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    provider, token_client = _oauth_provider(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "access_token": "graph-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": expected_scope,
            },
        ),
        scopes={expected_scope},
    )
    connector = MicrosoftGraphMailConnector(
        provider,
        tenant_id="tenant-1",
        user_id="user-1",
        read_body=read_body,
        client=client,
    )
    try:
        capture = connector.get_message("message-1")
        assert capture.object_id == "graph:tenant-1:user-1:message:message-1"
        assert capture.value["id"] == "message-1"
        assert len(requests) == 1
    finally:
        connector.close()
        client.close()
        provider.close()
        token_client.close()


def test_qdrant_api_key_provider_errors_do_not_leak_secret_material():
    def secret_provider():
        raise RuntimeError("backend failed while handling api-key=top-secret-value")

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: pytest.fail(
                "request must not run when secret retrieval fails"
            )
        ),
        follow_redirects=False,
    )
    connector = QdrantVectorConnector(
        "https://qdrant.example.test",
        cluster_id="cluster-1",
        tenant_id="tenant-acme",
        api_key_provider=secret_provider,
        client=client,
    )
    try:
        with pytest.raises(ProviderAuthenticationError) as error:
            connector.search("reports", [0.1, 0.2])
        assert "top-secret-value" not in str(error.value)
        assert "top-secret-value" not in repr(error.value)
    finally:
        connector.close()
        client.close()
