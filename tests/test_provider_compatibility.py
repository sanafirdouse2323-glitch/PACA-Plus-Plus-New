from __future__ import annotations

import importlib
import pickle

from paca.integrations import providers

integrations = importlib.import_module("paca.integrations")


PUBLIC_TYPES = (
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
)


def test_provider_public_imports_and_pickle_names_are_stable() -> None:
    for name in PUBLIC_TYPES:
        provider_type = getattr(providers, name)
        assert getattr(paca.integrations, name) is provider_type
        assert provider_type.__module__ == "paca.integrations.providers"
        assert pickle.loads(pickle.dumps(provider_type)) is provider_type


def test_provider_capture_and_page_instances_remain_pickle_compatible() -> None:
    token = providers.OAuthAccessToken(
        "test-access-token",
        "Bearer",
        frozenset({"scope.read"}),
        1_000.0,
    )
    capture = providers.ProviderCapture(
        provider="gmail",
        connector_id="gmail:account-1",
        object_id="gmail:account-1:message:message-1",
        version_id="a" * 64,
        provider_version="thread-1",
        value={"id": "message-1"},
    )
    page = providers.ProviderPage((capture,), "next-page")

    for value in (token, capture, page):
        restored = pickle.loads(pickle.dumps(value))
        assert restored == value


def test_private_http_wrapper_remains_importable_from_compatibility_module() -> None:
    from paca.integrations.providers import _ProviderHTTPClient

    assert _ProviderHTTPClient.__name__ == "_ProviderHTTPClient"
