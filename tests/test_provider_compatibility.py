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
        assert getattr(integrations, name) is provider_type
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


def test_provider_connector_modules_reexport_through_legacy_facade() -> None:
    modules = {
        "GmailConnector": "paca.integrations.gmail",
        "MicrosoftGraphMailConnector": "paca.integrations.microsoft_graph",
        "SlackHistoryConnector": "paca.integrations.slack",
        "QdrantVectorConnector": "paca.integrations.qdrant",
    }
    for name, module_name in modules.items():
        provider_type = getattr(importlib.import_module(module_name), name)
        assert getattr(providers, name) is provider_type
        assert provider_type.__module__ == "paca.integrations.providers"
        assert pickle.loads(pickle.dumps(provider_type)) is provider_type


def test_shared_http_wrapper_is_exported_by_legacy_facade() -> None:
    from paca.integrations import provider_core
    from paca.integrations.providers import _ProviderHTTPClient

    assert _ProviderHTTPClient is provider_core._ProviderHTTPClient


def test_private_http_wrapper_remains_importable_from_compatibility_module() -> None:
    from paca.integrations.providers import _ProviderHTTPClient

    assert _ProviderHTTPClient.__name__ == "_ProviderHTTPClient"
