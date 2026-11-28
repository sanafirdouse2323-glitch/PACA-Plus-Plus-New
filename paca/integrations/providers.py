"""Compatibility exports for the focused read-only provider adapters.

Shared OAuth, HTTP and provenance-capture primitives live in provider_core.py.
Provider-specific request and response handling lives in its own module.
"""

from .gmail import GmailConnector
from .microsoft_graph import MicrosoftGraphMailConnector
from .provider_core import (
    OAuthAccessToken,
    OAuth2RefreshTokenProvider,
    ProviderAuthenticationError,
    ProviderCapture,
    ProviderConnectorError,
    ProviderPage,
    ProviderProtocolError,
    ProviderResponseTooLarge,
    ProviderScopeError,
    _ProviderHTTPClient as _ProviderHTTPClient,
)
from .qdrant import QdrantVectorConnector
from .slack import SlackHistoryConnector

# Preserve the historical module path for public classes, reprs and pickles.
for _provider_type in (
    GmailConnector,
    MicrosoftGraphMailConnector,
    OAuth2RefreshTokenProvider,
    OAuthAccessToken,
    ProviderAuthenticationError,
    ProviderCapture,
    ProviderConnectorError,
    ProviderPage,
    ProviderProtocolError,
    ProviderResponseTooLarge,
    ProviderScopeError,
    QdrantVectorConnector,
    SlackHistoryConnector,
):
    _provider_type.__module__ = __name__

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
