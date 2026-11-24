"""Optional integrations for external agent runtimes and evaluation harnesses.

Import individual integration modules explicitly. They may require optional dependencies.
"""

from .providers import (
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
)

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
