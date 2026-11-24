from __future__ import annotations

import paca
from paca.authority_registry import (
    AuthorityRegistryError as ExtractedRegistryError,
    SQLiteAuthorityRegistry as ExtractedRegistry,
    VerifiedResourceCommitPermit as ExtractedPermit,
)
from paca.authority_runtime import (
    AuthorityRegistryError as LegacyRegistryError,
    SQLiteAuthorityRegistry as LegacyRegistry,
    VerifiedResourceCommitPermit as LegacyPermit,
)


def test_authority_registry_legacy_and_package_exports_are_compatible():
    assert LegacyRegistry is ExtractedRegistry
    assert LegacyRegistryError is ExtractedRegistryError
    assert LegacyPermit is ExtractedPermit
    assert paca.SQLiteAuthorityRegistry is ExtractedRegistry
    assert paca.AuthorityRegistryError is ExtractedRegistryError
    assert paca.VerifiedResourceCommitPermit is ExtractedPermit
    assert ExtractedRegistry.__module__ == "paca.authority_runtime"
    assert ExtractedRegistryError.__module__ == "paca.authority_runtime"
    assert ExtractedPermit.__module__ == "paca.authority_runtime"
