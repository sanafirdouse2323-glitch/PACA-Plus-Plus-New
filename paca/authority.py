"""Typed authority lineage records for agent capabilities.

The graph is an in-memory, append-only reference model. It records the issuer,
principal, tenant, task, purpose, policy epoch, expiry, parent and exact grant
scope associated with a capability. It is not a credential issuer, signature
verification service, persistent revocation registry or production authority
store.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

GrantScope = tuple[tuple[str, tuple[str, ...]], ...]
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def normalise_grants(grants: Mapping[str, Iterable[str]]) -> GrantScope:
    """Return a deterministic immutable representation of an action/target scope."""
    if not isinstance(grants, Mapping):
        raise TypeError("grants must be a mapping of action names to target patterns")

    normalized: list[tuple[str, tuple[str, ...]]] = []
    for action, patterns in grants.items():
        if not isinstance(action, str) or not action:
            raise ValueError("grant action names must be non-empty strings")
        if isinstance(patterns, (str, bytes)):
            raise TypeError(
                "grant patterns must be an iterable of strings, not a string"
            )
        try:
            values = tuple(sorted(set(patterns)))
        except TypeError as exc:
            raise TypeError(
                "grant patterns must be an iterable of hashable strings"
            ) from exc
        if any(not isinstance(pattern, str) or not pattern for pattern in values):
            raise ValueError("grant target patterns must be non-empty strings")
        normalized.append((action, values))
    return tuple(sorted(normalized))


def grant_pattern_is_subset(child: str, parent: str) -> bool:
    """Conservative glob-subset check shared by monitor and authority lineage.

    Exact targets may be checked against a parent glob. Pattern-to-pattern
    containment is accepted only for a simple trailing-star parent prefix;
    uncertain wildcard relationships fail closed.
    """
    if not isinstance(child, str) or not isinstance(parent, str):
        return False
    if not child or not parent or ".." in child.split("/") or ".." in parent.split("/"):
        return False
    if child == parent:
        return True
    if not any(character in child for character in "*?["):
        import fnmatch

        return fnmatch.fnmatchcase(child, parent)
    if (
        parent.endswith("*")
        and parent.count("*") == 1
        and "?" not in parent
        and "[" not in parent
    ):
        return child.startswith(parent[:-1])
    return False


@dataclass(frozen=True)
class AuthorityLineage:
    """Immutable authority grant snapshot associated with one capability."""

    authority_id: str
    issuer: str
    principal: str
    tenant: str
    task_id: str
    purpose: str
    policy_epoch: int
    expires: int
    grants: GrantScope
    parent_id: str | None = None
    # Parent-chain digest makes this node transitively bind the entire grant chain.
    parent_digest: str | None = None
    # All capabilities for one tenant/task share this immutable aggregate call ceiling.
    max_task_calls: int = 100
    # Persist the per-capability effect ceiling so a broker can resolve it without
    # trusting a caller-supplied token claim. None is retained only for legacy records.
    max_calls: int | None = None
    # Audience is persisted for broker-side grant resolution. None is legacy-only.
    audience: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "authority_id",
            "issuer",
            "principal",
            "tenant",
            "task_id",
            "purpose",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        for field_name in ("policy_epoch", "expires"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if (
            isinstance(self.max_task_calls, bool)
            or not isinstance(self.max_task_calls, int)
            or self.max_task_calls < 1
        ):
            raise ValueError("max_task_calls must be a positive integer")
        if self.max_calls is not None and (
            isinstance(self.max_calls, bool)
            or not isinstance(self.max_calls, int)
            or self.max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer or None")
        if self.audience is not None and (
            not isinstance(self.audience, str) or not self.audience
        ):
            raise ValueError("audience must be a non-empty string or None")
        if self.parent_id is not None and (
            not isinstance(self.parent_id, str) or not self.parent_id
        ):
            raise ValueError("parent_id must be a non-empty string or None")
        if self.parent_id is None and self.parent_digest is not None:
            raise ValueError("a root authority record cannot have a parent digest")
        if self.parent_id is not None and (
            not isinstance(self.parent_digest, str)
            or not _SHA256_RE.fullmatch(self.parent_digest)
        ):
            raise ValueError(
                "a delegated authority record requires its parent's SHA-256 chain digest"
            )

        if not isinstance(self.grants, tuple):
            raise TypeError("grants must be created with AuthorityLineage.create()")
        seen_actions = set()
        normalized: list[tuple[str, tuple[str, ...]]] = []
        for entry in self.grants:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("each grant entry must be an (action, patterns) tuple")
            action, patterns = entry
            if not isinstance(action, str) or not action or action in seen_actions:
                raise ValueError(
                    "authority grant actions must be unique non-empty strings"
                )
            seen_actions.add(action)
            if not isinstance(patterns, tuple):
                raise TypeError("authority grant patterns must be tuples")
            if any(not isinstance(pattern, str) or not pattern for pattern in patterns):
                raise ValueError("authority grant patterns must be non-empty strings")
            normalized.append((action, tuple(sorted(set(patterns)))))
        object.__setattr__(self, "grants", tuple(sorted(normalized)))

    @classmethod
    def create(
        cls,
        *,
        authority_id: str,
        issuer: str,
        principal: str,
        tenant: str,
        task_id: str,
        purpose: str,
        policy_epoch: int,
        expires: int,
        grants: Mapping[str, Iterable[str]],
        parent_id: str | None = None,
        parent_digest: str | None = None,
        max_task_calls: int = 100,
        max_calls: int | None = None,
        audience: str | None = None,
    ) -> AuthorityLineage:
        return cls(
            authority_id=authority_id,
            issuer=issuer,
            principal=principal,
            tenant=tenant,
            task_id=task_id,
            purpose=purpose,
            policy_epoch=policy_epoch,
            expires=expires,
            grants=normalise_grants(grants),
            parent_id=parent_id,
            parent_digest=parent_digest,
            max_task_calls=max_task_calls,
            max_calls=max_calls,
            audience=audience,
        )

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "authority_id": self.authority_id,
            "issuer": self.issuer,
            "principal": self.principal,
            "tenant": self.tenant,
            "task_id": self.task_id,
            "max_task_calls": self.max_task_calls,
            "purpose": self.purpose,
            "policy_epoch": self.policy_epoch,
            "expires": self.expires,
            "grants": {action: list(patterns) for action, patterns in self.grants},
            "parent_id": self.parent_id,
            "parent_digest": self.parent_digest,
        }
        # Omit the absent field for historical records so their canonical bytes
        # and parent-chain digests remain stable across this additive extension.
        if self.max_calls is not None:
            result["max_calls"] = self.max_calls
        if self.audience is not None:
            result["audience"] = self.audience
        return result

    @property
    def digest(self) -> str:
        blob = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def validate_capability(
        self,
        *,
        capability_id: str,
        principal: str,
        tenant: str,
        task_id: str,
        grants: Mapping[str, Iterable[str]],
        expires: int,
        parent_id: str | None,
        max_calls: int | None = None,
    ) -> None:
        """Fail if a mutable Capability has drifted from this immutable grant record."""
        if (
            capability_id != self.authority_id
            or principal != self.principal
            or tenant != self.tenant
            or task_id != self.task_id
            or expires != self.expires
            or parent_id != self.parent_id
            or normalise_grants(grants) != self.grants
            or (self.max_calls is not None and max_calls != self.max_calls)
        ):
            raise ValueError(
                "capability fields do not match their authority-lineage record"
            )


@dataclass
class AuthorityLineageGraph:
    """Append-only in-memory authority DAG with conservative delegation checks."""

    _nodes: dict[str, AuthorityLineage] = field(
        default_factory=dict, init=False, repr=False
    )

    def add(self, record: AuthorityLineage) -> AuthorityLineage:
        if not isinstance(record, AuthorityLineage):
            raise TypeError("record must be an AuthorityLineage")

        existing = self._nodes.get(record.authority_id)
        if existing is not None:
            if existing != record:
                raise ValueError(
                    "authority_id already exists with different immutable contents"
                )
            return existing

        if record.parent_id is not None:
            parent = self._nodes.get(record.parent_id)
            if parent is None:
                raise ValueError("authority parent must be recorded before its child")
            if record.parent_digest != self.digest(record.parent_id):
                raise ValueError(
                    "authority record does not bind the exact parent chain"
                )
            if record.tenant != parent.tenant or record.task_id != parent.task_id:
                raise ValueError("delegated authority cannot change tenant or task")
            if record.purpose != parent.purpose:
                raise ValueError("delegated authority cannot broaden or change purpose")
            if record.max_task_calls != parent.max_task_calls:
                raise ValueError(
                    "delegated authority must preserve the task-wide call quota"
                )
            if parent.max_calls is not None and (
                record.max_calls is None or record.max_calls > parent.max_calls
            ):
                raise ValueError(
                    "delegated authority cannot exceed or omit the persisted parent call limit"
                )
            if parent.audience is not None and record.audience != parent.audience:
                raise ValueError(
                    "delegated authority cannot change or omit its parent's audience"
                )
            if record.policy_epoch < parent.policy_epoch:
                raise ValueError(
                    "delegated authority cannot move to an older policy epoch"
                )
            if record.expires > parent.expires:
                raise ValueError("delegated authority cannot outlive its parent")
            parent_grants = dict(parent.grants)
            for action, child_patterns in record.grants:
                allowed_patterns = parent_grants.get(action)
                if allowed_patterns is None or not all(
                    any(
                        grant_pattern_is_subset(child, allowed)
                        for allowed in allowed_patterns
                    )
                    for child in child_patterns
                ):
                    raise ValueError(
                        "delegated grant scope exceeds or is not provably within its parent"
                    )

        # Parents must already exist, so a cycle cannot be introduced by add().
        self._nodes[record.authority_id] = record
        return record

    def get(self, authority_id: str) -> AuthorityLineage | None:
        return self._nodes.get(authority_id)

    def ancestors(self, authority_id: str) -> tuple[AuthorityLineage, ...]:
        """Return the root-to-record chain, including the requested record."""
        current: AuthorityLineage | None = self._nodes.get(authority_id)
        if current is None:
            raise KeyError(authority_id)
        chain: list[AuthorityLineage] = []
        while current is not None:
            chain.append(current)
            current = (
                self._nodes.get(current.parent_id)
                if current.parent_id is not None
                else None
            )
        chain.reverse()
        return tuple(chain)

    def digest(self, authority_id: str) -> str:
        chain = [record.as_dict() for record in self.ancestors(authority_id)]
        blob = json.dumps(
            chain, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def __len__(self) -> int:
        return len(self._nodes)


__all__ = [
    "AuthorityLineage",
    "AuthorityLineageGraph",
    "GrantScope",
    "grant_pattern_is_subset",
    "normalise_grants",
]
