"""Authenticated capability issuance and durable policy-epoch/revocation state.

HMAC is used as a dependency-free research reference mechanism. It is a shared-secret
MAC, not a public-key credential format or an OAuth authorization server. Every party
holding the verification key can also mint credentials, so key distribution and the
issuer process remain part of the trusted computing base.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Optional, Tuple

from .authority import AuthorityLineage, AuthorityLineageGraph
from .runtime import Capability


class AuthorityRegistryError(RuntimeError):
    """Authority state is unavailable, inconsistent, stale or revoked."""


class CapabilityAuthenticationError(PermissionError):
    """A signed capability failed authentication or validation."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(
        value + ("=" * (-len(value) % 4)), altchars=b"-_", validate=True,
    )


def _record_from_dict(data: Mapping[str, object]) -> AuthorityLineage:
    try:
        grants = data["grants"]
        if not isinstance(grants, dict):
            raise TypeError("grants must be an object")
        parent_id = data.get("parent_id")
        parent_digest = data.get("parent_digest")
        return AuthorityLineage.create(
            authority_id=str(data["authority_id"]),
            issuer=str(data["issuer"]),
            principal=str(data["principal"]),
            tenant=str(data["tenant"]),
            task_id=str(data["task_id"]),
            purpose=str(data["purpose"]),
            policy_epoch=int(data["policy_epoch"]),
            expires=int(data["expires"]),
            grants={str(action): tuple(patterns) for action, patterns in grants.items()},
            parent_id=str(parent_id) if parent_id is not None else None,
            parent_digest=str(parent_digest) if parent_digest is not None else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityRegistryError("authority record is malformed") from exc


class SQLiteAuthorityRegistry:
    """Durable authority graph, monotonically increasing policy epoch and revocations.

    Revoking a parent invalidates every descendant at validation time through a
    recursive ancestor query; descendant rows are not rewritten. Advancing the
    global policy epoch invalidates all capabilities issued at earlier epochs.
    """

    SCHEMA_VERSION = 3

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
        clock=time.time,
    ) -> None:
        raw = os.fspath(database)
        if raw == ":memory:" or not raw:
            raise ValueError("authority registry requires a file-backed SQLite database")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.database = Path(raw).expanduser().resolve()
        self.timeout = float(timeout)
        self.clock = clock
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database), timeout=self.timeout, isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=%d" % int(self.timeout * 1000))
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS paca_authority_meta "
                    "(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
                )
                row = connection.execute(
                    "SELECT value FROM paca_authority_meta WHERE key='schema_version'"
                ).fetchone()
                version = int(row["value"]) if row else 0
                if version > self.SCHEMA_VERSION:
                    raise AuthorityRegistryError("authority database schema is newer than this package")
                if version < 1:
                    connection.execute(
                        "CREATE TABLE authority_state ("
                        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                        "policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=0))"
                    )
                    connection.execute(
                        "INSERT INTO authority_state(singleton,policy_epoch) VALUES(1,0)"
                    )
                    connection.execute(
                        "CREATE TABLE policy_epoch_events ("
                        "epoch INTEGER PRIMARY KEY,"
                        "changed_at INTEGER NOT NULL,"
                        "reason TEXT NOT NULL)"
                    )
                    connection.execute(
                        "CREATE TABLE authority_records ("
                        "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "authority_id TEXT NOT NULL UNIQUE,"
                        "parent_id TEXT,"
                        "record_json TEXT NOT NULL)"
                    )
                    connection.execute(
                        "CREATE INDEX authority_parent_idx ON authority_records(parent_id)"
                    )
                    connection.execute(
                        "CREATE TABLE authority_revocations ("
                        "authority_id TEXT PRIMARY KEY REFERENCES authority_records(authority_id),"
                        "revoked_at INTEGER NOT NULL,"
                        "reason TEXT NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO paca_authority_meta(key,value) VALUES('schema_version','1')"
                    )
                if version < 2:
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS authority_usage ("
                        "authority_id TEXT PRIMARY KEY REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "calls_used INTEGER NOT NULL DEFAULT 0 CHECK(calls_used>=0),"
                        "fanout_used INTEGER NOT NULL DEFAULT 0 CHECK(fanout_used>=0))"
                    )
                    connection.execute(
                        "INSERT OR IGNORE INTO authority_usage(authority_id,calls_used,fanout_used) "
                        "SELECT authority_id,0,0 FROM authority_records"
                    )
                    connection.execute(
                        "UPDATE paca_authority_meta SET value='2' WHERE key='schema_version'"
                    )
                if version < 3:
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS authority_message_receipts ("
                        "principal TEXT NOT NULL,"
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "message_id TEXT NOT NULL,"
                        "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "received_at INTEGER NOT NULL,"
                        "PRIMARY KEY(principal,tenant,task_id,message_id))"
                    )
                    connection.execute(
                        "UPDATE paca_authority_meta SET value='3' WHERE key='schema_version'"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        try:
            os.chmod(self.database, 0o600)
        except OSError:
            pass

    @staticmethod
    def _load_graph(connection: sqlite3.Connection) -> AuthorityLineageGraph:
        graph = AuthorityLineageGraph()
        rows = connection.execute(
            "SELECT authority_id,parent_id,record_json FROM authority_records ORDER BY seq"
        ).fetchall()
        for row in rows:
            try:
                data = json.loads(row["record_json"])
                record = _record_from_dict(data)
                if (
                    record.authority_id != row["authority_id"]
                    or record.parent_id != row["parent_id"]
                    or _canonical(record.as_dict()).decode() != row["record_json"]
                ):
                    raise AuthorityRegistryError(
                        "authority record or parent edge failed canonical identity verification"
                    )
                graph.add(record)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                if isinstance(exc, AuthorityRegistryError):
                    raise
                raise AuthorityRegistryError("stored authority graph failed validation") from exc
        return graph

    def current_epoch(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT policy_epoch FROM authority_state WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise AuthorityRegistryError("policy epoch state is missing")
        return int(row["policy_epoch"])

    def advance_policy_epoch(self, reason: str) -> int:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("policy epoch change requires a reason")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = int(connection.execute(
                    "SELECT policy_epoch FROM authority_state WHERE singleton=1"
                ).fetchone()["policy_epoch"])
                new_epoch = current + 1
                connection.execute(
                    "UPDATE authority_state SET policy_epoch=? WHERE singleton=1",
                    (new_epoch,),
                )
                connection.execute(
                    "INSERT INTO policy_epoch_events(epoch,changed_at,reason) VALUES(?,?,?)",
                    (new_epoch, int(self.clock()), reason.strip()),
                )
                connection.commit()
                return new_epoch
            except Exception:
                connection.rollback()
                raise

    def register_authority(
        self,
        record: AuthorityLineage,
        *,
        parent_max_fanout: Optional[int] = None,
        parent_max_calls: Optional[int] = None,
    ) -> AuthorityLineage:
        if not isinstance(record, AuthorityLineage):
            raise TypeError("record must be an AuthorityLineage")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT record_json FROM authority_records WHERE authority_id=?",
                    (record.authority_id,),
                ).fetchone()
                encoded = _canonical(record.as_dict()).decode("utf-8")
                if existing is not None:
                    if existing["record_json"] != encoded:
                        raise AuthorityRegistryError("authority ID was reused with different immutable contents")
                    connection.commit()
                    return record
                epoch_row = connection.execute(
                    "SELECT policy_epoch FROM authority_state WHERE singleton=1"
                ).fetchone()
                if epoch_row is None or record.policy_epoch != int(epoch_row["policy_epoch"]):
                    raise AuthorityRegistryError("authority must be issued at the current policy epoch")
                if int(self.clock()) >= record.expires:
                    raise AuthorityRegistryError("cannot register an expired authority")
                graph = self._load_graph(connection)
                if record.parent_id is not None:
                    if not self._is_active(connection, record.parent_id):
                        raise AuthorityRegistryError("cannot delegate from a missing, expired, revoked or stale parent")
                    if (
                        isinstance(parent_max_fanout, bool)
                        or not isinstance(parent_max_fanout, int)
                        or parent_max_fanout < 1
                    ):
                        raise AuthorityRegistryError("delegation requires the authenticated parent fan-out budget")
                    usage = connection.execute(
                        "SELECT fanout_used FROM authority_usage WHERE authority_id=?",
                        (record.parent_id,),
                    ).fetchone()
                    fanout_used = int(usage["fanout_used"]) if usage else 0
                    if fanout_used >= parent_max_fanout:
                        raise AuthorityRegistryError("parent delegation fan-out budget is exhausted")
                    if (
                        isinstance(parent_max_calls, bool)
                        or not isinstance(parent_max_calls, int)
                        or parent_max_calls < 1
                    ):
                        raise AuthorityRegistryError("delegation requires the authenticated parent call budget")
                    usage = connection.execute(
                        "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                        (record.parent_id,),
                    ).fetchone()
                    if usage is None:
                        raise AuthorityRegistryError("parent durable usage state is missing")
                    if int(usage["calls_used"]) >= parent_max_calls:
                        raise AuthorityRegistryError("parent call budget is exhausted before delegation")
                graph.add(record)
                connection.execute(
                    "INSERT INTO authority_records(authority_id,parent_id,record_json) VALUES(?,?,?)",
                    (record.authority_id, record.parent_id, encoded),
                )
                connection.execute(
                    "INSERT INTO authority_usage(authority_id,calls_used,fanout_used) VALUES(?,0,0)",
                    (record.authority_id,),
                )
                if record.parent_id is not None:
                    connection.execute(
                        "UPDATE authority_usage SET fanout_used=fanout_used+1,"
                        "calls_used=calls_used+1 WHERE authority_id=?",
                        (record.parent_id,),
                    )
                connection.commit()
                return record
            except Exception:
                connection.rollback()
                raise

    def get_authority(self, authority_id: str) -> Optional[AuthorityLineage]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT authority_id,record_json FROM authority_records WHERE authority_id=?",
                (authority_id,),
            ).fetchone()
        if row is None:
            return None
        data = json.loads(row["record_json"])
        record = _record_from_dict(data)
        if record.authority_id != row["authority_id"] or _canonical(record.as_dict()).decode() != row["record_json"]:
            raise AuthorityRegistryError("authority record failed canonical verification")
        return record

    def chain_digest(self, authority_id: str) -> str:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
        try:
            return graph.digest(authority_id)
        except KeyError as exc:
            raise AuthorityRegistryError("unknown authority identifier") from exc

    def _is_active(self, connection: sqlite3.Connection, authority_id: str) -> bool:
        row = connection.execute(
            "SELECT record_json FROM authority_records WHERE authority_id=?",
            (authority_id,),
        ).fetchone()
        if row is None:
            return False
        record = _record_from_dict(json.loads(row["record_json"]))
        epoch_row = connection.execute(
            "SELECT policy_epoch FROM authority_state WHERE singleton=1"
        ).fetchone()
        if epoch_row is None or record.policy_epoch != int(epoch_row["policy_epoch"]):
            return False
        if int(self.clock()) >= record.expires:
            return False
        revoked = connection.execute(
            "WITH RECURSIVE chain(authority_id,parent_id) AS ("
            " SELECT authority_id,parent_id FROM authority_records WHERE authority_id=?"
            " UNION ALL"
            " SELECT parent.authority_id,parent.parent_id FROM authority_records parent"
            " JOIN chain child ON child.parent_id=parent.authority_id"
            ") SELECT 1 FROM chain JOIN authority_revocations r USING(authority_id) LIMIT 1",
            (authority_id,),
        ).fetchone()
        return revoked is None

    def consume_effect(self, authority_id: str, *, max_calls: int) -> int:
        """Atomically consume one call from the durable per-capability budget."""
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
            raise ValueError("max_calls must be a positive integer")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._load_graph(connection)
                if not self._is_active(connection, authority_id):
                    raise AuthorityRegistryError("cannot consume a call for inactive authority")
                row = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if row is None:
                    raise AuthorityRegistryError("durable capability usage state is missing")
                used = int(row["calls_used"])
                if used >= max_calls:
                    raise AuthorityRegistryError("capability call budget is exhausted")
                next_used = used + 1
                connection.execute(
                    "UPDATE authority_usage SET calls_used=? WHERE authority_id=?",
                    (next_used, authority_id),
                )
                connection.commit()
                return next_used
            except Exception:
                connection.rollback()
                raise

    def consume_message(
        self,
        authority_id: str,
        message_id: str,
        *,
        max_calls: int,
    ) -> int:
        """Atomically enforce recipient budget and reject replay for a principal/task."""
        if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
            raise ValueError("message_id must be a non-empty bounded string")
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
            raise ValueError("max_calls must be a positive integer")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._load_graph(connection)
                if not self._is_active(connection, authority_id):
                    raise AuthorityRegistryError("cannot receive a message with inactive authority")
                record_row = connection.execute(
                    "SELECT record_json FROM authority_records WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if record_row is None:
                    raise AuthorityRegistryError("recipient authority is unknown")
                record = _record_from_dict(json.loads(record_row["record_json"]))
                usage = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if usage is None:
                    raise AuthorityRegistryError("recipient durable usage state is missing")
                used = int(usage["calls_used"])
                if used >= max_calls:
                    raise AuthorityRegistryError("recipient call budget is exhausted")
                try:
                    connection.execute(
                        "INSERT INTO authority_message_receipts("
                        "principal,tenant,task_id,message_id,authority_id,received_at"
                        ") VALUES(?,?,?,?,?,?)",
                        (
                            record.principal, record.tenant, record.task_id,
                            message_id, authority_id, int(self.clock()),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AuthorityRegistryError("inter-agent message replay was rejected") from exc
                next_used = used + 1
                connection.execute(
                    "UPDATE authority_usage SET calls_used=? WHERE authority_id=?",
                    (next_used, authority_id),
                )
                connection.commit()
                return next_used
            except Exception:
                connection.rollback()
                raise

    def usage(self, authority_id: str) -> Tuple[int, int]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT calls_used,fanout_used FROM authority_usage WHERE authority_id=?",
                (authority_id,),
            ).fetchone()
        if row is None:
            raise KeyError(authority_id)
        return int(row["calls_used"]), int(row["fanout_used"])
    def is_active(self, authority_id: str) -> bool:
        with closing(self._connect()) as connection:
            return self._is_active(connection, authority_id)

    def assert_active(self, authority_id: str) -> AuthorityLineage:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
            if graph.get(authority_id) is None:
                raise AuthorityRegistryError("authority is missing from the validated delegation graph")
            active = self._is_active(connection, authority_id)
            row = connection.execute(
                "SELECT record_json FROM authority_records WHERE authority_id=?",
                (authority_id,),
            ).fetchone()
        if not active or row is None:
            raise AuthorityRegistryError("authority is expired, revoked, stale or unknown")
        return _record_from_dict(json.loads(row["record_json"]))

    def revoke(self, authority_id: str, reason: str) -> Tuple[str, ...]:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("revocation requires a reason")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._load_graph(connection)
                if connection.execute(
                    "SELECT 1 FROM authority_records WHERE authority_id=?",
                    (authority_id,),
                ).fetchone() is None:
                    raise KeyError(authority_id)
                connection.execute(
                    "INSERT OR IGNORE INTO authority_revocations(authority_id,revoked_at,reason) "
                    "VALUES(?,?,?)",
                    (authority_id, int(self.clock()), reason.strip()),
                )
                rows = connection.execute(
                    "WITH RECURSIVE descendants(authority_id) AS ("
                    " SELECT authority_id FROM authority_records WHERE authority_id=?"
                    " UNION"
                    " SELECT child.authority_id FROM authority_records child"
                    " JOIN descendants parent ON child.parent_id=parent.authority_id"
                    ") SELECT authority_id FROM descendants ORDER BY authority_id",
                    (authority_id,),
                ).fetchall()
                connection.commit()
                return tuple(row["authority_id"] for row in rows)
            except Exception:
                connection.rollback()
                raise

    def policy_events(self) -> Tuple[Tuple[int, int, str], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT epoch,changed_at,reason FROM policy_epoch_events ORDER BY epoch"
            ).fetchall()
        return tuple((int(row["epoch"]), int(row["changed_at"]), row["reason"]) for row in rows)


@dataclass(frozen=True)
class SignedCapability:
    token: str
    capability: Capability


class HMACCapabilityAuthority:
    """Issue and verify audience-bound, HMAC-authenticated capability envelopes."""

    TOKEN_VERSION = 1

    def __init__(
        self,
        registry: SQLiteAuthorityRegistry,
        *,
        issuer_id: str,
        key_id: str,
        key: bytes,
        audience: str,
        identity_verifier: Callable[[str, str], bool],
        clock=time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        for name, value in (("issuer_id", issuer_id), ("key_id", key_id), ("audience", audience)):
            if not isinstance(value, str) or not value:
                raise ValueError(name + " must be a non-empty string")
        self.registry = registry
        self.issuer_id = issuer_id
        self.key_id = key_id
        self._key = bytes(key)
        if not callable(identity_verifier):
            raise TypeError("identity_verifier must bind a principal to a tenant using trusted identity state")
        self.audience = audience
        self.identity_verifier = identity_verifier
        self.clock = clock

    def _encode(self, payload: Mapping[str, object]) -> str:
        body = _b64encode(_canonical(payload))
        signing_input = self.key_id + "." + body
        signature = _b64encode(hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest())
        return signing_input + "." + signature

    def issue(
        self,
        *,
        principal: str,
        tenant: Optional[str] = None,
        task_id: Optional[str] = None,
        purpose: Optional[str] = None,
        grants: Mapping[str, Iterable[str]],
        expires_at: int,
        role: str = "assistant",
        max_calls: int = 40,
        max_fanout: int = 5,
        tool_pins: Optional[Mapping[str, str]] = None,
        parent_token: Optional[str] = None,
    ) -> SignedCapability:
        now = int(self.clock())
        if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= now:
            raise ValueError("expires_at must be a future Unix timestamp in seconds")
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
            raise ValueError("max_calls must be a positive integer")
        if isinstance(max_fanout, bool) or not isinstance(max_fanout, int) or max_fanout < 1:
            raise ValueError("max_fanout must be a positive integer")
        if not isinstance(principal, str) or not principal or not isinstance(role, str) or not role:
            raise ValueError("principal and role must be non-empty strings")
        pins = dict(tool_pins or {})
        if any(not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in pins.items()):
            raise ValueError("tool pins must map non-empty names to non-empty hashes")
        epoch = self.registry.current_epoch()
        parent_id = None
        parent_digest = None
        if parent_token is not None:
            parent_signed = self.verify(parent_token)
            parent_record = parent_signed.capability.authority_lineage
            if parent_record is None:
                raise CapabilityAuthenticationError("delegation parent lacks authority lineage")
            parent_id = parent_record.authority_id
            self.registry.assert_active(parent_id)
            delegated_targets = dict(parent_record.grants).get("delegate", ())
            from .authority import grant_pattern_is_subset
            if not delegated_targets or not any(
                grant_pattern_is_subset(principal, target) for target in delegated_targets
            ):
                raise ValueError("parent capability does not authorise delegation to this principal")
            parent_pins = parent_signed.capability.tool_pins
            if any(parent_pins.get(name) != digest for name, digest in pins.items()):
                raise ValueError("delegated tool pins must be a subset of the parent's pins")
            tenant = parent_record.tenant
            task_id = parent_record.task_id
            purpose = parent_record.purpose
            if expires_at > parent_record.expires:
                raise ValueError("delegated capability cannot outlive its parent")
            if max_calls > parent_signed.capability.max_calls:
                raise ValueError("delegated call budget cannot exceed its parent")
            if max_fanout > parent_signed.capability.max_fanout:
                raise ValueError("delegated fan-out cannot exceed its parent")
            parent_digest = self.registry.chain_digest(parent_id)
        if any(value is None or not isinstance(value, str) or not value for value in (tenant, task_id, purpose)):
            raise ValueError("root capability issuance requires tenant, task_id and purpose")
        try:
            authenticated = bool(self.identity_verifier(principal, str(tenant)))
        except Exception as exc:
            raise CapabilityAuthenticationError("trusted principal authentication failed") from exc
        if not authenticated:
            raise CapabilityAuthenticationError("principal is not authenticated for the requested tenant")
        authority_id = secrets.token_urlsafe(18)
        record = AuthorityLineage.create(
            authority_id=authority_id,
            issuer=self.issuer_id,
            principal=principal,
            tenant=str(tenant),
            task_id=str(task_id),
            purpose=str(purpose),
            policy_epoch=epoch,
            expires=expires_at,
            grants=grants,
            parent_id=parent_id,
            parent_digest=parent_digest,
        )
        self.registry.register_authority(
            record,
            parent_max_fanout=(
                parent_signed.capability.max_fanout if parent_token is not None else None
            ),
            parent_max_calls=(
                parent_signed.capability.max_calls if parent_token is not None else None
            ),
        )
        capability = Capability(
            cap_id=record.authority_id,
            principal=record.principal,
            tenant=record.tenant,
            task_id=record.task_id,
            role=role,
            grants={action: patterns for action, patterns in record.grants},
            expires=record.expires,
            max_calls=max_calls,
            max_fanout=max_fanout,
            tool_pins=pins,
            parent=record.parent_id,
            authority_lineage=record,
        )
        payload: Dict[str, object] = {
            "version": self.TOKEN_VERSION,
            "issuer": self.issuer_id,
            "audience": self.audience,
            "issued_at": now,
            "key_id": self.key_id,
            "authority": record.as_dict(),
            "role": role,
            "max_calls": max_calls,
            "max_fanout": max_fanout,
            "tool_pins": pins,
        }
        return SignedCapability(self._encode(payload), capability)

    def verify(self, token: str, *, audience: Optional[str] = None) -> SignedCapability:
        try:
            if not isinstance(token, str) or len(token) > 65536:
                raise ValueError("invalid token size or type")
            key_id, body, signature = token.split(".")
            if key_id != self.key_id:
                raise ValueError("unknown signing key")
            signing_input = key_id + "." + body
            expected = hmac.new(
                self._key, signing_input.encode("ascii"), hashlib.sha256,
            ).digest()
            supplied = _b64decode(signature)
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("signature mismatch")
            payload = json.loads(_b64decode(body))
            if not isinstance(payload, dict):
                raise ValueError("token payload is not an object")
            if payload.get("version") != self.TOKEN_VERSION:
                raise ValueError("unsupported token version")
            if payload.get("key_id") != self.key_id or payload.get("issuer") != self.issuer_id:
                raise ValueError("issuer or key identifier mismatch")
            expected_audience = audience or self.audience
            if payload.get("audience") != expected_audience:
                raise ValueError("token audience mismatch")
            issued_at = payload.get("issued_at")
            if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at > int(self.clock()) + 30:
                raise ValueError("invalid token issuance time")
            authority_data = payload.get("authority")
            if not isinstance(authority_data, dict):
                raise ValueError("authority record is missing")
            record = _record_from_dict(authority_data)
            if record.issuer != self.issuer_id:
                raise ValueError("authority issuer mismatch")
            stored = self.registry.get_authority(record.authority_id)
            if stored != record:
                raise ValueError("signed authority does not match the trusted registry")
            self.registry.assert_active(record.authority_id)
            role = payload.get("role")
            max_calls = payload.get("max_calls")
            max_fanout = payload.get("max_fanout")
            pins = payload.get("tool_pins")
            if not isinstance(role, str) or not role:
                raise ValueError("invalid capability role")
            if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
                raise ValueError("invalid call budget")
            if isinstance(max_fanout, bool) or not isinstance(max_fanout, int) or max_fanout < 1:
                raise ValueError("invalid fan-out budget")
            if not isinstance(pins, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in pins.items()
            ):
                raise ValueError("invalid tool pins")
            capability = Capability(
                cap_id=record.authority_id,
                principal=record.principal,
                tenant=record.tenant,
                task_id=record.task_id,
                role=role,
                grants={action: patterns for action, patterns in record.grants},
                expires=record.expires,
                max_calls=max_calls,
                max_fanout=max_fanout,
                tool_pins=pins,
                parent=record.parent_id,
                authority_lineage=record,
            )
            capability.validate_authority_lineage()
            return SignedCapability(token, capability)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, AuthorityRegistryError, sqlite3.Error) as exc:
            if isinstance(exc, CapabilityAuthenticationError):
                raise
            raise CapabilityAuthenticationError("capability authentication or active-state validation failed") from exc


__all__ = [
    "AuthorityRegistryError",
    "CapabilityAuthenticationError",
    "HMACCapabilityAuthority",
    "SQLiteAuthorityRegistry",
    "SignedCapability",
]
