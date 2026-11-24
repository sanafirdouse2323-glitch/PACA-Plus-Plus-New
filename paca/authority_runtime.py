"""Authenticated capability issuance and durable policy-epoch/revocation state.

HMAC is used as a dependency-free research reference mechanism. It is a shared-secret
MAC, not a public-key credential format or an OAuth authorization server. Every party
holding the verification key can also mint credentials, so key distribution and the
issuer process remain part of the trusted computing base.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .authority import AuthorityLineage, AuthorityLineageGraph, grant_pattern_is_subset
from .runtime import Capability


class AuthorityRegistryError(RuntimeError):
    """Authority state is unavailable, inconsistent, stale or revoked."""


class CapabilityAuthenticationError(PermissionError):
    """A signed capability failed authentication or validation."""


@dataclass(frozen=True)
class VerifiedResourceCommitPermit:
    """Verified short-lived authorization for one exact resource mutation.

    The record is immutable after signature verification. The authoritative
    active-state, target-scope, replay and quota checks still occur inside the
    resource database transaction that commits the mutation.
    """

    nonce: str
    issuer: str
    key_id: str
    audience: str
    authority_id: str
    tenant: str
    task_id: str
    purpose: str
    policy_epoch: int
    issued_at: int
    expires_at: int
    max_calls: int
    action: str
    resource: str
    request_digest: str
    payload_digest: str


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(
        value + ("=" * (-len(value) % 4)),
        altchars=b"-_",
        validate=True,
    )


def _record_from_dict(data: Mapping[str, object]) -> AuthorityLineage:
    try:
        grants = data["grants"]
        if not isinstance(grants, dict):
            raise TypeError("grants must be an object")
        parent_id = data.get("parent_id")
        parent_digest = data.get("parent_digest")
        max_task_calls = data.get("max_task_calls")
        if (
            isinstance(max_task_calls, bool)
            or not isinstance(max_task_calls, int)
            or max_task_calls < 1
        ):
            raise ValueError("max_task_calls is missing or invalid")
        return AuthorityLineage.create(
            authority_id=str(data["authority_id"]),
            issuer=str(data["issuer"]),
            principal=str(data["principal"]),
            tenant=str(data["tenant"]),
            task_id=str(data["task_id"]),
            purpose=str(data["purpose"]),
            policy_epoch=int(data["policy_epoch"]),
            expires=int(data["expires"]),
            grants={
                str(action): tuple(patterns) for action, patterns in grants.items()
            },
            parent_id=str(parent_id) if parent_id is not None else None,
            parent_digest=str(parent_digest) if parent_digest is not None else None,
            max_task_calls=max_task_calls,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityRegistryError("authority record is malformed") from exc


class SQLiteAuthorityRegistry:
    """Durable authority graph, monotonically increasing policy epoch and revocations.

    Revoking a parent invalidates every descendant at validation time through a
    recursive ancestor query; descendant rows are not rewritten. Advancing the
    global policy epoch invalidates all capabilities issued at earlier epochs.
    """

    SCHEMA_VERSION = 5

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
        clock=time.time,
    ) -> None:
        raw = os.fspath(database)
        if raw == ":memory:" or not raw:
            raise ValueError(
                "authority registry requires a file-backed SQLite database"
            )
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.database = Path(raw).expanduser().resolve()
        self.timeout = float(timeout)
        self.clock = clock
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database),
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
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
                    raise AuthorityRegistryError(
                        "authority database schema is newer than this package"
                    )
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
                if version < 4:
                    populated = connection.execute(
                        "SELECT 1 FROM authority_records LIMIT 1"
                    ).fetchone()
                    if populated is not None:
                        raise AuthorityRegistryError(
                            "authority database contains existing v3 or older capabilities without "
                            "an aggregate task quota; an operator-reviewed offline migration is "
                            "required, and automatic quota inference or usage reset is refused"
                        )
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS task_usage ("
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "calls_used INTEGER NOT NULL DEFAULT 0 CHECK(calls_used>=0),"
                        "max_task_calls INTEGER NOT NULL CHECK(max_task_calls>=1),"
                        "PRIMARY KEY(tenant,task_id))"
                    )
                    connection.execute(
                        "UPDATE paca_authority_meta SET value='4' WHERE key='schema_version'"
                    )
                if version < 5:
                    # Local resource state and commit receipts deliberately share
                    # the authority database. BEGIN IMMEDIATE therefore serializes
                    # a resource commit against revoke()/advance_policy_epoch().
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS paca_resource_commit_receipts ("
                        "nonce TEXT PRIMARY KEY,"
                        "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "action TEXT NOT NULL,"
                        "resource_key TEXT NOT NULL,"
                        "request_digest TEXT NOT NULL,"
                        "payload_digest TEXT NOT NULL,"
                        "committed_at INTEGER NOT NULL)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS paca_resource_commit_authority_idx "
                        "ON paca_resource_commit_receipts(authority_id,committed_at)"
                    )
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS paca_resource_values ("
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "resource_key TEXT NOT NULL,"
                        "action TEXT NOT NULL,"
                        "value_json TEXT NOT NULL,"
                        "payload_digest TEXT NOT NULL,"
                        "version INTEGER NOT NULL CHECK(version>=1),"
                        "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "request_digest TEXT NOT NULL,"
                        "commit_nonce TEXT NOT NULL UNIQUE REFERENCES paca_resource_commit_receipts(nonce) ON DELETE RESTRICT,"
                        "updated_at INTEGER NOT NULL,"
                        "PRIMARY KEY(tenant,task_id,resource_key))"
                    )
                    connection.execute(
                        "UPDATE paca_authority_meta SET value='5' WHERE key='schema_version'"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        with contextlib.suppress(OSError):
            os.chmod(self.database, 0o600)

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
                raise AuthorityRegistryError(
                    "stored authority graph failed validation"
                ) from exc
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
                current = int(
                    connection.execute(
                        "SELECT policy_epoch FROM authority_state WHERE singleton=1"
                    ).fetchone()["policy_epoch"]
                )
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
        parent_max_fanout: int | None = None,
        parent_max_calls: int | None = None,
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

                # One durable counter is shared by every authority with the same
                # authenticated tenant/task pair. A missing row beside existing
                # authority history is corruption, not a reason to start at zero.
                task_row = connection.execute(
                    "SELECT calls_used,max_task_calls FROM task_usage "
                    "WHERE tenant=? AND task_id=?",
                    (record.tenant, record.task_id),
                ).fetchone()
                if task_row is None:
                    if record.parent_id is not None:
                        raise AuthorityRegistryError(
                            "task-wide usage state is missing before delegation"
                        )
                    prior_rows = connection.execute(
                        "SELECT record_json FROM authority_records"
                    ).fetchall()
                    for stored in prior_rows:
                        try:
                            stored_record = json.loads(stored["record_json"])
                        except json.JSONDecodeError as exc:
                            raise AuthorityRegistryError(
                                "stored authority history is malformed"
                            ) from exc
                        if (
                            stored_record.get("tenant") == record.tenant
                            and stored_record.get("task_id") == record.task_id
                        ):
                            raise AuthorityRegistryError(
                                "task-wide usage state is missing for existing authority history; "
                                "refusing to reset the aggregate counter"
                            )
                    connection.execute(
                        "INSERT INTO task_usage(tenant,task_id,calls_used,max_task_calls) "
                        "VALUES(?,?,0,?)",
                        (record.tenant, record.task_id, record.max_task_calls),
                    )
                    task_calls_used = 0
                else:
                    if int(task_row["max_task_calls"]) != record.max_task_calls:
                        raise AuthorityRegistryError(
                            "task-wide call quota differs from the immutable task configuration"
                        )
                    task_calls_used = int(task_row["calls_used"])

                if existing is not None:
                    if existing["record_json"] != encoded:
                        raise AuthorityRegistryError(
                            "authority ID was reused with different immutable contents"
                        )
                    connection.commit()
                    return record

                epoch_row = connection.execute(
                    "SELECT policy_epoch FROM authority_state WHERE singleton=1"
                ).fetchone()
                if epoch_row is None or record.policy_epoch != int(
                    epoch_row["policy_epoch"]
                ):
                    raise AuthorityRegistryError(
                        "authority must be issued at the current policy epoch"
                    )
                if int(self.clock()) >= record.expires:
                    raise AuthorityRegistryError("cannot register an expired authority")

                graph = self._load_graph(connection)
                if record.parent_id is not None:
                    if not self._is_active(connection, record.parent_id):
                        raise AuthorityRegistryError(
                            "cannot delegate from a missing, expired, revoked or stale parent"
                        )
                    if task_calls_used >= record.max_task_calls:
                        raise AuthorityRegistryError(
                            "task-wide call budget is exhausted before delegation"
                        )
                    if (
                        isinstance(parent_max_fanout, bool)
                        or not isinstance(parent_max_fanout, int)
                        or parent_max_fanout < 1
                    ):
                        raise AuthorityRegistryError(
                            "delegation requires the authenticated parent fan-out budget"
                        )
                    usage = connection.execute(
                        "SELECT fanout_used FROM authority_usage WHERE authority_id=?",
                        (record.parent_id,),
                    ).fetchone()
                    fanout_used = int(usage["fanout_used"]) if usage else 0
                    if fanout_used >= parent_max_fanout:
                        raise AuthorityRegistryError(
                            "parent delegation fan-out budget is exhausted"
                        )
                    if (
                        isinstance(parent_max_calls, bool)
                        or not isinstance(parent_max_calls, int)
                        or parent_max_calls < 1
                    ):
                        raise AuthorityRegistryError(
                            "delegation requires the authenticated parent call budget"
                        )
                    usage = connection.execute(
                        "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                        (record.parent_id,),
                    ).fetchone()
                    if usage is None:
                        raise AuthorityRegistryError(
                            "parent durable usage state is missing"
                        )
                    if int(usage["calls_used"]) >= parent_max_calls:
                        raise AuthorityRegistryError(
                            "parent call budget is exhausted before delegation"
                        )

                graph.add(record)
                connection.execute(
                    "INSERT INTO authority_records(authority_id,parent_id,record_json) "
                    "VALUES(?,?,?)",
                    (record.authority_id, record.parent_id, encoded),
                )
                connection.execute(
                    "INSERT INTO authority_usage(authority_id,calls_used,fanout_used) "
                    "VALUES(?,0,0)",
                    (record.authority_id,),
                )
                if record.parent_id is not None:
                    connection.execute(
                        "UPDATE authority_usage SET fanout_used=fanout_used+1,"
                        "calls_used=calls_used+1 WHERE authority_id=?",
                        (record.parent_id,),
                    )
                    updated = connection.execute(
                        "UPDATE task_usage SET calls_used=calls_used+1 "
                        "WHERE tenant=? AND task_id=? AND calls_used<max_task_calls",
                        (record.tenant, record.task_id),
                    )
                    if updated.rowcount != 1:
                        raise AuthorityRegistryError(
                            "task-wide call budget was exhausted during delegation"
                        )
                connection.commit()
                return record
            except Exception:
                connection.rollback()
                raise

    def get_authority(self, authority_id: str) -> AuthorityLineage | None:
        # Return only records from a fully reconstructed graph whose canonical
        # parent edges agree with the SQL columns used by revocation queries.
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
        return graph.get(authority_id)

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
        """Atomically consume per-capability and tenant/task-wide call budgets."""
        if (
            isinstance(max_calls, bool)
            or not isinstance(max_calls, int)
            or max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                graph = self._load_graph(connection)
                record = graph.get(authority_id)
                if record is None or not self._is_active(connection, authority_id):
                    raise AuthorityRegistryError(
                        "cannot consume a call for inactive authority"
                    )
                row = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if row is None:
                    raise AuthorityRegistryError(
                        "durable capability usage state is missing"
                    )
                used = int(row["calls_used"])
                if used >= max_calls:
                    raise AuthorityRegistryError("capability call budget is exhausted")

                task_row = connection.execute(
                    "SELECT calls_used,max_task_calls FROM task_usage "
                    "WHERE tenant=? AND task_id=?",
                    (record.tenant, record.task_id),
                ).fetchone()
                if (
                    task_row is None
                    or int(task_row["max_task_calls"]) != record.max_task_calls
                ):
                    raise AuthorityRegistryError(
                        "durable task-wide usage state is missing or inconsistent"
                    )
                task_used = int(task_row["calls_used"])
                if task_used >= record.max_task_calls:
                    raise AuthorityRegistryError("task-wide call budget is exhausted")

                next_used = used + 1
                connection.execute(
                    "UPDATE authority_usage SET calls_used=? WHERE authority_id=?",
                    (next_used, authority_id),
                )
                updated = connection.execute(
                    "UPDATE task_usage SET calls_used=calls_used+1 "
                    "WHERE tenant=? AND task_id=? AND calls_used<max_task_calls",
                    (record.tenant, record.task_id),
                )
                if updated.rowcount != 1:
                    raise AuthorityRegistryError(
                        "task-wide call budget was exhausted during operation"
                    )
                connection.commit()
                return next_used
            except Exception:
                connection.rollback()
                raise

    def commit_fenced_resource_write(
        self,
        permit: VerifiedResourceCommitPermit,
        payload: Mapping[str, object],
    ) -> dict[str, object]:
        """Commit one resource mutation under the same transaction as revocation.

        This reference data plane is intentionally colocated with the authority
        registry. Both this method and revoke()/advance_policy_epoch() use
        BEGIN IMMEDIATE on this SQLite database, so they have a serial order:
        a write commits before revocation, or the write observes the revocation
        and fails. This guarantee does not extend to a remote provider/API.
        """
        if not isinstance(permit, VerifiedResourceCommitPermit):
            raise TypeError(
                "resource commit requires a cryptographically verified permit"
            )
        if permit.action not in {"write_file", "mem_write"}:
            raise AuthorityRegistryError(
                "resource commit action is not supported by this local commit gate"
            )
        if (
            not isinstance(permit.resource, str)
            or not permit.resource
            or len(permit.resource) > 4096
            or any(ord(character) < 32 for character in permit.resource)
        ):
            raise ValueError("resource key must be a bounded, printable string")
        for name, value in (
            ("nonce", permit.nonce),
            ("issuer", permit.issuer),
            ("key_id", permit.key_id),
            ("audience", permit.audience),
            ("authority_id", permit.authority_id),
            ("tenant", permit.tenant),
            ("task_id", permit.task_id),
            ("purpose", permit.purpose),
            ("action", permit.action),
            ("resource", permit.resource),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"commit permit {name} must be a non-empty string")
        for name, value in (
            ("policy_epoch", permit.policy_epoch),
            ("issued_at", permit.issued_at),
            ("expires_at", permit.expires_at),
            ("max_calls", permit.max_calls),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"commit permit {name} must be a non-negative integer")
        if permit.max_calls < 1:
            raise ValueError("commit permit max_calls must be positive")
        for name, digest in (
            ("request_digest", permit.request_digest),
            ("payload_digest", permit.payload_digest),
        ):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError(
                    f"commit permit {name} must be a lowercase SHA-256 digest"
                )
        if not isinstance(payload, Mapping):
            raise TypeError("fenced resource payload must be a JSON object")
        try:
            encoded_payload = _canonical(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("fenced resource payload must be canonical JSON") from exc
        payload_digest = hashlib.sha256(encoded_payload).hexdigest()
        if not hmac.compare_digest(payload_digest, permit.payload_digest):
            raise AuthorityRegistryError(
                "resource payload does not match the signed commit permit"
            )
        now = int(self.clock())
        if (
            permit.issued_at > now + 30
            or permit.expires_at <= now
            or permit.expires_at <= permit.issued_at
            or permit.expires_at - permit.issued_at > 30
        ):
            raise AuthorityRegistryError(
                "resource commit permit is expired or has an invalid lifetime"
            )

        encoded_value = encoded_payload.decode("utf-8")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                graph = self._load_graph(connection)
                record = graph.get(permit.authority_id)
                if record is None or not self._is_active(
                    connection, permit.authority_id
                ):
                    raise AuthorityRegistryError(
                        "resource commit authority is expired, revoked, stale or unknown"
                    )
                if (
                    record.issuer != permit.issuer
                    or record.tenant != permit.tenant
                    or record.task_id != permit.task_id
                    or record.purpose != permit.purpose
                    or record.policy_epoch != permit.policy_epoch
                ):
                    raise AuthorityRegistryError(
                        "resource commit permit does not match the active authority record"
                    )
                patterns = dict(record.grants).get(permit.action, ())
                if not any(
                    grant_pattern_is_subset(permit.resource, pattern)
                    for pattern in patterns
                ):
                    raise AuthorityRegistryError(
                        "active authority does not grant the fenced resource target"
                    )

                usage = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (permit.authority_id,),
                ).fetchone()
                if usage is None or int(usage["calls_used"]) >= permit.max_calls:
                    raise AuthorityRegistryError(
                        "capability call budget is exhausted at resource commit"
                    )
                task_usage = connection.execute(
                    "SELECT calls_used,max_task_calls FROM task_usage WHERE tenant=? AND task_id=?",
                    (record.tenant, record.task_id),
                ).fetchone()
                if (
                    task_usage is None
                    or int(task_usage["max_task_calls"]) != record.max_task_calls
                    or int(task_usage["calls_used"]) >= record.max_task_calls
                ):
                    raise AuthorityRegistryError(
                        "task-wide call budget is exhausted or inconsistent at resource commit"
                    )

                # The unique nonce prevents a captured commit permit from being
                # replayed to produce a second mutation or quota charge.
                try:
                    connection.execute(
                        "INSERT INTO paca_resource_commit_receipts("
                        "nonce,authority_id,tenant,task_id,action,resource_key,"
                        "request_digest,payload_digest,committed_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            permit.nonce,
                            permit.authority_id,
                            permit.tenant,
                            permit.task_id,
                            permit.action,
                            permit.resource,
                            permit.request_digest,
                            permit.payload_digest,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AuthorityRegistryError(
                        "resource commit permit replay was rejected"
                    ) from exc

                connection.execute(
                    "UPDATE authority_usage SET calls_used=calls_used+1 WHERE authority_id=?",
                    (permit.authority_id,),
                )
                updated = connection.execute(
                    "UPDATE task_usage SET calls_used=calls_used+1 "
                    "WHERE tenant=? AND task_id=? AND calls_used<max_task_calls",
                    (record.tenant, record.task_id),
                )
                if updated.rowcount != 1:
                    raise AuthorityRegistryError(
                        "task-wide quota was exhausted during resource commit"
                    )

                existing = connection.execute(
                    "SELECT version FROM paca_resource_values "
                    "WHERE tenant=? AND task_id=? AND resource_key=?",
                    (record.tenant, record.task_id, permit.resource),
                ).fetchone()
                version = int(existing["version"]) + 1 if existing is not None else 1
                connection.execute(
                    "INSERT INTO paca_resource_values("
                    "tenant,task_id,resource_key,action,value_json,payload_digest,"
                    "version,authority_id,request_digest,commit_nonce,updated_at"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(tenant,task_id,resource_key) DO UPDATE SET "
                    "action=excluded.action,value_json=excluded.value_json,"
                    "payload_digest=excluded.payload_digest,version=excluded.version,"
                    "authority_id=excluded.authority_id,request_digest=excluded.request_digest,"
                    "commit_nonce=excluded.commit_nonce,updated_at=excluded.updated_at",
                    (
                        record.tenant,
                        record.task_id,
                        permit.resource,
                        permit.action,
                        encoded_value,
                        permit.payload_digest,
                        version,
                        permit.authority_id,
                        permit.request_digest,
                        permit.nonce,
                        now,
                    ),
                )
                connection.commit()
                return {
                    "tenant": record.tenant,
                    "task_id": record.task_id,
                    "resource": permit.resource,
                    "action": permit.action,
                    "version": version,
                    "payload_digest": permit.payload_digest,
                    "commit_nonce": permit.nonce,
                    "committed_at": now,
                }
            except Exception:
                connection.rollback()
                raise

    def has_message_receipt(
        self,
        principal: str,
        tenant: str,
        task_id: str,
        message_id: str,
    ) -> bool:
        """Check the indexed durable replay key without traversing message lineage.

        This is an availability fast path only. It is intentionally a read-only
        pre-check: consume_message() remains the authoritative transactional
        insert-and-charge operation and rejects concurrent duplicate deliveries.
        """
        values = (principal, tenant, task_id, message_id)
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError(
                "message receipt identity fields must be non-empty strings"
            )
        if len(message_id) > 256:
            raise ValueError("message_id exceeds the supported length")
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT 1 FROM authority_message_receipts "
                    "WHERE principal=? AND tenant=? AND task_id=? AND message_id=? LIMIT 1",
                    values,
                ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise AuthorityRegistryError(
                "durable message replay state is unavailable"
            ) from exc

    def consume_message(
        self,
        authority_id: str,
        message_id: str,
        *,
        max_calls: int,
    ) -> int:
        """Atomically enforce replay, per-capability and task-wide receive budgets."""
        if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
            raise ValueError("message_id must be a non-empty bounded string")
        if (
            isinstance(max_calls, bool)
            or not isinstance(max_calls, int)
            or max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                graph = self._load_graph(connection)
                record = graph.get(authority_id)
                if record is None or not self._is_active(connection, authority_id):
                    raise AuthorityRegistryError(
                        "cannot receive a message with inactive authority"
                    )
                usage = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if usage is None:
                    raise AuthorityRegistryError(
                        "recipient durable usage state is missing"
                    )
                used = int(usage["calls_used"])
                if used >= max_calls:
                    raise AuthorityRegistryError("recipient call budget is exhausted")

                task_row = connection.execute(
                    "SELECT calls_used,max_task_calls FROM task_usage "
                    "WHERE tenant=? AND task_id=?",
                    (record.tenant, record.task_id),
                ).fetchone()
                if (
                    task_row is None
                    or int(task_row["max_task_calls"]) != record.max_task_calls
                ):
                    raise AuthorityRegistryError(
                        "durable task-wide usage state is missing or inconsistent"
                    )
                task_used = int(task_row["calls_used"])
                if task_used >= record.max_task_calls:
                    raise AuthorityRegistryError("task-wide call budget is exhausted")

                try:
                    connection.execute(
                        "INSERT INTO authority_message_receipts("
                        "principal,tenant,task_id,message_id,authority_id,received_at"
                        ") VALUES(?,?,?,?,?,?)",
                        (
                            record.principal,
                            record.tenant,
                            record.task_id,
                            message_id,
                            authority_id,
                            int(self.clock()),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AuthorityRegistryError(
                        "inter-agent message replay was rejected"
                    ) from exc

                next_used = used + 1
                connection.execute(
                    "UPDATE authority_usage SET calls_used=? WHERE authority_id=?",
                    (next_used, authority_id),
                )
                updated = connection.execute(
                    "UPDATE task_usage SET calls_used=calls_used+1 "
                    "WHERE tenant=? AND task_id=? AND calls_used<max_task_calls",
                    (record.tenant, record.task_id),
                )
                if updated.rowcount != 1:
                    raise AuthorityRegistryError(
                        "task-wide call budget was exhausted during message receipt"
                    )
                connection.commit()
                return next_used
            except Exception:
                connection.rollback()
                raise

    def usage(self, authority_id: str) -> tuple[int, int]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT calls_used,fanout_used FROM authority_usage WHERE authority_id=?",
                (authority_id,),
            ).fetchone()
        if row is None:
            raise KeyError(authority_id)
        return int(row["calls_used"]), int(row["fanout_used"])

    def task_usage(self, tenant: str, task_id: str) -> tuple[int, int]:
        """Return (calls_used, max_task_calls) for one authenticated tenant/task."""
        if not isinstance(tenant, str) or not tenant:
            raise ValueError("tenant must be a non-empty string")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a non-empty string")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT calls_used,max_task_calls FROM task_usage "
                "WHERE tenant=? AND task_id=?",
                (tenant, task_id),
            ).fetchone()
        if row is None:
            raise KeyError((tenant, task_id))
        return int(row["calls_used"]), int(row["max_task_calls"])

    def is_active(self, authority_id: str) -> bool:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
            if graph.get(authority_id) is None:
                return False
            return self._is_active(connection, authority_id)

    def assert_active(self, authority_id: str) -> AuthorityLineage:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
            if graph.get(authority_id) is None:
                raise AuthorityRegistryError(
                    "authority is missing from the validated delegation graph"
                )
            active = self._is_active(connection, authority_id)
            row = connection.execute(
                "SELECT record_json FROM authority_records WHERE authority_id=?",
                (authority_id,),
            ).fetchone()
        if not active or row is None:
            raise AuthorityRegistryError(
                "authority is expired, revoked, stale or unknown"
            )
        return _record_from_dict(json.loads(row["record_json"]))

    def revoke(self, authority_id: str, reason: str) -> tuple[str, ...]:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("revocation requires a reason")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._load_graph(connection)
                if (
                    connection.execute(
                        "SELECT 1 FROM authority_records WHERE authority_id=?",
                        (authority_id,),
                    ).fetchone()
                    is None
                ):
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

    def policy_events(self) -> tuple[tuple[int, int, str], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT epoch,changed_at,reason FROM policy_epoch_events ORDER BY epoch"
            ).fetchall()
        return tuple(
            (int(row["epoch"]), int(row["changed_at"]), row["reason"]) for row in rows
        )


@dataclass(frozen=True)
class SignedCapability:
    token: str
    capability: Capability


class HMACCapabilityAuthority:
    """Issue and verify audience-bound, HMAC-authenticated capability envelopes."""

    TOKEN_VERSION = 2
    SIGNATURE_ALGORITHM = "HS256"
    DEFAULT_TASK_MAX_CALLS = 100

    def __init__(
        self,
        registry: SQLiteAuthorityRegistry,
        *,
        issuer_id: str,
        key_id: str,
        key: bytes,
        audience: str,
        identity_verifier: Callable[[str, str], bool],
        task_context_verifier: Callable[[str, str, str, str], bool],
        clock=time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        for name, value in (
            ("issuer_id", issuer_id),
            ("key_id", key_id),
            ("audience", audience),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(name + " must be a non-empty string")
        self.registry = registry
        self.issuer_id = issuer_id
        self.key_id = key_id
        self._key = bytes(key)
        if not callable(identity_verifier):
            raise TypeError(
                "identity_verifier must bind a principal to a tenant using trusted identity state"
            )
        if not callable(task_context_verifier):
            raise TypeError(
                "task_context_verifier must validate principal, tenant, task and purpose "
                "against trusted orchestrator state"
            )
        self.audience = audience
        self.identity_verifier = identity_verifier
        self.task_context_verifier = task_context_verifier
        self.clock = clock

    def _sign_bytes(self, message: bytes) -> bytes:
        """Sign bytes with the configured issuer key."""
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def _verify_bytes(self, message: bytes, signature: bytes) -> bool:
        """Verify bytes with the configured verification key."""
        return hmac.compare_digest(self._sign_bytes(message), signature)

    def _encode(self, payload: Mapping[str, object]) -> str:
        encoded_payload = dict(payload)
        encoded_payload["signature_algorithm"] = self.SIGNATURE_ALGORITHM
        body = _b64encode(_canonical(encoded_payload))
        signing_input = self.key_id + "." + body
        signature = _b64encode(self._sign_bytes(signing_input.encode("ascii")))
        return signing_input + "." + signature

    def issue_resource_commit_permit(
        self,
        capability_token: str,
        *,
        request_digest: str,
        action: str,
        resource: str,
        payload_digest: str,
        lifetime_seconds: int = 15,
    ) -> str:
        """Issue a one-use, short-lived signed permit for one exact resource write.

        The signature implementation is selected by this authority instance.
        HMAC verifiers are also signers; Ed25519 verifiers can hold only a public
        key and cannot mint permits.
        """
        for name, value in (
            ("request_digest", request_digest),
            ("payload_digest", payload_digest),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if action not in {"write_file", "mem_write"}:
            raise ValueError(
                "resource commit permits are supported only for write_file and mem_write"
            )
        if not isinstance(resource, str) or not resource or len(resource) > 4096:
            raise ValueError("resource must be a non-empty bounded key")
        if (
            isinstance(lifetime_seconds, bool)
            or not isinstance(lifetime_seconds, int)
            or not 1 <= lifetime_seconds <= 30
        ):
            raise ValueError(
                "resource commit permit lifetime must be between 1 and 30 seconds"
            )
        signed = self.verify(capability_token)
        capability = signed.capability
        record = capability.authority_lineage
        if record is None:
            raise CapabilityAuthenticationError(
                "resource commit capability lacks authority lineage"
            )
        now = int(self.clock())
        payload: dict[str, object] = {
            "version": 1,
            "issuer": self.issuer_id,
            "key_id": self.key_id,
            "audience": self.audience,
            "authority_id": record.authority_id,
            "tenant": record.tenant,
            "task_id": record.task_id,
            "purpose": record.purpose,
            "policy_epoch": record.policy_epoch,
            "issued_at": now,
            "expires_at": now + lifetime_seconds,
            "max_calls": capability.max_calls,
            "action": action,
            "resource": resource,
            "request_digest": request_digest,
            "payload_digest": payload_digest,
            "nonce": secrets.token_urlsafe(24),
        }
        payload["signature_algorithm"] = self.SIGNATURE_ALGORITHM
        body = _b64encode(_canonical(payload))
        signing_input = "resource-commit-v1." + self.key_id + "." + body
        signature = _b64encode(self._sign_bytes(signing_input.encode("ascii")))
        return signing_input + "." + signature

    def verify_resource_commit_permit(
        self,
        token: str,
    ) -> VerifiedResourceCommitPermit:
        """Authenticate a resource permit; active-state checks happen in commit SQL."""
        try:
            if not isinstance(token, str) or len(token) > 16_384:
                raise ValueError("invalid resource commit permit size or type")
            version, key_id, body, signature = token.split(".")
            if version != "resource-commit-v1" or key_id != self.key_id:
                raise ValueError(
                    "resource commit permit version or key identifier mismatch"
                )
            signing_input = version + "." + key_id + "." + body
            if not self._verify_bytes(
                signing_input.encode("ascii"),
                _b64decode(signature),
            ):
                raise ValueError("resource commit permit signature mismatch")
            payload = json.loads(_b64decode(body))
            if not isinstance(payload, dict) or payload.get("version") != 1:
                raise ValueError("resource commit permit payload is malformed")
            if payload.get("issuer") != self.issuer_id:
                raise ValueError("resource commit permit issuer mismatch")
            if (
                payload.get("key_id") != self.key_id
                or payload.get("audience") != self.audience
            ):
                raise ValueError("resource commit permit key or audience mismatch")
            if payload.get("signature_algorithm") != self.SIGNATURE_ALGORITHM:
                raise ValueError("resource commit permit signature algorithm mismatch")
            expected_fields = {
                "version",
                "signature_algorithm",
                "issuer",
                "key_id",
                "audience",
                "authority_id",
                "tenant",
                "task_id",
                "purpose",
                "policy_epoch",
                "issued_at",
                "expires_at",
                "max_calls",
                "action",
                "resource",
                "request_digest",
                "payload_digest",
                "nonce",
            }
            if set(payload) != expected_fields:
                raise ValueError(
                    "resource commit permit contains missing or unknown fields"
                )
            result = VerifiedResourceCommitPermit(
                nonce=payload["nonce"],
                issuer=payload["issuer"],
                key_id=payload["key_id"],
                audience=payload["audience"],
                authority_id=payload["authority_id"],
                tenant=payload["tenant"],
                task_id=payload["task_id"],
                purpose=payload["purpose"],
                policy_epoch=payload["policy_epoch"],
                issued_at=payload["issued_at"],
                expires_at=payload["expires_at"],
                max_calls=payload["max_calls"],
                action=payload["action"],
                resource=payload["resource"],
                request_digest=payload["request_digest"],
                payload_digest=payload["payload_digest"],
            )
            now = int(self.clock())
            if (
                result.issued_at > now + 30
                or result.expires_at <= now
                or result.expires_at <= result.issued_at
                or result.expires_at - result.issued_at > 30
            ):
                raise ValueError(
                    "resource commit permit is expired or has an invalid lifetime"
                )
            return result
        except (
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            AuthorityRegistryError,
            sqlite3.Error,
        ) as exc:
            raise CapabilityAuthenticationError(
                "resource commit permit authentication failed"
            ) from exc

    def issue(
        self,
        *,
        principal: str,
        tenant: str | None = None,
        task_id: str | None = None,
        purpose: str | None = None,
        grants: Mapping[str, Iterable[str]],
        expires_at: int,
        role: str = "assistant",
        max_calls: int = 40,
        max_fanout: int = 5,
        max_task_calls: int | None = None,
        tool_pins: Mapping[str, str] | None = None,
        parent_token: str | None = None,
    ) -> SignedCapability:
        now = int(self.clock())
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or expires_at <= now
        ):
            raise ValueError("expires_at must be a future Unix timestamp in seconds")
        if (
            isinstance(max_calls, bool)
            or not isinstance(max_calls, int)
            or max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")
        if (
            isinstance(max_fanout, bool)
            or not isinstance(max_fanout, int)
            or max_fanout < 1
        ):
            raise ValueError("max_fanout must be a positive integer")
        if max_task_calls is not None and (
            isinstance(max_task_calls, bool)
            or not isinstance(max_task_calls, int)
            or max_task_calls < 1
        ):
            raise ValueError("max_task_calls must be a positive integer")
        if (
            not isinstance(principal, str)
            or not principal
            or not isinstance(role, str)
            or not role
        ):
            raise ValueError("principal and role must be non-empty strings")
        pins = dict(tool_pins or {})
        if any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in pins.items()
        ):
            raise ValueError("tool pins must map non-empty names to non-empty hashes")
        epoch = self.registry.current_epoch()
        parent_id = None
        parent_digest = None
        if parent_token is not None:
            parent_signed = self.verify(parent_token)
            parent_record = parent_signed.capability.authority_lineage
            if parent_record is None:
                raise CapabilityAuthenticationError(
                    "delegation parent lacks authority lineage"
                )
            parent_id = parent_record.authority_id
            self.registry.assert_active(parent_id)
            if (
                max_task_calls is not None
                and max_task_calls != parent_record.max_task_calls
            ):
                raise ValueError(
                    "delegated capability must preserve its parent's task-wide call quota"
                )
            max_task_calls = parent_record.max_task_calls
            delegated_targets = dict(parent_record.grants).get("delegate", ())
            from .authority import grant_pattern_is_subset

            if not delegated_targets or not any(
                grant_pattern_is_subset(principal, target)
                for target in delegated_targets
            ):
                raise ValueError(
                    "parent capability does not authorise delegation to this principal"
                )
            parent_pins = parent_signed.capability.tool_pins
            if any(parent_pins.get(name) != digest for name, digest in pins.items()):
                raise ValueError(
                    "delegated tool pins must be a subset of the parent's pins"
                )
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
        if max_task_calls is None:
            max_task_calls = self.DEFAULT_TASK_MAX_CALLS
        if any(
            value is None or not isinstance(value, str) or not value
            for value in (tenant, task_id, purpose)
        ):
            raise ValueError(
                "root capability issuance requires tenant, task_id and purpose"
            )
        try:
            authenticated = bool(self.identity_verifier(principal, str(tenant)))
        except Exception as exc:
            raise CapabilityAuthenticationError(
                "trusted principal authentication failed"
            ) from exc
        if not authenticated:
            raise CapabilityAuthenticationError(
                "principal is not authenticated for the requested tenant"
            )
        try:
            task_context_authenticated = bool(
                self.task_context_verifier(
                    principal,
                    str(tenant),
                    str(task_id),
                    str(purpose),
                )
            )
        except Exception as exc:
            raise CapabilityAuthenticationError(
                "trusted task context authentication failed"
            ) from exc
        if not task_context_authenticated:
            raise CapabilityAuthenticationError(
                "principal is not authorised for the requested task and purpose"
            )
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
            max_task_calls=max_task_calls,
        )
        self.registry.register_authority(
            record,
            parent_max_fanout=(
                parent_signed.capability.max_fanout
                if parent_token is not None
                else None
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
        payload: dict[str, object] = {
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

    def verify(self, token: str, *, audience: str | None = None) -> SignedCapability:
        try:
            if not isinstance(token, str):
                raise TypeError("token must be a string")
            if len(token) > 65536:
                raise ValueError("token exceeds the maximum size")
            key_id, body, signature = token.split(".")
            if key_id != self.key_id:
                raise ValueError("unknown signing key")
            signing_input = key_id + "." + body
            supplied = _b64decode(signature)
            if not self._verify_bytes(signing_input.encode("ascii"), supplied):
                raise ValueError("signature mismatch")
            payload = json.loads(_b64decode(body))
            if not isinstance(payload, dict):
                raise TypeError("token payload must be an object")
            if payload.get("version") != self.TOKEN_VERSION:
                raise ValueError("unsupported token version")
            token_algorithm = payload.get("signature_algorithm")
            if token_algorithm not in (None, self.SIGNATURE_ALGORITHM):
                raise ValueError("token signature algorithm mismatch")
            if (
                self.SIGNATURE_ALGORITHM != "HS256"
                and token_algorithm != self.SIGNATURE_ALGORITHM
            ):
                raise ValueError(
                    "asymmetric token is missing its required signature algorithm"
                )
            if (
                payload.get("key_id") != self.key_id
                or payload.get("issuer") != self.issuer_id
            ):
                raise ValueError("issuer or key identifier mismatch")
            expected_audience = audience or self.audience
            if payload.get("audience") != expected_audience:
                raise ValueError("token audience mismatch")
            issued_at = payload.get("issued_at")
            if (
                isinstance(issued_at, bool)
                or not isinstance(issued_at, int)
                or issued_at > int(self.clock()) + 30
            ):
                raise ValueError("invalid token issuance time")
            authority_data = payload.get("authority")
            if not isinstance(authority_data, dict):
                raise TypeError("authority record must be an object")
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
            if (
                isinstance(max_calls, bool)
                or not isinstance(max_calls, int)
                or max_calls < 1
            ):
                raise ValueError("invalid call budget")
            if (
                isinstance(max_fanout, bool)
                or not isinstance(max_fanout, int)
                or max_fanout < 1
            ):
                raise ValueError("invalid fan-out budget")
            if not isinstance(pins, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in pins.items()
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
        except (
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            AuthorityRegistryError,
            sqlite3.Error,
        ) as exc:
            if isinstance(exc, CapabilityAuthenticationError):
                raise
            raise CapabilityAuthenticationError(
                "capability authentication or active-state validation failed"
            ) from exc


class Ed25519CapabilityAuthority(HMACCapabilityAuthority):
    """Ed25519 authority with distinct private-key issuer and public-key verifier roles.

    The verifier receives only a raw Ed25519 public key and cannot mint
    capabilities or resource-commit permits. The optional cryptography dependency
    is imported lazily. Key storage, rotation and authenticated public-key
    distribution remain responsibilities of the deployment.
    """

    SIGNATURE_ALGORITHM = "Ed25519"

    def __init__(
        self,
        registry: SQLiteAuthorityRegistry,
        *,
        issuer_id: str,
        key_id: str,
        audience: str,
        identity_verifier: Callable[[str, str], bool],
        task_context_verifier: Callable[[str, str, str, str], bool],
        public_key: bytes | None = None,
        private_key: bytes | None = None,
        clock=time.time,
    ) -> None:
        if public_key is None and private_key is None:
            raise ValueError("Ed25519 authority requires a public or private key")
        if public_key is not None and (
            not isinstance(public_key, bytes) or len(public_key) != 32
        ):
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        if private_key is not None and (
            not isinstance(private_key, bytes) or len(private_key) != 32
        ):
            raise ValueError("Ed25519 private key seed must be 32 raw bytes")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise ImportError(
                "Ed25519CapabilityAuthority requires the optional 'crypto' dependency"
            ) from exc

        signing_key = (
            Ed25519PrivateKey.from_private_bytes(private_key)
            if private_key is not None
            else None
        )
        derived_public = (
            signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if signing_key is not None
            else None
        )
        if (
            public_key is not None
            and derived_public is not None
            and not hmac.compare_digest(
                public_key,
                derived_public,
            )
        ):
            raise ValueError(
                "Ed25519 public key does not match the supplied private key"
            )
        verification_bytes = public_key or derived_public
        if verification_bytes is None:
            raise ValueError("Ed25519 verification key is missing")

        # Satisfy the shared base configuration contract, then discard the
        # placeholder HMAC key. All cryptographic operations use Ed25519 hooks.
        super().__init__(
            registry,
            issuer_id=issuer_id,
            key_id=key_id,
            key=b"\x00" * 32,
            audience=audience,
            identity_verifier=identity_verifier,
            task_context_verifier=task_context_verifier,
            clock=clock,
        )
        self._key = b""
        self._ed25519_signing_key = signing_key
        self._ed25519_verification_key = Ed25519PublicKey.from_public_bytes(
            verification_bytes,
        )
        self._ed25519_invalid_signature = InvalidSignature

    def _sign_bytes(self, message: bytes) -> bytes:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue signed artifacts"
            )
        return self._ed25519_signing_key.sign(message)

    def _verify_bytes(self, message: bytes, signature: bytes) -> bool:
        try:
            self._ed25519_verification_key.verify(signature, message)
            return True
        except self._ed25519_invalid_signature:
            return False

    def issue(self, **kwargs: object) -> SignedCapability:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue capabilities"
            )
        return super().issue(**kwargs)  # type: ignore[arg-type]

    def issue_resource_commit_permit(
        self,
        capability_token: str,
        **kwargs: object,
    ) -> str:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue resource commit permits"
            )
        return super().issue_resource_commit_permit(
            capability_token,
            **kwargs,
        )  # type: ignore[arg-type]


__all__ = [
    "AuthorityRegistryError",
    "CapabilityAuthenticationError",
    "Ed25519CapabilityAuthority",
    "HMACCapabilityAuthority",
    "SQLiteAuthorityRegistry",
    "SignedCapability",
    "VerifiedResourceCommitPermit",
]
