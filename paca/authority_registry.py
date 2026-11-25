"""Persistent authority registry and transactional local resource state.

This module owns the SQLite authority graph, policy epochs, revocation,
usage quotas, message receipts and logical resource-commit records. Credential
issuance and signature verification are implemented separately in
:mod:`paca.authority_runtime`.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .authority import (
    AuthorityLineage,
    AuthorityLineageGraph,
    grant_pattern_is_subset,
)


class AuthorityRegistryError(RuntimeError):
    """Authority state is unavailable, inconsistent, stale or revoked."""


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

    SCHEMA_VERSION = 6

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
        self.authority_store_id = "sqlite:" + str(self.database)
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
                if version < 6:
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS paca_resource_provenance ("
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "resource_key TEXT NOT NULL,"
                        "resource_version INTEGER NOT NULL CHECK(resource_version>=1),"
                        "metadata_json TEXT NOT NULL,"
                        "PRIMARY KEY(tenant,task_id,resource_key,resource_version))"
                    )
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS paca_resource_access_receipts ("
                        "session_id TEXT NOT NULL,"
                        "nonce_digest TEXT NOT NULL,"
                        "operation_id TEXT NOT NULL UNIQUE,"
                        "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "action TEXT NOT NULL,"
                        "resource_key TEXT NOT NULL,"
                        "request_digest TEXT NOT NULL,"
                        "payload_digest TEXT,"
                        "outcome TEXT NOT NULL,"
                        "created_at INTEGER NOT NULL,"
                        "PRIMARY KEY(session_id,nonce_digest))"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS paca_resource_access_authority_idx "
                        "ON paca_resource_access_receipts(authority_id,created_at)"
                    )
                    connection.execute(
                        "UPDATE paca_authority_meta SET value='6' WHERE key='schema_version'"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO paca_authority_meta(key,value) VALUES(?,?)",
                    ("authority_store_id", secrets.token_hex(16)),
                )
                store_row = connection.execute(
                    "SELECT value FROM paca_authority_meta WHERE key='authority_store_id'"
                ).fetchone()
                if store_row is None or not store_row["value"]:
                    raise AuthorityRegistryError(
                        "authority database store identity is missing"
                    )
                self.authority_store_id = "sqlite:" + store_row["value"]
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
        *,
        access_receipt: Mapping[str, object] | None = None,
        provenance_metadata: Mapping[str, object] | None = None,
        protocol_payload_digest: bool = False,
        expected_resource_version: int | None = None,
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
        if not isinstance(protocol_payload_digest, bool):
            raise TypeError("protocol_payload_digest must be a boolean")
        if expected_resource_version is not None and (
            isinstance(expected_resource_version, bool)
            or not isinstance(expected_resource_version, int)
            or expected_resource_version < 0
        ):
            raise ValueError("expected_resource_version must be a non-negative integer")
        if access_receipt is not None:
            required_receipt_fields = {
                "session_id",
                "nonce_digest",
                "operation_id",
                "request_digest",
                "payload_digest",
            }
            if (
                not isinstance(access_receipt, Mapping)
                or set(access_receipt) != required_receipt_fields
            ):
                raise ValueError("broker access receipt has an invalid field set")
            for name in ("session_id", "nonce_digest", "operation_id"):
                value = access_receipt.get(name)
                if not isinstance(value, str) or not value or len(value) > 256:
                    raise ValueError(f"broker access receipt {name} is invalid")
            for name in ("nonce_digest", "request_digest", "payload_digest"):
                value = access_receipt.get(name)
                if (
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                ):
                    raise ValueError(f"broker access receipt {name} must be SHA-256")
            if not hmac.compare_digest(
                access_receipt["request_digest"], permit.request_digest
            ):
                raise AuthorityRegistryError(
                    "broker access receipt request binding mismatch"
                )
            if not hmac.compare_digest(
                access_receipt["payload_digest"], permit.payload_digest
            ):
                raise AuthorityRegistryError(
                    "broker access receipt payload binding mismatch"
                )
        if provenance_metadata is not None and not isinstance(
            provenance_metadata, Mapping
        ):
            raise TypeError("provenance_metadata must be a JSON object")
        try:
            encoded_payload = _canonical(payload)
            if protocol_payload_digest:
                from .contracts.canonical import digest_object

                payload_digest = digest_object(dict(payload), purpose="payload")
            else:
                payload_digest = hashlib.sha256(encoded_payload).hexdigest()
            encoded_provenance = (
                _canonical(dict(provenance_metadata))
                if provenance_metadata is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "fenced resource payload or provenance must be canonical JSON"
            ) from exc
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
                current_version = (
                    int(existing["version"]) if existing is not None else 0
                )
                if (
                    expected_resource_version is not None
                    and current_version != expected_resource_version
                ):
                    raise AuthorityRegistryError(
                        "resource version precondition did not match at commit"
                    )
                version = current_version + 1
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
                if encoded_provenance is not None:
                    connection.execute(
                        "INSERT INTO paca_resource_provenance("
                        "tenant,task_id,resource_key,resource_version,metadata_json"
                        ") VALUES(?,?,?,?,?)",
                        (
                            record.tenant,
                            record.task_id,
                            permit.resource,
                            version,
                            encoded_provenance.decode("utf-8"),
                        ),
                    )
                if access_receipt is not None:
                    try:
                        connection.execute(
                            "INSERT INTO paca_resource_access_receipts("
                            "session_id,nonce_digest,operation_id,authority_id,tenant,task_id,"
                            "action,resource_key,request_digest,payload_digest,outcome,created_at"
                            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                access_receipt["session_id"],
                                access_receipt["nonce_digest"],
                                access_receipt["operation_id"],
                                permit.authority_id,
                                permit.tenant,
                                permit.task_id,
                                permit.action,
                                permit.resource,
                                permit.request_digest,
                                permit.payload_digest,
                                "committed",
                                now,
                            ),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise AuthorityRegistryError(
                            "broker operation replay or duplicate operation ID was rejected"
                        ) from exc

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

    def read_fenced_resource(
        self,
        *,
        authority_id: str,
        tenant: str,
        task_id: str,
        purpose: str,
        resource: str,
        max_calls: int,
        access_receipt: Mapping[str, object],
        expected_resource_version: int | None = None,
    ) -> dict[str, object]:
        """Read one logical file under current authority and durable replay state.

        Authority revalidation, quota consumption, request receipt and resource
        snapshot occur in one registry transaction. Returned bytes are still
        withheld by the broker until its trusted provenance guard approves them.
        """
        for name, value in (
            ("authority_id", authority_id),
            ("tenant", tenant),
            ("task_id", task_id),
            ("purpose", purpose),
            ("resource", resource),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if (
            isinstance(max_calls, bool)
            or not isinstance(max_calls, int)
            or max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")
        if expected_resource_version is not None and (
            isinstance(expected_resource_version, bool)
            or not isinstance(expected_resource_version, int)
            or expected_resource_version < 0
        ):
            raise ValueError("expected_resource_version must be a non-negative integer")
        required_receipt_fields = {
            "session_id",
            "nonce_digest",
            "operation_id",
            "request_digest",
        }
        if (
            not isinstance(access_receipt, Mapping)
            or set(access_receipt) != required_receipt_fields
        ):
            raise ValueError("broker access receipt has an invalid field set")
        for name in ("session_id", "nonce_digest", "operation_id"):
            value = access_receipt.get(name)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"broker access receipt {name} is invalid")
        for name in ("nonce_digest", "request_digest"):
            value = access_receipt.get(name)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"broker access receipt {name} must be SHA-256")

        now = int(self.clock())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                graph = self._load_graph(connection)
                record = graph.get(authority_id)
                if record is None or not self._is_active(connection, authority_id):
                    raise AuthorityRegistryError(
                        "resource read authority is expired, revoked, stale or unknown"
                    )
                if (
                    record.tenant != tenant
                    or record.task_id != task_id
                    or record.purpose != purpose
                ):
                    raise AuthorityRegistryError(
                        "resource read session does not match the active authority"
                    )
                patterns = dict(record.grants).get("read_file", ())
                if not any(
                    grant_pattern_is_subset(resource, pattern) for pattern in patterns
                ):
                    raise AuthorityRegistryError(
                        "active authority does not grant the logical resource read"
                    )
                usage = connection.execute(
                    "SELECT calls_used FROM authority_usage WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                if usage is None or int(usage["calls_used"]) >= max_calls:
                    raise AuthorityRegistryError(
                        "capability call budget is exhausted at resource read"
                    )
                task_usage = connection.execute(
                    "SELECT calls_used,max_task_calls FROM task_usage WHERE tenant=? AND task_id=?",
                    (tenant, task_id),
                ).fetchone()
                if (
                    task_usage is None
                    or int(task_usage["max_task_calls"]) != record.max_task_calls
                    or int(task_usage["calls_used"]) >= record.max_task_calls
                ):
                    raise AuthorityRegistryError(
                        "task-wide call budget is exhausted or inconsistent at resource read"
                    )

                row = connection.execute(
                    "SELECT value_json,payload_digest,version,action "
                    "FROM paca_resource_values WHERE tenant=? AND task_id=? AND resource_key=?",
                    (tenant, task_id, resource),
                ).fetchone()
                if row is None:
                    result = {
                        "found": False,
                        "resource": resource,
                        "version": 0,
                        "value": None,
                        "payload_digest": None,
                        "provenance_metadata": None,
                    }
                    outcome = "not_found"
                    stored_digest = None
                else:
                    current_version = int(row["version"])
                    if (
                        expected_resource_version is not None
                        and current_version != expected_resource_version
                    ):
                        raise AuthorityRegistryError(
                            "resource version precondition did not match at read"
                        )
                    try:
                        value = json.loads(row["value_json"])
                        from .contracts.canonical import digest_object

                        protocol_digest = digest_object(value, purpose="payload")
                        legacy_digest = hashlib.sha256(_canonical(value)).hexdigest()
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise AuthorityRegistryError(
                            "stored resource value or digest cannot be verified"
                        ) from exc
                    stored_digest = row["payload_digest"]
                    if not (
                        hmac.compare_digest(stored_digest, protocol_digest)
                        or hmac.compare_digest(stored_digest, legacy_digest)
                    ):
                        raise AuthorityRegistryError(
                            "stored resource payload digest verification failed"
                        )
                    metadata_row = connection.execute(
                        "SELECT metadata_json FROM paca_resource_provenance "
                        "WHERE tenant=? AND task_id=? AND resource_key=? AND resource_version=?",
                        (tenant, task_id, resource, current_version),
                    ).fetchone()
                    metadata = (
                        json.loads(metadata_row["metadata_json"])
                        if metadata_row is not None
                        else None
                    )
                    if not isinstance(value, dict):
                        raise AuthorityRegistryError(
                            "logical file resource must contain a JSON object"
                        )
                    result = {
                        "found": True,
                        "resource": resource,
                        "version": current_version,
                        "action": row["action"],
                        "value": value,
                        "payload_digest": stored_digest,
                        "provenance_metadata": metadata,
                    }
                    outcome = "found"

                try:
                    connection.execute(
                        "INSERT INTO paca_resource_access_receipts("
                        "session_id,nonce_digest,operation_id,authority_id,tenant,task_id,"
                        "action,resource_key,request_digest,payload_digest,outcome,created_at"
                        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            access_receipt["session_id"],
                            access_receipt["nonce_digest"],
                            access_receipt["operation_id"],
                            authority_id,
                            tenant,
                            task_id,
                            "read_file",
                            resource,
                            access_receipt["request_digest"],
                            stored_digest,
                            outcome,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AuthorityRegistryError(
                        "broker request replay or duplicate operation ID was rejected"
                    ) from exc

                connection.execute(
                    "UPDATE authority_usage SET calls_used=calls_used+1 WHERE authority_id=?",
                    (authority_id,),
                )
                updated = connection.execute(
                    "UPDATE task_usage SET calls_used=calls_used+1 "
                    "WHERE tenant=? AND task_id=? AND calls_used<max_task_calls",
                    (tenant, task_id),
                )
                if updated.rowcount != 1:
                    raise AuthorityRegistryError(
                        "task-wide quota was exhausted during resource read"
                    )
                connection.commit()
                return result
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


# Preserve the historical public module path for introspection and pickled
# references, while the implementation now lives in this module.
AuthorityRegistryError.__module__ = "paca.authority_runtime"
VerifiedResourceCommitPermit.__module__ = "paca.authority_runtime"
SQLiteAuthorityRegistry.__module__ = "paca.authority_runtime"


__all__ = [
    "AuthorityRegistryError",
    "SQLiteAuthorityRegistry",
    "VerifiedResourceCommitPermit",
]
