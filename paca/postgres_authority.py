"""PostgreSQL-backed authority registry for multi-process PACA deployments.

This backend preserves the SQLiteAuthorityRegistry contract while placing
authority, revocation, usage, aggregate quota, message receipts and local
resource-commit state in one shared PostgreSQL database.

Mutating operations take a transaction-scoped table lock before running the
existing registry state machine. This deliberately favours a simple, auditable
serial order over maximum write throughput. All workers must use the same
authoritative primary database. Read replicas, multi-primary writes and failover
rollback semantics are not supported by this reference implementation.
"""

from __future__ import annotations

import math
import re
import secrets
import sqlite3
from contextlib import closing
from typing import Any

from .authority_runtime import AuthorityRegistryError, SQLiteAuthorityRegistry

_LOCK_ID = 0x5041434155544852


class _PostgresConnection:
    """Small DB-API compatibility adapter used by the shared registry methods."""

    _WRITE_LOCK = (
        "LOCK TABLE authority_state, policy_epoch_events, authority_records, "
        "authority_revocations, authority_usage, authority_message_receipts, "
        "task_usage, paca_resource_commit_receipts, paca_resource_values, "
        "paca_resource_provenance, paca_resource_access_receipts "
        "IN SHARE ROW EXCLUSIVE MODE"
    )

    def __init__(self, raw: Any, psycopg_module: Any) -> None:
        self.raw = raw
        self.psycopg = psycopg_module

    @staticmethod
    def _translate_sql(statement: str) -> str:
        sql = statement.strip()
        if re.match(r"(?is)^INSERT\s+OR\s+IGNORE\s+INTO\b", sql):
            sql = re.sub(
                r"(?is)^INSERT\s+OR\s+IGNORE\s+INTO\b",
                "INSERT INTO",
                sql,
                count=1,
            )
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        # Registry SQL uses DB-API qmark placeholders. None of its SQL literals
        # contain question marks, so this narrow translation is unambiguous.
        return sql.replace("?", "%s")

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        sql = statement.strip()
        try:
            if sql.upper() == "BEGIN IMMEDIATE":
                self.raw.execute("BEGIN")
                # This lock conflicts with other registry writers across all
                # application processes/hosts connected to the same primary.
                return self.raw.execute(self._WRITE_LOCK)
            translated = self._translate_sql(sql)
            return self.raw.execute(translated, parameters)
        except self.psycopg.errors.UniqueViolation as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        except self.psycopg.Error as exc:
            raise sqlite3.DatabaseError(str(exc)) from exc

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()


class PostgresAuthorityRegistry(SQLiteAuthorityRegistry):
    """Shared PostgreSQL backend implementing the SQLite authority-registry API.

    The transaction-wide lock makes revocation/epoch updates linearizable against
    capability consumption, aggregate-quota charging, message receipt insertion
    and fenced resource commits across independent clients using this database.
    It is conservative: writes are serialized at the registry-table level.
    """

    def __init__(
        self,
        dsn: str,
        *,
        clock=None,
        timeout: float = 15.0,
    ) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN must be a non-empty string")
        if not dsn.startswith(("postgresql://", "postgres://")) and "host=" not in dsn:
            raise ValueError("PostgreSQL DSN must identify a PostgreSQL connection")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be finite and positive")
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise ImportError(
                "PostgresAuthorityRegistry requires the optional 'postgres' dependency"
            ) from exc

        import time

        # Never expose a connection string (which may contain a password) through
        # the SQLite-compatible diagnostic attribute.
        self._dsn = dsn
        self.database = "<PostgreSQL authority database>"
        # The persistent opaque ID is stored inside the authority schema, so
        # independent clients match without exposing connection credentials.
        self.authority_store_id = None
        self.timeout = float(timeout)
        self.clock = clock if clock is not None else time.time
        self._psycopg = psycopg
        self._dict_row = dict_row
        self._initialise()

    def _connect(self) -> _PostgresConnection:
        try:
            raw = self._psycopg.connect(
                self._dsn,
                autocommit=True,
                row_factory=self._dict_row,
                connect_timeout=max(1, int(self.timeout)),
            )
        except self._psycopg.Error as exc:
            raise AuthorityRegistryError(
                "could not connect to the PostgreSQL authority database"
            ) from exc
        return _PostgresConnection(raw, self._psycopg)

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            # Serialize schema initialization across service replicas.
            connection.execute(f"SELECT pg_advisory_lock({_LOCK_ID})")
            try:
                connection.execute("BEGIN")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS paca_authority_meta "
                    "(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority_state ("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                    "policy_epoch BIGINT NOT NULL CHECK(policy_epoch>=0))"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS policy_epoch_events ("
                    "epoch BIGINT PRIMARY KEY,"
                    "changed_at BIGINT NOT NULL,"
                    "reason TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority_records ("
                    "seq BIGSERIAL PRIMARY KEY,"
                    "authority_id TEXT NOT NULL UNIQUE,"
                    "parent_id TEXT,"
                    "record_json TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS authority_parent_idx ON authority_records(parent_id)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority_revocations ("
                    "authority_id TEXT PRIMARY KEY REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                    "revoked_at BIGINT NOT NULL,"
                    "reason TEXT NOT NULL)"
                )

                version_row = connection.execute(
                    "SELECT value FROM paca_authority_meta WHERE key='schema_version'"
                ).fetchone()
                version = int(version_row["value"]) if version_row else 0
                if version > self.SCHEMA_VERSION:
                    raise AuthorityRegistryError(
                        "PostgreSQL authority schema is newer than this package"
                    )

                populated = connection.execute(
                    "SELECT 1 FROM authority_records LIMIT 1"
                ).fetchone()
                if version < 4 and populated is not None:
                    raise AuthorityRegistryError(
                        "PostgreSQL authority database contains capabilities without the "
                        "aggregate task-wide quota; an operator-reviewed offline migration "
                        "is required, and automatic quota inference or usage reset is refused"
                    )

                if version == 0:
                    connection.execute(
                        "INSERT INTO authority_state(singleton,policy_epoch) VALUES(1,0) "
                        "ON CONFLICT(singleton) DO NOTHING"
                    )
                else:
                    state = connection.execute(
                        "SELECT policy_epoch FROM authority_state WHERE singleton=1"
                    ).fetchone()
                    if state is None:
                        raise AuthorityRegistryError(
                            "PostgreSQL authority policy state is missing; refusing to reset the epoch"
                        )

                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority_usage ("
                    "authority_id TEXT PRIMARY KEY REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                    "calls_used BIGINT NOT NULL DEFAULT 0 CHECK(calls_used>=0),"
                    "fanout_used BIGINT NOT NULL DEFAULT 0 CHECK(fanout_used>=0))"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority_message_receipts ("
                    "principal TEXT NOT NULL,"
                    "tenant TEXT NOT NULL,"
                    "task_id TEXT NOT NULL,"
                    "message_id TEXT NOT NULL,"
                    "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                    "received_at BIGINT NOT NULL,"
                    "PRIMARY KEY(principal,tenant,task_id,message_id))"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS task_usage ("
                    "tenant TEXT NOT NULL,"
                    "task_id TEXT NOT NULL,"
                    "calls_used BIGINT NOT NULL DEFAULT 0 CHECK(calls_used>=0),"
                    "max_task_calls BIGINT NOT NULL CHECK(max_task_calls>=1),"
                    "PRIMARY KEY(tenant,task_id))"
                )

                missing_authority_usage = connection.execute(
                    "SELECT authority_records.authority_id "
                    "FROM authority_records LEFT JOIN authority_usage USING(authority_id) "
                    "WHERE authority_usage.authority_id IS NULL LIMIT 1"
                ).fetchone()
                if missing_authority_usage is not None:
                    raise AuthorityRegistryError(
                        "PostgreSQL capability usage state is missing for an existing authority"
                    )
                missing_task_usage = connection.execute(
                    "SELECT a.authority_id FROM authority_records a "
                    "LEFT JOIN task_usage t ON t.tenant="
                    "(a.record_json::jsonb->>'tenant') AND t.task_id="
                    "(a.record_json::jsonb->>'task_id') "
                    "WHERE t.tenant IS NULL LIMIT 1"
                ).fetchone()
                if missing_task_usage is not None:
                    raise AuthorityRegistryError(
                        "PostgreSQL aggregate task-usage state is missing for existing authority history"
                    )

                if version < 5:
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
                        "committed_at BIGINT NOT NULL)"
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
                        "version BIGINT NOT NULL CHECK(version>=1),"
                        "authority_id TEXT NOT NULL REFERENCES authority_records(authority_id) ON DELETE RESTRICT,"
                        "request_digest TEXT NOT NULL,"
                        "commit_nonce TEXT NOT NULL UNIQUE REFERENCES paca_resource_commit_receipts(nonce) ON DELETE RESTRICT,"
                        "updated_at BIGINT NOT NULL,"
                        "PRIMARY KEY(tenant,task_id,resource_key))"
                    )
                else:
                    resource_tables = connection.execute(
                        "SELECT to_regclass('paca_resource_commit_receipts') AS receipts,"
                        "to_regclass('paca_resource_values') AS resource_values"
                    ).fetchone()
                    if (
                        resource_tables is None
                        or not resource_tables["receipts"]
                        or not resource_tables["resource_values"]
                    ):
                        raise AuthorityRegistryError(
                            "PostgreSQL resource-commit schema is incomplete; refusing to recreate lost state"
                        )

                if version < 6:
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS paca_resource_provenance ("
                        "tenant TEXT NOT NULL,"
                        "task_id TEXT NOT NULL,"
                        "resource_key TEXT NOT NULL,"
                        "resource_version BIGINT NOT NULL CHECK(resource_version>=1),"
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
                        "created_at BIGINT NOT NULL,"
                        "PRIMARY KEY(session_id,nonce_digest))"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS paca_resource_access_authority_idx "
                        "ON paca_resource_access_receipts(authority_id,created_at)"
                    )
                else:
                    access_tables = connection.execute(
                        "SELECT to_regclass('paca_resource_provenance') AS provenance,"
                        "to_regclass('paca_resource_access_receipts') AS access_receipts"
                    ).fetchone()
                    if (
                        access_tables is None
                        or not access_tables["provenance"]
                        or not access_tables["access_receipts"]
                    ):
                        raise AuthorityRegistryError(
                            "PostgreSQL broker-resource schema is incomplete; refusing to recreate lost state"
                        )

                connection.execute(
                    "INSERT INTO paca_authority_meta(key,value) VALUES('schema_version','6') "
                    "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value"
                )
                connection.execute(
                    "INSERT INTO paca_authority_meta(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO NOTHING",
                    ("authority_store_id", secrets.token_hex(16)),
                )
                store_row = connection.execute(
                    "SELECT value FROM paca_authority_meta WHERE key='authority_store_id'"
                ).fetchone()
                if store_row is None or not store_row["value"]:
                    raise AuthorityRegistryError(
                        "PostgreSQL authority store identity is missing"
                    )
                self.authority_store_id = "postgresql:" + store_row["value"]
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            # The enclosing closing() context releases the session advisory lock.
            # Avoid a second unlock query in finally: it could mask the real
            # schema-initialization error when the connection has already failed.


__all__ = ["PostgresAuthorityRegistry"]
