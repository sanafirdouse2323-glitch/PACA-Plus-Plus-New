"""Durable transactional operation and single-use token state.

SQLite gives restart-safe, multi-process coordination on one host when every
worker uses the same local database file. It is not a multi-host database.
Deployments spanning hosts must implement the same contract with a transactional
server database such as PostgreSQL.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Iterable, Iterator, Optional, Protocol, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime import Capability


class LedgerError(RuntimeError):
    """Base class for fail-closed ledger errors."""


class CapabilityConflict(LedgerError):
    """A capability identifier was reused with different authority."""


@dataclass(frozen=True)
class LedgerState:
    calls: int
    strikes: int
    destinations: FrozenSet[str]


def task_scope_key(tenant: str, task_id: str) -> str:
    """Return a stable opaque identity for one tenant's task namespace.

    Task identifiers are application supplied and are not globally unique. All
    task-wide counters must therefore be keyed by both authenticated tenant and
    task ID, not by the task ID alone.
    """
    if not isinstance(tenant, str) or not tenant:
        raise ValueError("tenant must be a non-empty string")
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("task_id must be a non-empty string")
    encoded = json.dumps(
        [tenant, task_id], separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class OperationLedger(Protocol):
    """Storage contract consumed by the reference Monitor."""

    def register_capability(self, capability: "Capability") -> LedgerState: ...
    def issue_authorization(
        self, capability: "Capability", action: str, digest: str,
        checks: Iterable[str], destination: Optional[str],
        consequential: bool, quarantine_after: int,
    ) -> Tuple[Optional[str], Optional[str]]: ...
    def record_decision(
        self, capability: "Capability", action: str, digest: str,
        verdict: str, checks: Iterable[str], consequential: bool,
    ) -> None: ...
    def consume_token(self, token: str, digest: str) -> bool: ...


class SQLiteOperationLedger:
    """SQLite-backed ledger with atomic call-budget and token transitions.

    The database path is trusted deployment configuration. Use a private local
    filesystem, protect backups, and keep the database on persistent storage.
    SQLite serializes writers with BEGIN IMMEDIATE. Do not put this database on
    an untrusted or network filesystem or treat this backend as multi-host state.
    """

    def __init__(
        self,
        database: str | os.PathLike[str],
        token_ttl_seconds: float = 60.0,
        timeout_seconds: float = 10.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if token_ttl_seconds <= 0 or timeout_seconds <= 0:
            raise ValueError("ledger timeouts must be positive")
        raw_path = os.fspath(database)
        if raw_path == ":memory:":
            raise ValueError("a persistent file-backed database is required")
        self.path = os.path.abspath(raw_path)
        self.token_ttl_seconds = float(token_ttl_seconds)
        self.timeout_seconds = float(timeout_seconds)
        self._clock = clock
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        if os.path.islink(self.path):
            raise ValueError("ledger database path must not be a symlink")
        try:
            fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path, timeout=self.timeout_seconds, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialise(self) -> None:
        # Multiple workers may start simultaneously against a newly-created file.
        # journal_mode changes require a schema-level lock, and SQLite may report
        # SQLITE_BUSY immediately for that PRAGMA despite busy_timeout. Retry the
        # complete idempotent initialization for a bounded period.
        deadline = time.monotonic() + self.timeout_seconds
        delay = 0.02
        while True:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = FULL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS capability_state (
                        cap_id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        authority_digest TEXT NOT NULL,
                        calls INTEGER NOT NULL DEFAULT 0 CHECK (calls >= 0)
                    );
                    CREATE TABLE IF NOT EXISTS task_state (
                        task_scope TEXT PRIMARY KEY,
                        strikes INTEGER NOT NULL DEFAULT 0 CHECK (strikes >= 0)
                    );
                    CREATE TABLE IF NOT EXISTS destinations (
                        task_scope TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        PRIMARY KEY (task_scope, destination)
                    );
                    CREATE TABLE IF NOT EXISTS operations (
                        operation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cap_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        checks_json TEXT NOT NULL,
                        execution_state TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS tokens (
                        token_hash TEXT PRIMARY KEY,
                        operation_id INTEGER NOT NULL REFERENCES operations(operation_id),
                        request_digest TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired')),
                        issued_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        consumed_at REAL
                    );
                    CREATE INDEX IF NOT EXISTS operations_task_created
                        ON operations(task_id, created_at);
                    """
                )
                self._validate_scope_schema(conn)
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise LedgerError(
                        "could not initialise persistent operation ledger"
                    ) from exc
                time.sleep(delay)
                delay = min(delay * 2, 0.25)
            except sqlite3.Error as exc:
                raise LedgerError(
                    "could not initialise persistent operation ledger"
                ) from exc
            finally:
                conn.close()

    @staticmethod
    def _validate_scope_schema(conn: sqlite3.Connection) -> None:
        """Validate or safely initialize tenant-scoped task-state tables.

        Earlier unversioned databases keyed task counters by task_id alone. There
        is no trustworthy tenant mapping in those rows. A populated legacy
        database must therefore fail closed and be migrated offline with an
        operator-reviewed task-to-tenant mapping; silently copying or resetting
        counters could weaken quotas or quarantine guarantees.
        """
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ledger_meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            version_row = conn.execute(
                "SELECT value FROM ledger_meta WHERE key='schema_version'"
            ).fetchone()
            task_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(task_state)")
            }
            destination_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(destinations)")
            }

            if version_row is None:
                populated = False
                for table in (
                    "capability_state", "task_state", "destinations", "operations", "tokens",
                ):
                    if conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                        populated = True
                        break
                if populated:
                    raise LedgerError(
                        "unversioned ledger contains persisted state keyed without tenant scope; "
                        "a reviewed offline migration with trusted task-to-tenant mappings is required"
                    )

                # Only empty legacy tables can be recreated automatically. This
                # avoids silently resetting existing call, strike, fan-out or
                # single-use-token state when upgrading an older installation.
                if (
                    "task_id" in task_columns
                    or "task_scope" not in task_columns
                    or "task_id" in destination_columns
                    or "task_scope" not in destination_columns
                ):
                    conn.execute("DROP TABLE IF EXISTS destinations")
                    conn.execute("DROP TABLE IF EXISTS task_state")
                    conn.execute(
                        "CREATE TABLE task_state ("
                        "task_scope TEXT PRIMARY KEY,"
                        "strikes INTEGER NOT NULL DEFAULT 0 CHECK (strikes >= 0))"
                    )
                    conn.execute(
                        "CREATE TABLE destinations ("
                        "task_scope TEXT NOT NULL,"
                        "destination TEXT NOT NULL,"
                        "PRIMARY KEY (task_scope, destination))"
                    )
                conn.execute(
                    "INSERT INTO ledger_meta(key,value) VALUES('schema_version','2')"
                )
            else:
                try:
                    version = int(version_row["value"])
                except (TypeError, ValueError) as exc:
                    raise LedgerError("operation ledger schema version is invalid") from exc
                if (
                    version != 2
                    or "task_scope" not in task_columns
                    or "task_scope" not in destination_columns
                ):
                    raise LedgerError("operation ledger schema is unsupported or inconsistent")
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    @staticmethod
    def _authority_digest(capability: "Capability") -> str:
        authority: Dict[str, object] = {
            "principal": capability.principal,
            "tenant": capability.tenant,
            "task_id": capability.task_id,
            "role": capability.role,
            "grants": {
                action: sorted(patterns)
                for action, patterns in sorted(capability.grants.items())
            },
            "expires": capability.expires,
            "max_calls": capability.max_calls,
            "max_fanout": capability.max_fanout,
            "tool_pins": dict(sorted(capability.tool_pins.items())),
            "parent": capability.parent,
        }
        payload = json.dumps(
            authority, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _ensure_capability(
        self, conn: sqlite3.Connection, capability: "Capability"
    ) -> None:
        fingerprint = self._authority_digest(capability)
        row = conn.execute(
            "SELECT task_id, authority_digest FROM capability_state WHERE cap_id = ?",
            (capability.cap_id,),
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO capability_state
                   (cap_id, task_id, authority_digest, calls) VALUES (?, ?, ?, 0)""",
                (capability.cap_id, capability.task_id, fingerprint),
            )
        elif row["task_id"] != capability.task_id or row["authority_digest"] != fingerprint:
            raise CapabilityConflict(
                "capability identifier is already bound to different authority"
            )
        scope = task_scope_key(capability.tenant, capability.task_id)
        conn.execute(
            "INSERT INTO task_state(task_scope, strikes) VALUES (?, 0) "
            "ON CONFLICT(task_scope) DO NOTHING",
            (scope,),
        )

    @staticmethod
    def _read_state(
        conn: sqlite3.Connection, capability: "Capability"
    ) -> LedgerState:
        cap_row = conn.execute(
            "SELECT calls FROM capability_state WHERE cap_id = ?",
            (capability.cap_id,),
        ).fetchone()
        scope = task_scope_key(capability.tenant, capability.task_id)
        task_row = conn.execute(
            "SELECT strikes FROM task_state WHERE task_scope = ?",
            (scope,),
        ).fetchone()
        dest_rows = conn.execute(
            "SELECT destination FROM destinations WHERE task_scope = ?",
            (scope,),
        ).fetchall()
        if cap_row is None or task_row is None:
            raise LedgerError("capability state disappeared during transaction")
        return LedgerState(
            calls=int(cap_row["calls"]),
            strikes=int(task_row["strikes"]),
            destinations=frozenset(str(row["destination"]) for row in dest_rows),
        )

    def register_capability(self, capability: "Capability") -> LedgerState:
        try:
            with self._transaction() as conn:
                self._ensure_capability(conn, capability)
                return self._read_state(conn, capability)
        except (CapabilityConflict, LedgerError):
            raise
        except sqlite3.Error as exc:
            raise LedgerError("could not read persistent capability state") from exc

    @staticmethod
    def _insert_operation(
        conn: sqlite3.Connection,
        capability: "Capability",
        action: str,
        digest: str,
        verdict: str,
        checks: Iterable[str],
        execution_state: str,
        created_at: float,
    ) -> int:
        cursor = conn.execute(
            """INSERT INTO operations
               (cap_id, task_id, action, request_digest, decision, checks_json,
                execution_state, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                capability.cap_id, capability.task_id, action, digest, verdict,
                json.dumps(sorted(set(checks)), separators=(",", ":")),
                execution_state, created_at,
            ),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _increment_strike(
        conn: sqlite3.Connection, capability: "Capability", consequential: bool
    ) -> None:
        if consequential:
            conn.execute(
                "UPDATE task_state SET strikes = strikes + 1 WHERE task_scope = ?",
                (task_scope_key(capability.tenant, capability.task_id),),
            )

    def issue_authorization(
        self,
        capability: "Capability",
        action: str,
        digest: str,
        checks: Iterable[str] = (),
        destination: Optional[str] = None,
        consequential: bool = True,
        quarantine_after: int = 3,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Atomically reserve budgets and issue a random single-use token.

        Returns (token, None) on success or (None, failure_check) on a
        transactionally detected C12, C2 or C8 limit.
        """
        now = float(self._clock())
        base_checks = set(checks)
        try:
            with self._transaction() as conn:
                self._ensure_capability(conn, capability)
                state = self._read_state(conn, capability)
                failure: Optional[str] = None
                if consequential and state.strikes >= quarantine_after:
                    failure = "C12"
                elif state.calls >= capability.max_calls:
                    failure = "C2"
                elif (
                    destination
                    and destination not in state.destinations
                    and len(state.destinations) >= capability.max_fanout
                ):
                    failure = "C8"

                if failure is not None:
                    self._insert_operation(
                        conn, capability, action, digest, "deny",
                        base_checks | {failure}, "not_executed", now,
                    )
                    self._increment_strike(conn, capability, consequential)
                    return None, failure

                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
                operation_id = self._insert_operation(
                    conn, capability, action, digest, "allow",
                    base_checks, "issued", now,
                )
                conn.execute(
                    "UPDATE capability_state SET calls = calls + 1 WHERE cap_id = ?",
                    (capability.cap_id,),
                )
                if destination:
                    conn.execute(
                        "INSERT INTO destinations(task_scope, destination) VALUES (?, ?) "
                        "ON CONFLICT(task_scope, destination) DO NOTHING",
                        (task_scope_key(capability.tenant, capability.task_id), destination),
                    )
                conn.execute(
                    """INSERT INTO tokens
                       (token_hash, operation_id, request_digest, state, issued_at, expires_at)
                       VALUES (?, ?, ?, 'issued', ?, ?)""",
                    (
                        token_hash, operation_id, digest, now,
                        now + self.token_ttl_seconds,
                    ),
                )
                return raw_token, None
        except (CapabilityConflict, LedgerError):
            raise
        except sqlite3.Error as exc:
            raise LedgerError("could not atomically issue authorisation token") from exc

    def record_decision(
        self,
        capability: "Capability",
        action: str,
        digest: str,
        verdict: str,
        checks: Iterable[str] = (),
        consequential: bool = True,
    ) -> None:
        if verdict not in {"deny", "needs_approval"}:
            raise ValueError("record_decision accepts only non-authorising verdicts")
        now = float(self._clock())
        try:
            with self._transaction() as conn:
                self._ensure_capability(conn, capability)
                self._insert_operation(
                    conn, capability, action, digest, verdict,
                    checks, "not_executed", now,
                )
                if verdict == "deny":
                    self._increment_strike(conn, capability, consequential)
        except (CapabilityConflict, LedgerError):
            raise
        except sqlite3.Error as exc:
            raise LedgerError("could not persist authorisation decision") from exc

    def consume_token(self, token: str, digest: str) -> bool:
        """Atomically consume a token once, only for its exact digest and TTL."""
        if not isinstance(token, str) or not token:
            return False
        now = float(self._clock())
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    """SELECT operation_id, request_digest, state, expires_at
                       FROM tokens WHERE token_hash = ?""",
                    (token_hash,),
                ).fetchone()
                if row is None or row["state"] != "issued" or row["request_digest"] != digest:
                    return False
                operation_id = int(row["operation_id"])
                if float(row["expires_at"]) <= now:
                    conn.execute(
                        "UPDATE tokens SET state = 'expired' WHERE token_hash = ? AND state = 'issued'",
                        (token_hash,),
                    )
                    conn.execute(
                        "UPDATE operations SET execution_state = 'expired' WHERE operation_id = ?",
                        (operation_id,),
                    )
                    return False
                updated = conn.execute(
                    """UPDATE tokens SET state = 'consumed', consumed_at = ?
                       WHERE token_hash = ? AND state = 'issued'
                         AND request_digest = ? AND expires_at > ?""",
                    (now, token_hash, digest, now),
                )
                if updated.rowcount != 1:
                    return False
                conn.execute(
                    "UPDATE operations SET execution_state = 'consumed' WHERE operation_id = ?",
                    (operation_id,),
                )
                return True
        except sqlite3.Error as exc:
            raise LedgerError("could not atomically consume authorisation token") from exc

    def operations(
        self, task_id: Optional[str] = None
    ) -> Tuple[Dict[str, object], ...]:
        """Return diagnostic snapshots; never expose raw authorisation tokens."""
        conn = self._connect()
        try:
            if task_id is None:
                rows = conn.execute(
                    """SELECT operation_id, cap_id, task_id, action, request_digest,
                              decision, checks_json, execution_state, created_at
                       FROM operations ORDER BY operation_id"""
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT operation_id, cap_id, task_id, action, request_digest,
                              decision, checks_json, execution_state, created_at
                       FROM operations WHERE task_id = ? ORDER BY operation_id""",
                    (task_id,),
                ).fetchall()
            return tuple(
                {
                    "operation_id": int(row["operation_id"]),
                    "cap_id": str(row["cap_id"]),
                    "task_id": str(row["task_id"]),
                    "action": str(row["action"]),
                    "request_digest": str(row["request_digest"]),
                    "decision": str(row["decision"]),
                    "checks": tuple(json.loads(row["checks_json"])),
                    "execution_state": str(row["execution_state"]),
                    "created_at": float(row["created_at"]),
                }
                for row in rows
            )
        except sqlite3.Error as exc:
            raise LedgerError("could not read operation history") from exc
        finally:
            conn.close()


__all__ = [
    "CapabilityConflict",
    "LedgerError",
    "LedgerState",
    "OperationLedger",
    "SQLiteOperationLedger",
    "task_scope_key",
]
