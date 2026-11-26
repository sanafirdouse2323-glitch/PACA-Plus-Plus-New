"""Durable, restart-safe storage for PACA++ New information lineage.

This module stores lineage metadata and edges only. It deliberately does not store
memory values; value storage and read authorization live in paca.memory. SQLite is
intended for a local file shared by processes on one host, not multi-host consensus.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import time
from collections.abc import Iterable, Iterator
from contextlib import closing
from pathlib import Path

from .provenance import Label, LineageNode, ProvenanceGraph


class ProvenanceStoreError(RuntimeError):
    """Base error for durable provenance failures."""


class ImmutableLineageConflict(ProvenanceStoreError):
    """An object/version or node identifier was reused with different metadata."""


class LineageIntegrityError(ProvenanceStoreError):
    """Stored lineage metadata failed canonical or graph validation."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _node_from_record(record: str, expected_id: str) -> LineageNode:
    try:
        data = json.loads(record)
        label_data = data["label"]
        label = Label(
            integrity=label_data["integrity"],
            sensitivity=label_data["sensitivity"],
            tenant=None,
            tenants=frozenset(label_data["tenants"]),
            tenant_unknown=label_data["tenant_unknown"],
            origins=frozenset(label_data["origins"]),
        )
        node = LineageNode(
            object_id=data["object_id"],
            version_id=data["version_id"],
            source=data["source"],
            source_class=data["source_class"],
            content_digest=data["content_digest"],
            label=label,
            parent_ids=tuple(data["parent_ids"]),
            transformation=data["transformation"],
            purpose=data["purpose"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LineageIntegrityError("stored lineage record is malformed") from exc
    if _canonical_json(node.as_dict()) != record or node.node_id != expected_id:
        raise LineageIntegrityError(
            "stored lineage record failed canonical digest verification"
        )
    return node


class SQLiteProvenanceRepository:
    """Append-only durable repository for object/version lineage metadata.

    Each mutation uses BEGIN IMMEDIATE and commits the node plus parent edges in a
    single SQLite transaction. Reads reconstruct the graph from committed records,
    validating node digests and all graph invariants. The database is intentionally
    file-backed: using :memory: would falsely imply restart safety.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self, database: str | os.PathLike[str], *, timeout: float = 10.0
    ) -> None:
        raw = os.fspath(database)
        if raw == ":memory:" or not raw:
            raise ValueError(
                "durable provenance requires a file-backed SQLite database"
            )
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.database = Path(raw).expanduser().resolve()
        self.timeout = float(timeout)
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
                    "CREATE TABLE IF NOT EXISTS paca_provenance_meta "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                row = connection.execute(
                    "SELECT value FROM paca_provenance_meta WHERE key='schema_version'"
                ).fetchone()
                version = int(row["value"]) if row else 0
                if version > self.SCHEMA_VERSION:
                    raise ProvenanceStoreError(
                        "database schema is newer than this package"
                    )
                if version < 1:
                    connection.execute(
                        "CREATE TABLE lineage_nodes ("
                        "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "node_id TEXT NOT NULL UNIQUE,"
                        "object_id TEXT NOT NULL,"
                        "version_id TEXT NOT NULL,"
                        "record_json TEXT NOT NULL,"
                        "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
                        "UNIQUE(object_id, version_id))"
                    )
                    connection.execute(
                        "CREATE TABLE lineage_edges ("
                        "child_node_id TEXT NOT NULL REFERENCES lineage_nodes(node_id) ON DELETE RESTRICT,"
                        "parent_node_id TEXT NOT NULL REFERENCES lineage_nodes(node_id) ON DELETE RESTRICT,"
                        "position INTEGER NOT NULL,"
                        "PRIMARY KEY(child_node_id, parent_node_id),"
                        "UNIQUE(child_node_id, position))"
                    )
                    connection.execute(
                        "CREATE INDEX lineage_edges_parent_idx ON lineage_edges(parent_node_id)"
                    )
                    connection.execute(
                        "CREATE TABLE lineage_revocations ("
                        "root_node_id TEXT PRIMARY KEY REFERENCES lineage_nodes(node_id) ON DELETE RESTRICT,"
                        "revoked_at INTEGER NOT NULL,"
                        "reason TEXT NOT NULL)"
                    )
                    connection.execute(
                        "CREATE TABLE lineage_authority_bindings ("
                        "node_id TEXT NOT NULL REFERENCES lineage_nodes(node_id) ON DELETE RESTRICT,"
                        "authority_id TEXT NOT NULL,"
                        "bound_at INTEGER NOT NULL DEFAULT (unixepoch()),"
                        "PRIMARY KEY(node_id, authority_id))"
                    )
                    connection.execute(
                        "INSERT INTO paca_provenance_meta(key,value) VALUES('schema_version','1')"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        # Existing filesystems may not support POSIX permissions. Deployment
        # must still provide a private directory and database ACLs.
        with contextlib.suppress(OSError):
            os.chmod(self.database, 0o600)

    @staticmethod
    def _load_graph(connection: sqlite3.Connection) -> ProvenanceGraph:
        graph = ProvenanceGraph()
        rows = connection.execute(
            "SELECT node_id,object_id,version_id,record_json "
            "FROM lineage_nodes ORDER BY seq"
        ).fetchall()
        expected_edges = set()
        for row in rows:
            node = _node_from_record(row["record_json"], row["node_id"])
            if (
                node.object_id != row["object_id"]
                or node.version_id != row["version_id"]
            ):
                raise LineageIntegrityError(
                    "indexed object/version columns disagree with immutable lineage record"
                )
            try:
                graph.add_lineage_node(node)
            except (TypeError, ValueError) as exc:
                raise LineageIntegrityError(
                    "stored lineage graph failed invariant validation"
                ) from exc
            for position, parent_id in enumerate(node.parent_ids):
                expected_edges.add((node.node_id, parent_id, position))
        edge_rows = connection.execute(
            "SELECT child_node_id,parent_node_id,position "
            "FROM lineage_edges ORDER BY child_node_id,position"
        ).fetchall()
        actual_edges = {
            (row["child_node_id"], row["parent_node_id"], int(row["position"]))
            for row in edge_rows
        }
        if actual_edges != expected_edges:
            raise LineageIntegrityError(
                "durable parent-edge table disagrees with immutable lineage node records"
            )
        return graph

    def add(self, node: LineageNode) -> LineageNode:
        if not isinstance(node, LineageNode):
            raise TypeError("node must be a LineageNode")
        record = _canonical_json(node.as_dict())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT node_id, record_json FROM lineage_nodes "
                    "WHERE object_id=? AND version_id=?",
                    (node.object_id, node.version_id),
                ).fetchone()
                if existing is not None:
                    stored = _node_from_record(
                        existing["record_json"], existing["node_id"]
                    )
                    if stored != node:
                        raise ImmutableLineageConflict(
                            "object/version identifiers are immutable and already have different lineage"
                        )
                    connection.commit()
                    return stored

                graph = self._load_graph(connection)
                try:
                    graph.add_lineage_node(node)
                except ValueError as exc:
                    raise ImmutableLineageConflict(str(exc)) from exc

                connection.execute(
                    "INSERT INTO lineage_nodes(node_id,object_id,version_id,record_json) "
                    "VALUES(?,?,?,?)",
                    (node.node_id, node.object_id, node.version_id, record),
                )
                for position, parent_id in enumerate(node.parent_ids):
                    connection.execute(
                        "INSERT INTO lineage_edges(child_node_id,parent_node_id,position) "
                        "VALUES(?,?,?)",
                        (node.node_id, parent_id, position),
                    )
                connection.commit()
                return node
            except Exception:
                connection.rollback()
                raise

    def get_node(self, node_id: str) -> LineageNode | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT node_id,object_id,version_id,record_json "
                "FROM lineage_nodes WHERE node_id=?",
                (node_id,),
            ).fetchone()
            if row is None:
                return None
            node = _node_from_record(row["record_json"], row["node_id"])
            if (
                node.object_id != row["object_id"]
                or node.version_id != row["version_id"]
            ):
                raise LineageIntegrityError(
                    "indexed object/version columns disagree with immutable lineage record"
                )
            return node

    def get_version(self, object_id: str, version_id: str) -> LineageNode | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT node_id,object_id,version_id,record_json "
                "FROM lineage_nodes WHERE object_id=? AND version_id=?",
                (object_id, version_id),
            ).fetchone()
            if row is None:
                return None
            node = _node_from_record(row["record_json"], row["node_id"])
            if (
                node.object_id != row["object_id"]
                or node.version_id != row["version_id"]
            ):
                raise LineageIntegrityError(
                    "indexed object/version columns disagree with immutable lineage record"
                )
            return node

    def latest_node(self, object_id: str) -> LineageNode | None:
        """Return the latest immutable version of an object, or None when absent."""
        if not isinstance(object_id, str) or not object_id:
            raise ValueError("object_id must be a non-empty string")
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
            row = connection.execute(
                "SELECT node_id,object_id,version_id,record_json FROM lineage_nodes "
                "WHERE object_id=? ORDER BY seq DESC LIMIT 1",
                (object_id,),
            ).fetchone()
        if row is None:
            return None
        node = _node_from_record(row["record_json"], row["node_id"])
        if (
            node.object_id != row["object_id"]
            or node.version_id != row["version_id"]
            or graph.get_node(node.node_id) != node
        ):
            raise LineageIntegrityError(
                "latest object version is inconsistent with the validated graph"
            )
        return node

    def list_nodes(
        self, *, object_id_prefix: str | None = None
    ) -> tuple[LineageNode, ...]:
        """Return a snapshot of immutable node records after validating the DAG and edges."""
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
        nodes = graph.lineage_nodes
        if object_id_prefix is not None:
            if not isinstance(object_id_prefix, str):
                raise TypeError("object_id_prefix must be a string or None")
            return tuple(
                node
                for node in nodes.values()
                if node.object_id.startswith(object_id_prefix)
            )
        return tuple(nodes.values())

    def node_created_at(self, node_id: str) -> int:
        """Return the persisted UTC Unix timestamp for a validated lineage node."""
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node_id must be a non-empty string")
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
            if graph.get_node(node_id) is None:
                raise KeyError(node_id)
            row = connection.execute(
                "SELECT created_at FROM lineage_nodes WHERE node_id=?",
                (node_id,),
            ).fetchone()
        if row is None:
            raise LineageIntegrityError(
                "validated node has no durable creation timestamp"
            )
        return int(row["created_at"])

    def ancestors(self, node_id: str) -> tuple[LineageNode, ...]:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
        try:
            return graph.ancestors(node_id)
        except KeyError:
            raise
        except (TypeError, ValueError, RuntimeError) as exc:
            raise LineageIntegrityError(
                "could not reconstruct lineage ancestry"
            ) from exc

    def snapshot(self) -> dict[str, LineageNode]:
        with closing(self._connect()) as connection:
            graph = self._load_graph(connection)
        return graph.lineage_nodes

    def bind_authority(self, node_id: str, authority_id: str) -> None:
        if not node_id or not authority_id:
            raise ValueError("node_id and authority_id must be non-empty")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if (
                    connection.execute(
                        "SELECT 1 FROM lineage_nodes WHERE node_id=?", (node_id,)
                    ).fetchone()
                    is None
                ):
                    raise KeyError(node_id)
                connection.execute(
                    "INSERT OR IGNORE INTO lineage_authority_bindings(node_id,authority_id) "
                    "VALUES(?,?)",
                    (node_id, authority_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def authority_ids_for_node(self, node_id: str) -> tuple[str, ...]:
        ancestors = self.ancestors(node_id)
        ids = tuple(node.node_id for node in ancestors)
        placeholders = ",".join("?" for _ in ids)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT DISTINCT authority_id FROM lineage_authority_bindings "
                "WHERE node_id IN (" + placeholders + ") ORDER BY authority_id",
                ids,
            ).fetchall()
        return tuple(row["authority_id"] for row in rows)

    @contextlib.contextmanager
    def revocation_guard(self) -> Iterator[None]:
        """Serialize a protected broker operation against lineage revocation.

        The guard holds SQLite's reserved writer lock for this repository until
        the caller finishes its provenance check and protected action. Since
        revoke_lineage() uses BEGIN IMMEDIATE on the same database, a concurrent
        revocation is ordered wholly before or after the guarded operation.

        Callers must keep the guarded section local and bounded. Do not perform
        network I/O or invoke callbacks that mutate this repository while the
        guard is held. This is a single-host SQLite ordering primitive, not a
        distributed transaction or multi-host revocation protocol.
        """
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise ProvenanceStoreError(
                    "could not acquire the provenance revocation guard"
                ) from exc
            try:
                yield
            finally:
                if connection.in_transaction:
                    connection.rollback()

    def revoke_lineage(
        self, root_node_id: str, reason: str, *, revoked_at: int | None = None
    ) -> None:
        if not reason:
            raise ValueError("revocation reason must be non-empty")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if (
                    connection.execute(
                        "SELECT 1 FROM lineage_nodes WHERE node_id=?", (root_node_id,)
                    ).fetchone()
                    is None
                ):
                    raise KeyError(root_node_id)
                connection.execute(
                    "INSERT OR IGNORE INTO lineage_revocations(root_node_id,revoked_at,reason) "
                    "VALUES(?,?,?)",
                    (
                        root_node_id,
                        int(revoked_at if revoked_at is not None else time.time()),
                        reason,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def revoked_nodes(self, node_ids: Iterable[str] | None = None) -> frozenset[str]:
        """Return requested nodes whose own or ancestor lineage has been revoked."""
        requested = None
        if node_ids is not None:
            requested = tuple(node_ids)
            if any(
                not isinstance(node_id, str) or not node_id for node_id in requested
            ):
                raise ValueError("node identifiers must be non-empty strings")
            if not requested:
                return frozenset()
        with closing(self._connect()) as connection:
            self._load_graph(connection)
            rows = connection.execute(
                "WITH RECURSIVE blocked(node_id) AS ("
                " SELECT root_node_id FROM lineage_revocations"
                " UNION"
                " SELECT edge.child_node_id FROM lineage_edges edge"
                " JOIN blocked parent ON edge.parent_node_id=parent.node_id"
                ") SELECT node_id FROM blocked"
            ).fetchall()
        blocked = {row["node_id"] for row in rows}
        return frozenset(
            blocked if requested is None else blocked.intersection(requested)
        )

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self.revoked_nodes((node_id,))

    def __len__(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM lineage_nodes"
            ).fetchone()
        return int(row["count"])


__all__ = [
    "ImmutableLineageConflict",
    "LineageIntegrityError",
    "ProvenanceStoreError",
    "SQLiteProvenanceRepository",
]
