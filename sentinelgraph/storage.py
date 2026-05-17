"""SQLite-backed graph and evidence store."""

from __future__ import annotations

import os
import sqlite3
import threading
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional, TypeVar

from .models import Edge, Entity
from .utils import dumps, loads, utcnow


DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "sentinelgraph.db"
F = TypeVar("F", bound=Callable[..., Any])


class Store:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path or os.environ.get("SENTINELGRAPH_DB", DEFAULT_DB))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                attributes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                relation TEXT NOT NULL,
                attributes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(source, target, relation)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                file TEXT,
                function TEXT,
                cwe TEXT,
                cve TEXT,
                ghsa TEXT,
                service TEXT,
                mr_id TEXT,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                score REAL NOT NULL,
                level TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS control_runs (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                control_id TEXT NOT NULL,
                control_type TEXT NOT NULL,
                scanner TEXT NOT NULL,
                score REAL NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_events (
                id TEXT PRIMARY KEY,
                repo TEXT,
                service TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                signal TEXT NOT NULL,
                code_path TEXT,
                attributes TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                service TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                report TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS compliance_evidence (
                id TEXT PRIMARY KEY,
                framework TEXT NOT NULL,
                control_ref TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS org_configs (
                org_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                repos TEXT NOT NULL,
                token_env TEXT,
                base_url TEXT,
                default_branch TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS background_jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                result TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
            CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
            CREATE INDEX IF NOT EXISTS idx_runtime_service ON runtime_events(service);
            CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status);
            """
        )
        self.conn.commit()

    def reset(self) -> None:
        self.conn.executescript(
            """
            DELETE FROM compliance_evidence;
            DELETE FROM incidents;
            DELETE FROM runtime_events;
            DELETE FROM control_runs;
            DELETE FROM analyses;
            DELETE FROM findings;
            DELETE FROM edges;
            DELETE FROM entities;
            DELETE FROM background_jobs;
            DELETE FROM org_configs;
            """
        )
        self.conn.commit()

    def upsert_entity(self, entity: Entity) -> Entity:
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO entities(id, type, name, attributes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              type=excluded.type,
              name=excluded.name,
              attributes=excluded.attributes,
              updated_at=excluded.updated_at
            """,
            (entity.id, entity.type, entity.name, dumps(entity.attributes), now, now),
        )
        self.conn.commit()
        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        row = self.conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, entity_type: str | None = None) -> List[Entity]:
        if entity_type:
            rows = self.conn.execute(
                "SELECT * FROM entities WHERE type = ? ORDER BY updated_at DESC", (entity_type,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM entities ORDER BY updated_at DESC").fetchall()
        return [self._entity_from_row(row) for row in rows]

    def search_entities(self, text: str, entity_type: str | None = None) -> List[Entity]:
        pattern = f"%{text.lower()}%"
        if entity_type:
            rows = self.conn.execute(
                """
                SELECT * FROM entities
                WHERE type = ? AND (lower(name) LIKE ? OR lower(attributes) LIKE ?)
                ORDER BY updated_at DESC
                """,
                (entity_type, pattern, pattern),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT * FROM entities
                WHERE lower(name) LIKE ? OR lower(attributes) LIKE ?
                ORDER BY updated_at DESC
                """,
                (pattern, pattern),
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def upsert_edge(self, edge: Edge) -> Edge:
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO edges(source, target, relation, attributes, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source, target, relation) DO UPDATE SET
              attributes=excluded.attributes
            """,
            (edge.source, edge.target, edge.relation, dumps(edge.attributes), now),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM edges WHERE source = ? AND target = ? AND relation = ?",
            (edge.source, edge.target, edge.relation),
        ).fetchone()
        return self._edge_from_row(row)

    def list_edges(self, source: str | None = None, target: str | None = None) -> List[Edge]:
        if source and target:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE source = ? OR target = ? ORDER BY id", (source, target)
            ).fetchall()
        elif source:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE source = ? ORDER BY id", (source,)
            ).fetchall()
        elif target:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE target = ? ORDER BY id", (target,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM edges ORDER BY id").fetchall()
        return [self._edge_from_row(row) for row in rows]

    def neighbors(self, entity_id: str) -> List[tuple[Edge, Entity]]:
        rows = self.conn.execute(
            """
            SELECT e.*, n.id AS n_id, n.type AS n_type, n.name AS n_name, n.attributes AS n_attributes
            FROM edges e
            JOIN entities n ON n.id = e.target
            WHERE e.source = ?
            UNION ALL
            SELECT e.*, n.id AS n_id, n.type AS n_type, n.name AS n_name, n.attributes AS n_attributes
            FROM edges e
            JOIN entities n ON n.id = e.source
            WHERE e.target = ?
            """,
            (entity_id, entity_id),
        ).fetchall()
        result: List[tuple[Edge, Entity]] = []
        for row in rows:
            edge = Edge(
                id=row["id"],
                source=row["source"],
                target=row["target"],
                relation=row["relation"],
                attributes=loads(row["attributes"], {}),
            )
            entity = Entity(
                id=row["n_id"],
                type=row["n_type"],
                name=row["n_name"],
                attributes=loads(row["n_attributes"], {}),
            )
            result.append((edge, entity))
        return result

    def insert_finding(self, finding_id: str, payload: dict[str, Any]) -> None:
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO findings(
              id, repo, title, category, severity, file, function, cwe, cve, ghsa,
              service, mr_id, status, evidence, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              title=excluded.title,
              severity=excluded.severity,
              status=excluded.status,
              evidence=excluded.evidence
            """,
            (
                finding_id,
                payload["repo"],
                payload["title"],
                payload["category"],
                payload["severity"],
                payload.get("file"),
                payload.get("function"),
                payload.get("cwe"),
                payload.get("cve"),
                payload.get("ghsa"),
                payload.get("service"),
                payload.get("mr_id"),
                payload.get("status", "open"),
                dumps(payload.get("evidence", {})),
                now,
            ),
        )
        self.conn.commit()

    def list_findings(self, repo: str | None = None) -> List[dict[str, Any]]:
        if repo:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE repo = ? ORDER BY created_at DESC", (repo,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
        return [dict(row) | {"evidence": loads(row["evidence"], {})} for row in rows]

    def insert_analysis(
        self,
        analysis_id: str,
        repo: str,
        subject_id: str,
        subject_type: str,
        score: float,
        level: str,
        payload: dict[str, Any],
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO analyses
            (id, repo, subject_id, subject_type, score, level, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (analysis_id, repo, subject_id, subject_type, score, level, dumps(payload), utcnow()),
        )
        self.conn.commit()

    def list_analyses(self, repo: str | None = None) -> List[dict[str, Any]]:
        if repo:
            rows = self.conn.execute(
                "SELECT * FROM analyses WHERE repo = ? ORDER BY created_at DESC", (repo,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM analyses ORDER BY created_at DESC").fetchall()
        return [dict(row) | {"payload": loads(row["payload"], {})} for row in rows]

    def insert_control_run(self, run_id: str, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO control_runs
            (id, repo, control_id, control_type, scanner, score, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                payload["repo"],
                payload["control_id"],
                payload["control_type"],
                payload["scanner"],
                payload["score"],
                dumps(payload),
                utcnow(),
            ),
        )
        self.conn.commit()

    def latest_control_runs(self, repo: str | None = None) -> List[dict[str, Any]]:
        if repo:
            rows = self.conn.execute(
                "SELECT * FROM control_runs WHERE repo = ? ORDER BY created_at DESC", (repo,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM control_runs ORDER BY created_at DESC").fetchall()
        return [dict(row) | {"payload": loads(row["payload"], {})} for row in rows]

    def insert_runtime_event(self, event_id: str, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO runtime_events
            (id, repo, service, source, event_type, severity, signal, code_path, attributes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                payload.get("repo"),
                payload["service"],
                payload["source"],
                payload["event_type"],
                payload["severity"],
                payload["signal"],
                payload.get("code_path"),
                dumps(payload.get("attributes", {})),
                utcnow(),
            ),
        )
        self.conn.commit()

    def list_runtime_events(self, repo: str | None = None, service: str | None = None) -> List[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if repo:
            clauses.append("repo = ?")
            params.append(repo)
        if service:
            clauses.append("service = ?")
            params.append(service)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM runtime_events {where} ORDER BY created_at DESC", params
        ).fetchall()
        return [dict(row) | {"attributes": loads(row["attributes"], {})} for row in rows]

    def insert_incident(self, incident_id: str, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO incidents
            (id, repo, service, title, severity, report, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                payload["repo"],
                payload["service"],
                payload["title"],
                payload["severity"],
                dumps(payload),
                utcnow(),
            ),
        )
        self.conn.commit()

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        return dict(row) | {"report": loads(row["report"], {})}

    def list_incidents(self, repo: str | None = None) -> List[dict[str, Any]]:
        if repo:
            rows = self.conn.execute(
                "SELECT * FROM incidents WHERE repo = ? ORDER BY created_at DESC", (repo,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [dict(row) | {"report": loads(row["report"], {})} for row in rows]

    def insert_compliance_evidence(self, evidence_id: str, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO compliance_evidence
            (id, framework, control_ref, subject_id, status, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                payload["framework"],
                payload["control_ref"],
                payload["subject_id"],
                payload["status"],
                dumps(payload.get("evidence", {})),
                utcnow(),
            ),
        )
        self.conn.commit()

    def list_compliance_evidence(self) -> List[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM compliance_evidence ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) | {"evidence": loads(row["evidence"], {})} for row in rows]

    def upsert_org_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO org_configs(org_id, provider, repos, token_env, base_url, default_branch, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id) DO UPDATE SET
              provider=excluded.provider,
              repos=excluded.repos,
              token_env=excluded.token_env,
              base_url=excluded.base_url,
              default_branch=excluded.default_branch,
              metadata=excluded.metadata,
              updated_at=excluded.updated_at
            """,
            (
                payload["org_id"],
                payload["provider"],
                dumps(payload.get("repos", [])),
                payload.get("token_env"),
                payload.get("base_url"),
                payload.get("default_branch", "main"),
                dumps(payload.get("metadata", {})),
                now,
                now,
            ),
        )
        self.conn.commit()
        return payload

    def list_org_configs(self) -> List[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM org_configs ORDER BY updated_at DESC").fetchall()
        return [
            dict(row)
            | {
                "repos": loads(row["repos"], []),
                "metadata": loads(row["metadata"], {}),
            }
            for row in rows
        ]

    def upsert_background_job(
        self,
        job_id: str,
        kind: str,
        status: str,
        payload: dict[str, Any],
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO background_jobs(id, kind, status, payload, result, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              status=excluded.status,
              payload=excluded.payload,
              result=excluded.result,
              error=excluded.error,
              updated_at=excluded.updated_at
            """,
            (job_id, kind, status, dumps(payload), dumps(result or {}), error, now, now),
        )
        self.conn.commit()
        return self.get_background_job(job_id) or {}

    def get_background_job(self, job_id: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM background_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job_from_row(row) if row else None

    def list_background_jobs(self) -> List[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM background_jobs ORDER BY updated_at DESC").fetchall()
        return [self._job_from_row(row) for row in rows]

    def counts(self) -> dict[str, int]:
        tables = [
            "entities",
            "edges",
            "findings",
            "analyses",
            "control_runs",
            "runtime_events",
            "incidents",
            "compliance_evidence",
            "org_configs",
            "background_jobs",
        ]
        result = {}
        for table in tables:
            row = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            result[table] = int(row["count"])
        return result

    def close(self) -> None:
        self.conn.close()

    @staticmethod
    def _entity_from_row(row: sqlite3.Row) -> Entity:
        return Entity(
            id=row["id"],
            type=row["type"],
            name=row["name"],
            attributes=loads(row["attributes"], {}),
        )

    @staticmethod
    def _edge_from_row(row: sqlite3.Row) -> Edge:
        return Edge(
            id=row["id"],
            source=row["source"],
            target=row["target"],
            relation=row["relation"],
            attributes=loads(row["attributes"], {}),
        )

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row) | {
            "payload": loads(row["payload"], {}),
            "result": loads(row["result"], {}),
        }


def connect(path: str | os.PathLike[str] | None = None) -> Store:
    return Store(path)


def _locked(method: F) -> F:
    @wraps(method)
    def wrapper(self: Store, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


for _method_name in [
    "init_schema",
    "reset",
    "upsert_entity",
    "get_entity",
    "list_entities",
    "search_entities",
    "upsert_edge",
    "list_edges",
    "neighbors",
    "insert_finding",
    "list_findings",
    "insert_analysis",
    "list_analyses",
    "insert_control_run",
    "latest_control_runs",
    "insert_runtime_event",
    "list_runtime_events",
    "insert_incident",
    "get_incident",
    "list_incidents",
    "insert_compliance_evidence",
    "list_compliance_evidence",
    "upsert_org_config",
    "list_org_configs",
    "upsert_background_job",
    "get_background_job",
    "list_background_jobs",
    "counts",
    "close",
]:
    setattr(Store, _method_name, _locked(getattr(Store, _method_name)))
