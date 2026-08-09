from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    upstream_url TEXT NOT NULL,
    public_host TEXT NOT NULL DEFAULT '',
    docker_container_id TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    qr_required INTEGER NOT NULL DEFAULT 0,
    qr_totem_mode INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    config TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    browser_hash TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'pending',
    expires_at INTEGER NOT NULL,
    approved_at INTEGER,
    return_path TEXT NOT NULL DEFAULT '/',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenge_expiry ON challenges(expires_at);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.connect() as connection:
            connection.executescript(SCHEMA)
            project_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(projects)")
            }
            if "qr_totem_mode" not in project_columns:
                connection.execute(
                    "ALTER TABLE projects ADD COLUMN qr_totem_mode INTEGER NOT NULL DEFAULT 0"
                )
            challenge_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(challenges)")
            }
            if "return_path" not in challenge_columns:
                connection.execute(
                    "ALTER TABLE challenges ADD COLUMN return_path TEXT NOT NULL DEFAULT '/'"
                )

    @staticmethod
    def _project(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["qr_required"] = bool(item["qr_required"])
        item["qr_totem_mode"] = bool(item["qr_totem_mode"])
        return item

    @staticmethod
    def _policy(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["config"] = json.loads(item["config"])
        return item

    def projects(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
            return [self._project(row) for row in rows]

    def project(self, project_id: int) -> dict[str, Any] | None:
        with self.connect() as db:
            return self._project(db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def project_by_slug(self, slug: str) -> dict[str, Any] | None:
        with self.connect() as db:
            return self._project(db.execute("SELECT * FROM projects WHERE slug=?", (slug,)).fetchone())

    def project_by_host(self, host: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM projects WHERE lower(public_host)=lower(?) AND enabled=1", (host,)
            ).fetchone()
            return self._project(row)

    def create_project(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """INSERT INTO projects
                (name,slug,upstream_url,public_host,docker_container_id,enabled,qr_required,qr_totem_mode,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    values["name"], values["slug"], values["upstream_url"],
                    values.get("public_host", ""), values.get("docker_container_id", ""),
                    int(values.get("enabled", True)), int(values.get("qr_required", False)),
                    int(values.get("qr_totem_mode", False)), utcnow(),
                ),
            )
            project_id = cursor.lastrowid
        return self.project(project_id)

    def update_project(self, project_id: int, values: dict[str, Any]) -> dict[str, Any] | None:
        allowed = {
            "name", "slug", "upstream_url", "public_host", "docker_container_id",
            "enabled", "qr_required", "qr_totem_mode",
        }
        fields = {key: value for key, value in values.items() if key in allowed}
        if not fields:
            return self.project(project_id)
        for key in ("enabled", "qr_required", "qr_totem_mode"):
            if key in fields:
                fields[key] = int(fields[key])
        clause = ", ".join(f"{key}=?" for key in fields)
        with self._lock, self.connect() as db:
            db.execute(f"UPDATE projects SET {clause} WHERE id=?", (*fields.values(), project_id))
        return self.project(project_id)

    def delete_project(self, project_id: int) -> bool:
        with self._lock, self.connect() as db:
            return db.execute("DELETE FROM projects WHERE id=?", (project_id,)).rowcount > 0

    def policies(self, project_id: int) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM policies WHERE project_id=? ORDER BY priority,id", (project_id,)
            ).fetchall()
            return [self._policy(row) for row in rows]

    def create_policy(self, project_id: int, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """INSERT INTO policies (project_id,type,name,enabled,priority,config,created_at)
                VALUES (?,?,?,?,?,?,?)""",
                (project_id, values["type"], values["name"], int(values.get("enabled", True)),
                 values.get("priority", 100), json.dumps(values.get("config", {})), utcnow()),
            )
            row = db.execute("SELECT * FROM policies WHERE id=?", (cursor.lastrowid,)).fetchone()
            return self._policy(row)

    def delete_policy(self, policy_id: int) -> bool:
        with self._lock, self.connect() as db:
            return db.execute("DELETE FROM policies WHERE id=?", (policy_id,)).rowcount > 0

    def save_challenge(self, values: dict[str, Any]) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                "UPDATE challenges SET state='superseded' WHERE project_id=? AND browser_hash=? AND state='pending'",
                (values["project_id"], values["browser_hash"]),
            )
            db.execute(
                """INSERT INTO challenges
                (id,project_id,browser_hash,token_hash,state,expires_at,return_path,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (values["id"], values["project_id"], values["browser_hash"], values["token_hash"],
                 "pending", values["expires_at"], values.get("return_path", "/"),
                 values["created_at"]),
            )

    def challenge(self, challenge_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
            return dict(row) if row else None

    def challenge_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM challenges WHERE token_hash=?", (token_hash,)).fetchone()
            return dict(row) if row else None

    def approve_challenge(self, challenge_id: str, now: int, state: str = "approved") -> bool:
        if state not in {"approved", "mobile_opened"}:
            raise ValueError("estado de aprovação inválido")
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE challenges SET state=?, approved_at=? WHERE id=? AND state='pending' AND expires_at>=?",
                (state, now, challenge_id, now),
            )
            return cursor.rowcount > 0

    def prune_challenges(self, before: int) -> None:
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM challenges WHERE expires_at<?", (before,))

    def audit(self, project_id: int | None, action: str, outcome: str, client_ip: str = "", **detail) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO audit_events(project_id,action,outcome,client_ip,detail,created_at) VALUES(?,?,?,?,?,?)",
                (project_id, action, outcome, client_ip, json.dumps(detail), utcnow()),
            )

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT e.*,p.name AS project_name FROM audit_events e
                LEFT JOIN projects p ON p.id=e.project_id ORDER BY e.id DESC LIMIT ?""", (limit,)
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["detail"] = json.loads(item["detail"])
                result.append(item)
            return result
