import sqlite3

from inlock.store import Store


def test_existing_database_gains_totem_columns(tmp_path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, upstream_url TEXT NOT NULL,
                public_host TEXT NOT NULL DEFAULT '', docker_container_id TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1, qr_required INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE challenges (
                id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
                browser_hash TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL DEFAULT 'pending', expires_at INTEGER NOT NULL,
                approved_at INTEGER, created_at INTEGER NOT NULL
            );
        """)

    store = Store(database)

    with sqlite3.connect(database) as connection:
        project_columns = {row[1] for row in connection.execute("PRAGMA table_info(projects)")}
        challenge_columns = {row[1] for row in connection.execute("PRAGMA table_info(challenges)")}
        probe_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='browser_probes'"
        ).fetchone()
    assert "qr_totem_mode" in project_columns
    assert "return_path" in challenge_columns
    assert probe_table

    store.audit(None, "bot.challenge", "failed", "203.0.113.8")
    store.audit(None, "bot.challenge", "failed", "203.0.113.8")
    score, counts = store.ip_reputation_score("203.0.113.8", "2000-01-01T00:00:00+00:00")
    assert score == 30
    assert counts["bot.challenge:failed"] == 2
