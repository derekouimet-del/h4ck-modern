"""results module — persistent scan results storage (results.py)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ResultsDB:
    """SQLite-backed storage for scan findings."""

    def __init__(self, path: str | Path = "local/h4ck_results.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT,
                port INTEGER,
                status INTEGER,
                extra TEXT
            )
            """
        )
        self._conn.commit()

    def add(
        self,
        category: str,
        target: str,
        detail: str = "",
        port: int | None = None,
        status: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO findings (timestamp, category, target, detail, port, status, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                category,
                target,
                detail,
                port,
                status,
                json.dumps(extra or {}),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def all(self) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT id, timestamp, category, target, detail, port, status, extra FROM findings"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def export_json(self, path: str | Path) -> None:
        data = self.all()
        Path(path).write_text(json.dumps(data, indent=2))

    def close(self) -> None:
        self._conn.close()
