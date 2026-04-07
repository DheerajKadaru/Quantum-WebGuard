import sqlite3
from pathlib import Path
from typing import Dict, List, Optional


DB_PATH = Path("scan_history.db")


def get_connection() -> sqlite3.Connection:
    """Create a SQLite connection with row access by column name."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Initialize history table if it does not exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.commit()


def log_scan(url: str, prediction: str, confidence: float, timestamp: str) -> int:
    """Insert a scan record and return the inserted row id."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (url, prediction, confidence, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (url, prediction, confidence, timestamp),
        )
        connection.commit()
        return int(cursor.lastrowid)


def get_recent_scans(limit: int = 20) -> List[Dict]:
    """Fetch most recent scan rows for dashboard table."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, url, prediction, confidence, timestamp
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    """Fetch one scan row for report generation."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, url, prediction, confidence, timestamp
            FROM scan_history
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    return dict(row) if row else None


def get_stats() -> Dict[str, float]:
    """Return aggregate statistics for admin and homepage counters."""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        malicious = connection.execute(
            "SELECT COUNT(*) FROM scan_history WHERE prediction = ?",
            ("Malicious",),
        ).fetchone()[0]
        safe = connection.execute(
            "SELECT COUNT(*) FROM scan_history WHERE prediction = ?",
            ("Safe",),
        ).fetchone()[0]

    detection_rate = (malicious / total * 100.0) if total else 0.0
    return {
        "total_scans": int(total),
        "malicious_scans": int(malicious),
        "safe_scans": int(safe),
        "detection_percentage": detection_rate,
    }
