
"""SQLite persistence for scan history."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

DB_NAME = Path(
    os.environ.get(
        "SCAMSHIELD_DB_PATH",
        Path(__file__).resolve().parent / "scamshield.db"
    )
)


@contextmanager
def get_connection(db_path=None):
    path = Path(db_path) if db_path else DB_NAME
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_table(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                content TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score REAL NOT NULL,
                scan_time TEXT NOT NULL
            )
        """)


def save_scan(scan_type, content, prediction, score, db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO scan_history
            (scan_type, content, prediction, risk_score, scan_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            str(scan_type),
            str(content)[:5000],
            str(prediction),
            float(score),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))


def get_all_scans(db_path=None):
    with get_connection(db_path) as conn:
        return conn.execute("""
            SELECT id, scan_type, content, prediction, risk_score, scan_time
            FROM scan_history ORDER BY id DESC
        """).fetchall()


def get_scan_count(db_path=None):
    with get_connection(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]


def get_high_risk_count(db_path=None):
    with get_connection(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE risk_score >= 70"
        ).fetchone()[0]


def clear_history(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM scan_history")


create_table()
