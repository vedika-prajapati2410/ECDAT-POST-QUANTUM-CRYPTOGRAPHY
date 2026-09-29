"""
Scan history + triage override store, backed by SQLite.

Uses Python's stdlib `sqlite3` -- no new dependency, no separate DB
server to run. This replaces an earlier in-memory version: losing
every scan the moment the process restarts is a real risk during a
live demo (a crash, a redeploy, a laptop sleep/wake), not just a
theoretical "swap this for a real DB later" footnote. The public
interface (save_scan / get_scan / list_scans / previous_scan /
set_override / get_overrides) is unchanged, so app/api.py needed zero
changes to pick this up.

DB file location is configurable via ECDAT_DB_PATH (default:
<project root>/ecdat.db). Delete that file to reset all history.
"""

import sqlite3
import json
import os
import threading

_DB_PATH = os.environ.get(
    "ECDAT_DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ecdat.db"),
)

# sqlite3 connections aren't safe to share across threads, and concurrent
# writers to the same file can hit "database is locked" -- a single
# process-wide lock around writes is enough for a hackathon-scale
# deployment (one Flask process). For real multi-worker production use,
# swap to Postgres, per the original module's guidance.
_WRITE_LOCK = threading.Lock()


def _connect():
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")  # readers don't block on a writer
    return conn


def _init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                artefact_count INTEGER NOT NULL,
                agility_score REAL NOT NULL,
                risk_tier_counts_json TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS overrides (
                scan_id TEXT NOT NULL,
                artefact_id TEXT NOT NULL,
                override_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, artefact_id)
            )
        """)


_init_db()


def save_scan(report: dict):
    scan_id = report["scan_id"]
    with _WRITE_LOCK, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans "
            "(scan_id, created_at, artefact_count, agility_score, risk_tier_counts_json, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                report["created_at"],
                report["artefact_count"],
                report["agility_score"]["score"],
                json.dumps(report["risk_tier_counts"]),
                json.dumps(report),
            ),
        )
    return scan_id


def get_scan(scan_id: str):
    with _connect() as conn:
        row = conn.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None


def previous_scan(scan_id: str):
    """
    The scan immediately before `scan_id` in insertion order, or None
    if `scan_id` is the first/only scan on record. Used for automatic
    trend analysis without the caller needing to track IDs itself.
    """
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT report_json FROM scans
            WHERE seq < (SELECT seq FROM scans WHERE scan_id = ?)
            ORDER BY seq DESC LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def list_scans():
    """Lightweight summaries for the scan history list view, most-recent-first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT scan_id, created_at, artefact_count, agility_score, risk_tier_counts_json "
            "FROM scans ORDER BY seq DESC"
        ).fetchall()
    return [
        {
            "scan_id": r[0],
            "created_at": r[1],
            "artefact_count": r[2],
            "agility_score": r[3],
            "risk_tier_counts": json.loads(r[4]),
        }
        for r in rows
    ]


# --- Triage overrides ---

def set_override(scan_id: str, artefact_id: str, override: dict):
    with _WRITE_LOCK, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO overrides (scan_id, artefact_id, override_json) VALUES (?, ?, ?)",
            (scan_id, artefact_id, json.dumps(override)),
        )


def get_overrides(scan_id: str) -> dict:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT artefact_id, override_json FROM overrides WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return {r[0]: json.loads(r[1]) for r in rows}


# --- Testing / demo convenience ---

def reset_all():
    """Wipe all stored scans and overrides. Handy for tests or starting a demo clean."""
    with _WRITE_LOCK, _connect() as conn:
        conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM overrides")
