from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "alerts.db"


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            user_name TEXT,
            source_ip TEXT,
            source_ips TEXT,
            prior_failed_ips TEXT,
            target_users TEXT,
            message TEXT NOT NULL,
            count INTEGER,
            timestamp TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    return conn


def save_alerts(alerts: list[dict[str, Any]]) -> None:
    conn = connect_db()
    for alert in alerts:
        conn.execute(
            """
            INSERT INTO alerts (
                alert_type, severity, user_name, source_ip, source_ips,
                prior_failed_ips, target_users, message, count, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("type"),
                alert.get("severity"),
                alert.get("user"),
                alert.get("source_ip"),
                json.dumps(alert.get("source_ips", [])),
                json.dumps(alert.get("prior_failed_ips", [])),
                json.dumps(alert.get("target_users", [])),
                alert.get("message"),
                alert.get("count"),
                alert.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            ),
        )
    conn.commit()
    conn.close()


def get_alerts() -> list[dict[str, Any]]:
    conn = connect_db()
    rows = conn.execute(
        """
        SELECT * FROM alerts ORDER BY id DESC
        """
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(
            {
                "id": row["id"],
                "type": row["alert_type"],
                "severity": row["severity"],
                "user": row["user_name"],
                "source_ip": row["source_ip"],
                "source_ips": json.loads(row["source_ips"] or "[]"),
                "prior_failed_ips": json.loads(row["prior_failed_ips"] or "[]"),
                "target_users": json.loads(row["target_users"] or "[]"),
                "message": row["message"],
                "count": row["count"],
                "timestamp": row["timestamp"],
            }
        )
    return results


def clear_alerts() -> None:
    conn = connect_db()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
