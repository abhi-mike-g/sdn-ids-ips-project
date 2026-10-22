"""SQLite persistence for incidents and their constituent alerts.

Single connection guarded by a lock -- adequate for one orchestrator process
plus the read-mostly API. Swap for Postgres if you ever run multiple writers.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from .models import Alert, Incident, IncidentState


class Store:
    def __init__(self, path: str = "orchestrator.db"):
        if path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    alert_count INTEGER,
                    signatures TEXT,
                    stride TEXT,
                    mitre TEXT,
                    dest_ips TEXT,
                    max_severity INTEGER,
                    max_confidence REAL,
                    state TEXT,
                    action TEXT,
                    action_reason TEXT,
                    mitigation_latency_ms REAL,
                    flow_rule TEXT
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    ts TEXT,
                    src_ip TEXT, dest_ip TEXT,
                    src_port INTEGER, dest_port INTEGER, proto TEXT,
                    signature TEXT, sid INTEGER,
                    severity INTEGER, stride TEXT, mitre TEXT, confidence REAL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_incident
                    ON alerts(incident_id);
                """
            )

    # -- writes -----------------------------------------------------------
    def upsert_incident(self, inc: Incident) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO incidents VALUES
                  (:id,:src_ip,:created_at,:updated_at,:alert_count,:signatures,
                   :stride,:mitre,:dest_ips,:max_severity,:max_confidence,:state,
                   :action,:action_reason,:mitigation_latency_ms,:flow_rule)
                ON CONFLICT(id) DO UPDATE SET
                  updated_at=excluded.updated_at,
                  alert_count=excluded.alert_count,
                  signatures=excluded.signatures,
                  stride=excluded.stride,
                  mitre=excluded.mitre,
                  dest_ips=excluded.dest_ips,
                  max_severity=excluded.max_severity,
                  max_confidence=excluded.max_confidence,
                  state=CASE WHEN incidents.state IN ('resolved', 'false_positive') THEN incidents.state ELSE excluded.state END,
                  action=CASE WHEN incidents.state IN ('resolved', 'false_positive') THEN 'none' ELSE excluded.action END,
                  action_reason=CASE WHEN incidents.state IN ('resolved', 'false_positive') THEN incidents.action_reason ELSE excluded.action_reason END,
                  mitigation_latency_ms=excluded.mitigation_latency_ms,
                  flow_rule=excluded.flow_rule
                """,
                self._inc_row(inc),
            )

    def insert_alert(self, alert: Alert, incident_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO alerts VALUES
                  (:id,:incident_id,:ts,:src_ip,:dest_ip,:src_port,:dest_port,
                   :proto,:signature,:sid,:severity,:stride,:mitre,:confidence)
                """,
                {
                    "id": alert.id, "incident_id": incident_id,
                    "ts": alert.timestamp.isoformat(),
                    "src_ip": alert.src_ip, "dest_ip": alert.dest_ip,
                    "src_port": alert.src_port, "dest_port": alert.dest_port,
                    "proto": alert.proto, "signature": alert.signature,
                    "sid": alert.sid, "severity": int(alert.severity),
                    "stride": alert.stride.value,
                    "mitre": json.dumps(alert.mitre),
                    "confidence": alert.confidence,
                },
            )

    def set_state(self, incident_id: str, state: IncidentState) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE incidents SET state=?, action='none', action_reason='Analyst closed this incident' WHERE id=?",
                (state.value, incident_id),
            )

    # -- reads ------------------------------------------------------------
    def recent_incidents(self, limit: int = 100) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
        return dict(row) if row else None

    def alerts_for(self, incident_id: str, limit: int = 500) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE incident_id=? ORDER BY ts LIMIT ?",
                (incident_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _inc_row(inc: Incident) -> dict:
        return {
            "id": inc.id, "src_ip": inc.src_ip,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat(),
            "alert_count": inc.alert_count,
            "signatures": json.dumps(sorted(inc.signatures)),
            "stride": json.dumps([s.value for s in inc.stride]),
            "mitre": json.dumps(sorted(inc.mitre)),
            "dest_ips": json.dumps(sorted(inc.dest_ips)),
            "max_severity": int(inc.max_severity),
            "max_confidence": inc.max_confidence,
            "state": inc.state.value,
            "action": inc.action.value,
            "action_reason": inc.action_reason,
            "mitigation_latency_ms": inc.mitigation_latency_ms,
            "flow_rule": inc.flow_rule,
        }
