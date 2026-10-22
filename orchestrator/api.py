"""Read + analyst-action REST API over the incident store.

This is what the dashboard should consume. Crucially, /api/stats reports
mitigation latency computed from MEASURED values in the store -- it replaces the
Math.random() performance panels in the old dashboard with real numbers.
"""
from __future__ import annotations

import json
import statistics

from flask import Flask, jsonify, request
from flask_cors import CORS

from .models import IncidentState
from .store import Store


def register_routes(app, store, orchestrator=None):

    @app.get("/api/incidents")
    def incidents():
        limit = max(1, min(request.args.get("limit", 100, type=int), 1000))
        return jsonify(store.recent_incidents(limit))

    @app.get("/api/incidents/<incident_id>")
    def incident(incident_id):
        inc = store.get_incident(incident_id)
        if not inc:
            return jsonify({"error": "not found"}), 404
        inc["alerts"] = store.alerts_for(incident_id)
        return jsonify(inc)

    @app.get("/api/stats")
    def stats():
        incs = store.recent_incidents(1000)
        by_state: dict = {}
        by_severity: dict = {}
        by_stride: dict = {}
        latencies = []
        for i in incs:
            by_state[i["state"]] = by_state.get(i["state"], 0) + 1
            sev = str(i["max_severity"])
            by_severity[sev] = by_severity.get(sev, 0) + 1
            for s in json.loads(i["stride"] or "[]"):
                by_stride[s] = by_stride.get(s, 0) + 1
            if i["mitigation_latency_ms"] is not None:
                latencies.append(i["mitigation_latency_ms"])

        latency = {}
        if latencies:
            latency = {
                "count": len(latencies),
                "min_ms": round(min(latencies), 1),
                "median_ms": round(statistics.median(latencies), 1),
                "max_ms": round(max(latencies), 1),
            }
        return jsonify({
            "total_incidents": len(incs),
            "by_state": by_state,
            "by_severity": by_severity,
            "by_stride": by_stride,
            "mitigation_latency": latency,  # measured, not synthetic
        })

    def change_state(incident_id, state):
        if store.get_incident(incident_id) is None:
            return jsonify(error='not found'), 404
        if orchestrator is None:
            return jsonify(error='Read-only API: no mitigation engine attached'), 503
        try:
            orchestrator.set_incident_state(incident_id, state)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 503

    @app.post("/api/incidents/<incident_id>/resolve")
    def resolve(incident_id):
        error = change_state(incident_id, IncidentState.RESOLVED)
        if error:
            return error
        return jsonify({"id": incident_id, "state": "resolved"})

    @app.post("/api/incidents/<incident_id>/false_positive")
    def false_positive(incident_id):
        error = change_state(incident_id, IncidentState.FALSE_POSITIVE)
        if error:
            return error
        return jsonify({"id": incident_id, "state": "false_positive"})

    return app


def create_app(store: Store, orchestrator=None) -> Flask:
    app = Flask(__name__)
    register_routes(app, store, orchestrator)
    return app
