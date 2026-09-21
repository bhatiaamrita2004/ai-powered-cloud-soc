"""
FastAPI backend for the SOC platform. Exposes endpoints to run the full
pipeline (ingest -> feature engineer -> detect -> score -> map to MITRE)
and to fetch LLM-generated investigations for specific incidents.
"""

import json
import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
from features import load_events, build_features
from detect import run_detection, evaluate
from mitre_map import build_incidents
from investigate import investigate_incident

app = FastAPI(title="AI-Powered Cloud SOC & Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# in-memory cache, populated on startup / re-ingest
_state = {"events": [], "events_by_id": {}, "incidents": [], "metrics": {}}


def _run_pipeline():
    events = load_events(os.path.join(DATA_DIR, "synthetic_logs.json"))
    df = build_features(events)
    result_df, _, _ = run_detection(df)
    metrics = evaluate(result_df)
    flagged = result_df[result_df["is_flagged"]]
    incidents = build_incidents(flagged)

    _state["events"] = events
    _state["events_by_id"] = {e["eventId"]: e for e in events}
    _state["incidents"] = incidents
    _state["metrics"] = metrics


@app.on_event("startup")
def startup():
    _run_pipeline()


@app.get("/")
def root():
    return {
        "service": "AI-Powered Cloud SOC & Threat Detection API",
        "status": "running",
        "incident_count": len(_state["incidents"]),
    }


@app.post("/ingest")
def ingest():
    """Re-runs the full detection pipeline against the current log data."""
    _run_pipeline()
    return {"status": "ok", "incident_count": len(_state["incidents"]), "metrics": _state["metrics"]}


@app.get("/metrics")
def get_metrics():
    """Detection performance metrics (precision/recall/F1/FPR) vs. ground truth."""
    return _state["metrics"]


@app.get("/alerts")
def get_alerts():
    """All flagged incidents, sorted by risk score (highest first)."""
    return _state["incidents"]


@app.get("/alerts/{incident_id}")
def get_alert(incident_id: str):
    for inc in _state["incidents"]:
        if inc["incident_id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/alerts/{incident_id}/investigate")
def investigate(incident_id: str):
    """LLM-assisted investigation: timeline, evidence summary, next steps."""
    for inc in _state["incidents"]:
        if inc["incident_id"] == incident_id:
            return investigate_incident(inc, _state["events_by_id"])
    raise HTTPException(status_code=404, detail="Incident not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
