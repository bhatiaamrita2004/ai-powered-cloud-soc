# AI-Powered Cloud SOC & Threat Detection Platform

A cloud security monitoring platform that ingests AWS-style security logs,
detects anomalous authentication/IAM/data-access behavior using unsupervised
machine learning, maps detections to MITRE ATT&CK, computes a weighted risk
score, and uses an LLM to generate human-readable incident investigations.

## Architecture

```
Synthetic AWS Logs (CloudTrail-style JSON)
        |
        v
Feature Engineering  ->  per-(user, day) behavioral features
        |                (login freq, geo deviation, privesc calls, data volume)
        v
Isolation Forest      ->  unsupervised anomaly detection
        |                (no labeled attack data required)
        v
MITRE ATT&CK Mapping  ->  signals -> techniques -> tactics
   + Risk Scoring          weighted: anomaly score + technique severity + frequency
        |
        v
LLM Investigation      ->  retrieves incident's raw events, generates
                            timeline + evidence summary + next steps
        |
        v
  FastAPI Backend  <---->  Streamlit Dashboard
```

## Why these design choices

- **Isolation Forest, not XGBoost**: real-world attack labels are scarce.
  An unsupervised model learns "normal" behavior and flags statistical
  outliers, so it doesn't depend on having pre-labeled attack examples.
- **Synthetic data with hidden ground truth**: normal behavior + injected
  anomalies (geo-anomalous logins, privilege-escalation bursts,
  large data transfers) are generated with a hidden `is_anomaly` label,
  used only to *evaluate* the model after the fact — never as a training input.
- **LLM investigation is grounded, not free-form**: the LLM only receives
  the specific retrieved events for one incident and is instructed to use
  only that data, reducing hallucination risk. Falls back to a deterministic
  template if no API key is configured, so the app runs standalone.

## Results (on synthetic test data)

Run against 2,167 synthetic events (39 injected anomalous behavior windows
out of 286 total user/day windows):

| Metric | Value |
|---|---|
| Detection rate (recall) | 89.7% |
| Precision | 100% |
| False positive rate | 0% |
| F1 score | 0.946 |
| Incidents generated | 35 |

*(Contamination parameter tuned via a small sweep — see `src/detect.py`.)*

## Project structure

```
soc-project/
├── data/
│   └── generate_logs.py      # synthetic AWS CloudTrail-style log generator
├── src/
│   ├── features.py           # behavioral feature engineering
│   ├── detect.py             # Isolation Forest anomaly detection + eval
│   ├── mitre_map.py          # MITRE ATT&CK mapping + risk scoring
│   ├── investigate.py        # LLM-assisted investigation layer
│   └── api.py                # FastAPI backend
├── dashboard/
│   └── app.py                # Streamlit SOC dashboard
├── run_pipeline.py           # runs the entire pipeline end-to-end, CLI
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Running it

### Quick: run the full pipeline from the command line

```bash
pip install -r requirements.txt
python3 run_pipeline.py
```

This generates data, runs detection, prints metrics, and investigates the
top incident — no servers needed.

### Full: API + interactive dashboard

```bash
pip install -r requirements.txt
python3 data/generate_logs.py

# Terminal 1
uvicorn src.api:app --reload

# Terminal 2
streamlit run dashboard/app.py
```

Open http://localhost:8501 for the dashboard.

### Optional: enable real LLM-generated investigations

```bash
export ANTHROPIC_API_KEY=your_key_here
```

Without this set, the investigation layer uses a deterministic template
summary so the app still runs fully offline.

### Docker

```bash
docker compose up --build
```

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /alerts` | All flagged incidents, sorted by risk score |
| `GET /alerts/{id}` | Single incident detail |
| `GET /alerts/{id}/investigate` | LLM-generated timeline/summary/next steps |
| `GET /metrics` | Detection precision/recall/F1/FPR |
| `POST /ingest` | Re-runs the full pipeline |

## Known limitations (honest, for interview discussion)

- Uses synthetic data, not live AWS CloudTrail/GuardDuty integration.
- MITRE mapping uses a hand-built lookup table rather than a learned
  classifier — simple but transparent and easy to extend.
- LLM retrieval is a direct filter by incident ID, not a vector-DB/embedding
  based RAG pipeline — appropriate at this data scale, would need to change
  at production log volume.
- Isolation Forest contamination parameter is tuned on this synthetic
  dataset; a production deployment would need periodic retraining as
  normal behavior drifts.
