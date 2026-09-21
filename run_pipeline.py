"""
Runs the full SOC detection pipeline end-to-end from the command line:
  generate logs -> features -> anomaly detection -> MITRE mapping/risk
  scoring -> LLM investigation on the top incident.

Usage: python3 run_pipeline.py
"""

import json
import subprocess
import sys

sys.path.insert(0, "src")

from features import load_events, build_features
from detect import run_detection, evaluate
from mitre_map import build_incidents
from investigate import investigate_incident


def main():
    print("=" * 60)
    print("STEP 1: Generating synthetic AWS CloudTrail-style logs")
    print("=" * 60)
    subprocess.run([sys.executable, "data/generate_logs.py"], check=True)

    print("\n" + "=" * 60)
    print("STEP 2: Feature engineering")
    print("=" * 60)
    events = load_events("data/synthetic_logs.json")
    df = build_features(events)
    print(f"Built {len(df)} (user, day) behavioral feature windows.")

    print("\n" + "=" * 60)
    print("STEP 3: Anomaly detection (Isolation Forest)")
    print("=" * 60)
    result_df, _, _ = run_detection(df)
    metrics = evaluate(result_df)
    flagged = result_df[result_df["is_flagged"]]
    print(f"Flagged {len(flagged)} of {len(result_df)} windows as anomalous.")
    print("Detection metrics vs. synthetic ground truth:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    print("\n" + "=" * 60)
    print("STEP 4: MITRE ATT&CK mapping + risk scoring")
    print("=" * 60)
    incidents = build_incidents(flagged)
    print(f"Built {len(incidents)} incidents.")
    for inc in incidents[:5]:
        techs = [t["technique_id"] for t in inc["mitre_techniques"]]
        print(f"  [{inc['severity']}] {inc['incident_id']} risk={inc['risk_score']} techniques={techs}")

    print("\n" + "=" * 60)
    print("STEP 5: LLM-assisted investigation (top incident)")
    print("=" * 60)
    events_by_id = {e["eventId"]: e for e in events}
    top = incidents[0]
    result = investigate_incident(top, events_by_id)
    print(f"Incident: {top['incident_id']} (risk {top['risk_score']})\n")
    if "llm_output" in result:
        print(result["llm_output"])
    else:
        print("Timeline:")
        print(result["timeline"])
        print("\nSummary:")
        print(result["summary"])
        print("\nRecommended steps:")
        for step in result["recommended_steps"]:
            print(f"  - {step}")

    with open("data/pipeline_report.json", "w") as f:
        json.dump({"metrics": metrics, "incident_count": len(incidents),
                   "top_incident": top, "top_investigation": result}, f, indent=2)

    print("\n" + "=" * 60)
    print("DONE. Full report saved -> data/pipeline_report.json")
    print("=" * 60)
    print("\nTo explore interactively:")
    print("  1. Terminal 1: uvicorn src.api:app --reload")
    print("  2. Terminal 2: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
