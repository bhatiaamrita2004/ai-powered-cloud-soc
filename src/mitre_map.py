"""
Maps flagged anomalous behavior to MITRE ATT&CK techniques based on which
feature(s) drove the anomaly, then computes a weighted risk score to
prioritize alerts for an analyst.
"""

# technique_id, technique_name, tactic, base_severity (0-10)
MITRE_MAP = {
    "geo_anomaly": ("T1078", "Valid Accounts", "Initial Access", 6),
    "off_hours_login": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access", 4),
    "privilege_escalation": ("T1098", "Account Manipulation", "Privilege Escalation", 8),
    "data_exfiltration": ("T1537", "Transfer Data to Cloud Account", "Exfiltration", 9),
    "high_activity_volume": ("T1078", "Valid Accounts", "Discovery", 3),
}

WEIGHTS = {
    "anomaly_score": 0.35,     # how statistically unusual the ML model found it
    "technique_severity": 0.40,  # how dangerous the underlying technique is
    "frequency_factor": 0.25,    # how much this exceeds normal volume
}


def classify_signals(row):
    """Given a feature row, determine which MITRE-mappable signal(s) fired."""
    signals = []
    if row["distinct_countries"] > 1:
        signals.append("geo_anomaly")
    if row["off_hours_ratio"] > 0.5:
        signals.append("off_hours_login")
    if row["privesc_call_count"] >= 2:
        signals.append("privilege_escalation")
    if row["total_bytes_transferred"] > 3_000_000:
        signals.append("data_exfiltration")
    if row["event_count"] > 15:
        signals.append("high_activity_volume")
    return signals or ["high_activity_volume"]  # fallback if flagged but no clear signal


def compute_risk_score(row, signals):
    """
    Weighted risk score (0-100):
      risk = (anomaly_score * W1) + (technique_severity * W2) + (frequency_factor * W3)
    """
    anomaly_component = row["anomaly_score_0_100"]  # already 0-100

    severities = [MITRE_MAP[s][3] for s in signals]
    technique_component = (max(severities) / 10) * 100  # scale 0-10 -> 0-100

    # frequency factor: how much this window's activity exceeds a "normal" baseline
    baseline_events = 8  # rough normal daily event count per user
    frequency_component = min(100, (row["event_count"] / baseline_events) * 25)

    score = (
        anomaly_component * WEIGHTS["anomaly_score"]
        + technique_component * WEIGHTS["technique_severity"]
        + frequency_component * WEIGHTS["frequency_factor"]
    )
    return round(min(100, score), 1)


def build_incidents(flagged_df):
    """Converts flagged rows into incident dicts with MITRE mapping + risk score."""
    incidents = []
    for _, row in flagged_df.iterrows():
        signals = classify_signals(row)
        techniques = [
            {"signal": s, "technique_id": MITRE_MAP[s][0], "technique_name": MITRE_MAP[s][1],
             "tactic": MITRE_MAP[s][2]}
            for s in signals
        ]
        risk_score = compute_risk_score(row, signals)

        incidents.append({
            "incident_id": f"INC-{row['user']}-{row['day']}",
            "user": row["user"],
            "day": row["day"],
            "risk_score": risk_score,
            "severity": (
                "Critical" if risk_score >= 75 else
                "High" if risk_score >= 55 else
                "Medium" if risk_score >= 35 else "Low"
            ),
            "signals": signals,
            "mitre_techniques": techniques,
            "features": {
                "event_count": int(row["event_count"]),
                "login_count": int(row["login_count"]),
                "distinct_countries": int(row["distinct_countries"]),
                "off_hours_ratio": round(float(row["off_hours_ratio"]), 2),
                "privesc_call_count": int(row["privesc_call_count"]),
                "total_bytes_transferred": int(row["total_bytes_transferred"]),
            },
            "event_ids": row["event_ids"],
        })

    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    return incidents


if __name__ == "__main__":
    import pandas as pd
    import json

    df = pd.read_json("/home/claude/soc-project/data/detection_results.json")
    flagged = df[df["is_flagged"]]
    incidents = build_incidents(flagged)

    print(f"Built {len(incidents)} incidents from {len(flagged)} flagged windows.\n")
    for inc in incidents[:5]:
        print(f"[{inc['severity']}] {inc['incident_id']} - risk={inc['risk_score']} "
              f"- techniques={[t['technique_id'] for t in inc['mitre_techniques']]}")

    with open("/home/claude/soc-project/data/incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)
    print("\nSaved -> data/incidents.json")
