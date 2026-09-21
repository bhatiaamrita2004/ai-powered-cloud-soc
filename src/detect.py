"""
Unsupervised anomaly detection using Isolation Forest.

Isolation Forest is chosen over a supervised model (e.g. XGBoost) because
real-world attack labels are scarce/unavailable in production -- this model
learns what "normal" behavior looks like and flags statistical outliers,
without needing pre-labeled attack examples.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLS = [
    "event_count", "login_count", "distinct_countries",
    "off_hours_ratio", "privesc_call_count", "total_bytes_transferred",
]


def run_detection(df: pd.DataFrame, contamination=0.12):
    X = df[FEATURE_COLS].copy()

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,   # expected fraction of anomalies
        random_state=42,
    )
    model.fit(X_scaled)

    df = df.copy()
    # decision_function: higher = more normal, lower/negative = more anomalous
    df["anomaly_score_raw"] = model.decision_function(X_scaled)
    df["is_flagged"] = model.predict(X_scaled) == -1

    # normalize score to a 0-100 "riskiness" scale (higher = riskier)
    min_s, max_s = df["anomaly_score_raw"].min(), df["anomaly_score_raw"].max()
    df["anomaly_score_0_100"] = df["anomaly_score_raw"].apply(
        lambda s: round(100 * (1 - (s - min_s) / (max_s - min_s + 1e-9)), 1)
    )

    return df, model, scaler


def evaluate(df: pd.DataFrame):
    """Compares model flags against the hidden ground-truth labels."""
    tp = ((df["is_flagged"]) & (df["true_is_anomaly"])).sum()
    fp = ((df["is_flagged"]) & (~df["true_is_anomaly"])).sum()
    fn = ((~df["is_flagged"]) & (df["true_is_anomaly"])).sum()
    tn = ((~df["is_flagged"]) & (~df["true_is_anomaly"])).sum()

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    return {
        "true_positives": int(tp), "false_positives": int(fp),
        "false_negatives": int(fn), "true_negatives": int(tn),
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1_score": round(f1, 3), "false_positive_rate": round(fpr, 3),
    }


if __name__ == "__main__":
    df = pd.read_json("/home/claude/soc-project/data/features.json")
    result_df, model, scaler = run_detection(df)
    metrics = evaluate(result_df)

    print("=== Detection Metrics (vs. synthetic ground truth) ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    flagged = result_df[result_df["is_flagged"]].sort_values("anomaly_score_0_100", ascending=False)
    print(f"\nFlagged {len(flagged)} of {len(result_df)} windows as anomalous.")

    result_df.to_json("/home/claude/soc-project/data/detection_results.json", orient="records", indent=2)
    print("Saved -> data/detection_results.json")
