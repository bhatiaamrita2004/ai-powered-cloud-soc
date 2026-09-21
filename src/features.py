"""
Turns raw CloudTrail-style events into behavioral feature rows, one per
(user, time-window) bucket. These features feed the anomaly detection model.
"""

import json
from collections import defaultdict
from datetime import datetime

import pandas as pd


def load_events(path="/home/claude/soc-project/data/synthetic_logs.json"):
    with open(path) as f:
        return json.load(f)


def _hour_of(event):
    return datetime.fromisoformat(event["eventTime"].replace("Z", "")).hour


def _day_key(event):
    ts = datetime.fromisoformat(event["eventTime"].replace("Z", ""))
    return ts.strftime("%Y-%m-%d")


PRIVESC_EVENTS = {"AttachUserPolicy", "PutUserPolicy", "CreateAccessKey",
                  "AttachRolePolicy", "CreateLoginProfile"}


def build_features(events):
    """
    Groups events into (user, day) windows and computes behavioral features:
      - login_count: number of ConsoleLogin events in the window
      - distinct_countries: count of distinct source countries seen
      - off_hours_ratio: fraction of events outside the user's typical 8am-8pm band
      - privesc_call_count: count of privilege-escalation-related API calls
      - total_bytes_transferred: sum of data transfer volume in the window
      - event_count: total events in the window (activity volume)

    Also carries forward whether ANY event in the window was a ground-truth
    anomaly (and its type), purely for later evaluation -- never used as a
    model input.
    """
    buckets = defaultdict(list)
    for e in events:
        key = (e["userIdentity"]["userName"], _day_key(e))
        buckets[key].append(e)

    rows = []
    for (user, day), evs in buckets.items():
        countries = set(e["country"] for e in evs)
        login_events = [e for e in evs if e["eventName"] == "ConsoleLogin"]
        off_hours = [e for e in evs if _hour_of(e) < 7 or _hour_of(e) > 21]
        privesc = [e for e in evs if e["eventName"] in PRIVESC_EVENTS]
        total_bytes = sum(e.get("bytesTransferred", 0) for e in evs)

        row = {
            "user": user,
            "day": day,
            "event_count": len(evs),
            "login_count": len(login_events),
            "distinct_countries": len(countries),
            "off_hours_ratio": len(off_hours) / len(evs) if evs else 0,
            "privesc_call_count": len(privesc),
            "total_bytes_transferred": total_bytes,
            # ground truth, for evaluation only
            "true_is_anomaly": any(e["is_anomaly"] for e in evs),
            "true_anomaly_types": list({e["anomaly_type"] for e in evs if e["anomaly_type"]}),
            "event_ids": [e["eventId"] for e in evs],
        }
        rows.append(row)

    return pd.DataFrame(rows)


if __name__ == "__main__":
    events = load_events()
    df = build_features(events)
    print(df.shape)
    print(df.head(10))
    df.to_json("/home/claude/soc-project/data/features.json", orient="records", indent=2)
    print("Saved features -> data/features.json")
