"""
Generates synthetic AWS CloudTrail-style security logs for the SOC project.

Produces a realistic mix of "normal" user activity plus a set of injected
anomalies (privilege escalation, geo-anomalous logins, exfiltration-like
data transfers). A hidden `is_anomaly` ground-truth label is kept so the
detection pipeline's performance can be evaluated later -- it is NOT used
as a training input (the model is unsupervised).
"""
import os
import json
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

USERS = [f"user_{i:03d}" for i in range(1, 21)]
NORMAL_COUNTRIES = ["US", "US", "US", "IN", "IN", "GB"]  # weighted "home" countries
RARE_COUNTRIES = ["RU", "NG", "KP", "BR", "CN"]

NORMAL_EVENTS = [
    "ConsoleLogin", "GetObject", "ListBucket", "DescribeInstances",
    "PutObject", "AssumeRole", "GetSecretValue", "DescribeSecurityGroups",
]
PRIVESC_EVENTS = ["AttachUserPolicy", "PutUserPolicy", "CreateAccessKey",
                  "AttachRolePolicy", "CreateLoginProfile"]
EXFIL_EVENTS = ["GetObject", "CopyObject", "GetObject", "GetObject"]

# Give each user a "home" country and typical login hour range, so we can
# later inject deviations from THEIR baseline (not just a global one).
USER_PROFILE = {
    u: {
        "home_country": random.choice(NORMAL_COUNTRIES),
        "typical_hour_start": random.randint(7, 10),
        "typical_hour_end": random.randint(17, 20),
    }
    for u in USERS
}


def make_event(user, event_name, event_time, source_ip, country,
               bytes_transferred=0, is_anomaly=False, anomaly_type=None):
    return {
        "eventId": str(uuid.uuid4()),
        "eventTime": event_time.isoformat() + "Z",
        "eventName": event_name,
        "userIdentity": {"userName": user, "type": "IAMUser"},
        "sourceIPAddress": source_ip,
        "awsRegion": "us-east-1",
        "country": country,
        "bytesTransferred": bytes_transferred,
        # ground-truth label, hidden from the model, used only for evaluation
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type,
    }


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


def generate_normal_events(n=2000, start=None):
    events = []
    start = start or (datetime.utcnow() - timedelta(days=14))
    for _ in range(n):
        user = random.choice(USERS)
        profile = USER_PROFILE[user]
        day_offset = random.randint(0, 13)
        hour = random.randint(profile["typical_hour_start"], profile["typical_hour_end"])
        minute = random.randint(0, 59)
        ts = start + timedelta(days=day_offset, hours=hour, minutes=minute)
        event_name = random.choice(NORMAL_EVENTS)
        bytes_transferred = random.randint(1_000, 500_000) if event_name in ("GetObject", "PutObject") else 0
        events.append(make_event(
            user, event_name, ts, random_ip(), profile["home_country"],
            bytes_transferred=bytes_transferred, is_anomaly=False
        ))
    return events


def generate_anomalies(n_geo=15, n_privesc=15, n_exfil=15, start=None):
    events = []
    start = start or (datetime.utcnow() - timedelta(days=14))

    # 1. Geo-anomalous logins: user logs in from a rare country at an odd hour
    for _ in range(n_geo):
        user = random.choice(USERS)
        day_offset = random.randint(0, 13)
        hour = random.choice([1, 2, 3, 4, 23])  # off-hours
        ts = start + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
        events.append(make_event(
            user, "ConsoleLogin", ts, random_ip(), random.choice(RARE_COUNTRIES),
            is_anomaly=True, anomaly_type="unusual_login_geo"
        ))

    # 2. Privilege escalation bursts: several privesc calls in a short window
    for _ in range(n_privesc):
        user = random.choice(USERS)
        day_offset = random.randint(0, 13)
        base_ts = start + timedelta(days=day_offset, hours=random.randint(0, 23))
        burst_size = random.randint(3, 6)
        for i in range(burst_size):
            events.append(make_event(
                user, random.choice(PRIVESC_EVENTS),
                base_ts + timedelta(minutes=i * 2), random_ip(),
                USER_PROFILE[user]["home_country"],
                is_anomaly=True, anomaly_type="privilege_escalation_calls"
            ))

    # 3. Exfiltration-like large data transfers
    for _ in range(n_exfil):
        user = random.choice(USERS)
        day_offset = random.randint(0, 13)
        base_ts = start + timedelta(days=day_offset, hours=random.randint(0, 23))
        burst_size = random.randint(4, 8)
        for i in range(burst_size):
            events.append(make_event(
                user, random.choice(EXFIL_EVENTS),
                base_ts + timedelta(minutes=i), random_ip(),
                USER_PROFILE[user]["home_country"],
                bytes_transferred=random.randint(5_000_000, 50_000_000),
                is_anomaly=True, anomaly_type="large_data_transfer"
            ))

    return events


def main():
    normal = generate_normal_events(n=2000)
    anomalies = generate_anomalies(n_geo=15, n_privesc=15, n_exfil=15)
    all_events = normal + anomalies
    random.shuffle(all_events)
    all_events.sort(key=lambda e: e["eventTime"])

    out_path= os.path.join(os.path.dirname(__file__), "synthetic_logs.json")
    with open(out_path, "w") as f:
        json.dump(all_events, f, indent=2)

    n_anom = sum(1 for e in all_events if e["is_anomaly"])
    print(f"Generated {len(all_events)} events ({n_anom} anomalous) -> {out_path}")


if __name__ == "__main__":
    main()
