"""
LLM-assisted investigation layer.

Given a flagged incident, retrieves its underlying raw log events (this is
the "retrieval" step -- filtering the log store down to the events relevant
to this specific incident) and passes them as grounded context to an LLM,
which generates a human-readable timeline, evidence summary, and
recommended next steps.

If no ANTHROPIC_API_KEY is configured, falls back to a deterministic
template-based summary so the pipeline still runs end-to-end without
external dependencies -- useful for demos and offline development.
"""

import json
import os

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")


def retrieve_incident_events(incident, all_events_by_id):
    """Filters the full event log down to just this incident's events."""
    return [all_events_by_id[eid] for eid in incident["event_ids"] if eid in all_events_by_id]


def _build_prompt(incident, events):
    return f"""You are a SOC (Security Operations Center) analyst assistant.
Below is a flagged security incident with its risk score, MITRE ATT&CK
mapping, and the raw log events that were retrieved for it. Using ONLY the
data provided (do not invent facts not present in the data), produce:

1. A short chronological timeline of what happened.
2. A 2-3 sentence evidence summary explaining why this was flagged.
3. 3-4 concrete recommended next investigation steps for a human analyst.

Incident metadata:
{json.dumps({k: v for k, v in incident.items() if k != 'event_ids'}, indent=2)}

Retrieved raw events:
{json.dumps(events, indent=2)}
"""


def _call_llm(prompt):
    """Calls the Anthropic API if a key is configured."""
    import urllib.request

    body = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return "".join(block["text"] for block in data["content"] if block["type"] == "text")


def _template_fallback(incident, events):
    """Deterministic, template-based summary used when no LLM API key is set."""
    techniques = ", ".join(f"{t['technique_id']} ({t['technique_name']})" for t in incident["mitre_techniques"])
    lines = [f"- {e['eventTime']}: {e['eventName']} from {e['sourceIPAddress']} ({e['country']})"
             for e in sorted(events, key=lambda e: e["eventTime"])]

    timeline = "\n".join(lines)
    summary = (
        f"User {incident['user']} triggered a {incident['severity'].lower()}-severity alert "
        f"(risk score {incident['risk_score']}/100) on {incident['day']}, matching signal(s): "
        f"{', '.join(incident['signals'])}. This maps to MITRE technique(s): {techniques}."
    )
    steps = [
        f"Verify whether {incident['user']}'s activity on {incident['day']} was authorized "
        f"(check with the user or their manager).",
        "Cross-reference the source IP address(es) against known corporate IP ranges / VPN exit nodes.",
        "Review recent IAM policy changes for this user for unauthorized privilege grants.",
        "If confirmed malicious, rotate this user's credentials and review CloudTrail for lateral movement.",
    ]
    return {
        "timeline": timeline,
        "summary": summary,
        "recommended_steps": steps,
        "generated_by": "template_fallback (no LLM API key configured)",
    }


def investigate_incident(incident, all_events_by_id):
    events = retrieve_incident_events(incident, all_events_by_id)

    if not ANTHROPIC_API_KEY:
        return _template_fallback(incident, events)

    try:
        prompt = _build_prompt(incident, events)
        text = _call_llm(prompt)
        return {"llm_output": text, "generated_by": "claude-sonnet-4-6"}
    except Exception as ex:
        # graceful fallback if the API call fails for any reason
        result = _template_fallback(incident, events)
        result["note"] = f"LLM call failed ({ex}); used template fallback."
        return result


if __name__ == "__main__":
    with open("/home/claude/soc-project/data/incidents.json") as f:
        incidents = json.load(f)
    with open("/home/claude/soc-project/data/synthetic_logs.json") as f:
        all_events = json.load(f)
    all_events_by_id = {e["eventId"]: e for e in all_events}

    top_incident = incidents[0]
    result = investigate_incident(top_incident, all_events_by_id)

    print(f"=== Investigation: {top_incident['incident_id']} ===\n")
    print(json.dumps(result, indent=2))
