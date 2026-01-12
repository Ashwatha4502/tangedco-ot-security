"""
thehive_cases.py
──────────────────────────────────────────────────────────────────
Auto-creates TheHive cases from TANGEDCO Wazuh alerts.

Connects to TheHive API and creates structured incident cases
with full context: ATT&CK techniques, observables, severity,
and pre-populated investigation tasks.

This is the SOC analyst workflow automation — Tier 1 gets a 
pre-structured case instead of a raw alert.

Setup:
  1. TheHive running (via docker-compose)
  2. Generate API key in TheHive admin panel
  3. Set THEHIVE_API_KEY env var:
     export THEHIVE_API_KEY="your_key_here"

Usage:
  python thehive_cases.py --csv ../anomaly-detection/output/anomaly_detections.csv
  python thehive_cases.py --severity Critical High   # only create for these severities
  python thehive_cases.py --dry-run                  # print cases without creating
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
import urllib.request
import urllib.error

# ── Config ───────────────────────────────────────────────────────────────────
THEHIVE_URL  = os.getenv("THEHIVE_URL",  "http://localhost:9000")
THEHIVE_KEY  = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_ORG  = os.getenv("THEHIVE_ORG",  "TANGEDCO-SOC")

# ── Severity mapping ─────────────────────────────────────────────────────────
SEV_TO_THEHIVE = {
    "Critical": {"severity": 3, "tlp": 2, "pap": 2},  # TLP:AMBER
    "High":     {"severity": 2, "tlp": 2, "pap": 2},
    "Medium":   {"severity": 1, "tlp": 1, "pap": 1},  # TLP:GREEN
    "Low":      {"severity": 1, "tlp": 1, "pap": 0},
}

# ── Playbook tasks per anomaly type ──────────────────────────────────────────
INVESTIGATION_TASKS = {
    "Ransomware_SCADA_Blackout": [
        {"title": "1. Scope — Identify affected IT hosts",
         "description": "Check EDR console for hosts with mass file rename events. "
                        "Document blast radius before any remediation."},
        {"title": "2. Contain — Isolate affected hosts",
         "description": "Use VLAN quarantine or firewall ACL to isolate. "
                        "Do NOT shut down until forensic image is captured."},
        {"title": "3. OT Check — Verify SCADA status",
         "description": "Confirm whether SCADA blackout is genuine or false alarm. "
                        "Contact control room operators directly (phone, not email)."},
        {"title": "4. Notify — CERT-In mandatory report",
         "description": "CERT-In notification required within 6 hours of discovery "
                        "(CERT-In Directions 2022, Section 70B IT Act). Use incident report template."},
        {"title": "5. Evidence — Capture forensic images",
         "description": "Before remediation: capture memory dump and disk image of affected hosts. "
                        "Use FTK Imager or dd. Store on isolated evidence drive."},
        {"title": "6. Eradicate — Rebuild from gold images",
         "description": "Rebuild affected systems from verified gold images. "
                        "Patch exploited vulnerability before reconnecting to network."},
        {"title": "7. Recover — Restore from clean backup",
         "description": "Restore data from last verified clean backup. "
                        "Confirm integrity before reconnecting historian to OT network."},
        {"title": "8. Post-incident — Root cause analysis",
         "description": "Write RCA report within 5 business days. "
                        "Update detection rules and IR playbook based on findings."},
    ],
    "Demand_Manipulation_Unauthorised_Command": [
        {"title": "1. Verify — Confirm anomalous demand readings",
         "description": "Cross-reference SCADA historian with SRLDC SCADA feeds. "
                        "Determine if actual grid impact or false positive."},
        {"title": "2. Network — Capture IEC 104/DNP3 traffic",
         "description": "Pull PCAP from OT NDR (Claroty/Dragos). "
                        "Look for Type ID 45/46 commands from non-EMS source IP."},
        {"title": "3. Contain — Block non-authorised SCADA source IPs",
         "description": "Apply emergency firewall ACL to block unauthorised source IPs "
                        "from reaching SCADA master on port 2404 and DNP3 port 20000."},
        {"title": "4. Grid — Coordinate with SRLDC",
         "description": "Call SRLDC control desk. Verify affected substation breaker states. "
                        "Consider switching affected substations to local manual control."},
        {"title": "5. Forensics — Analyse command logs",
         "description": "Extract SCADA command log from EMS. Identify all commands sent "
                        "in the 2-hour window before and after detection."},
    ],
    "Sensor_Spoofing_MITM": [
        {"title": "1. Isolate — Identify affected sensor zone",
         "description": "Determine which ICS zone contains the spoofed sensor. "
                        "Cross-reference with physical sensor readings where possible."},
        {"title": "2. Verify — Physical field check",
         "description": "Request field crew to manually read affected meters. "
                        "Compare physical readings with SCADA historian values."},
        {"title": "3. Network — Check for MITM on ICS protocol",
         "description": "Review OT network topology for unexpected devices on the fieldbus. "
                        "Check MAC address tables for unknown devices in affected VLAN."},
        {"title": "4. Protocol — Enable DNP3 Secure Authentication",
         "description": "If not already in place, initiate change request to enable "
                        "DNP3-SA v5 on affected RTU/substation communications."},
    ],
    "OffHours_Privileged_Access": [
        {"title": "1. Verify — Identify responsible user",
         "description": "Check Wazuh auth logs for username of SCADA access. "
                        "Call the user's manager to confirm whether access was authorised."},
        {"title": "2. Check — Review change management calendar",
         "description": "Verify whether an approved change ticket exists for this time window. "
                        "Access ITSM (ServiceNow/Jira) change log."},
        {"title": "3. Investigate — Review session activity",
         "description": "Pull session recording from PAM (if deployed). "
                        "What SCADA commands were issued during this session?"},
        {"title": "4. Assess — Determine if credential compromise",
         "description": "Run credential hygiene check on affected account. "
                        "Check for concurrent logins from different locations."},
    ],
    "Loss_of_View_SCADA_Wiper": [
        {"title": "1. IMMEDIATE — Switch to manual grid operations",
         "description": "SCADA visibility is gone. Notify all substations to switch to "
                        "local manual control. Contact SRLDC immediately."},
        {"title": "2. Scope — Determine wiper blast radius",
         "description": "Which SCADA systems are affected? Check historian, EMS, HMI servers. "
                        "Preserve what evidence you can before systems are rebuilt."},
        {"title": "3. Isolate — Disconnect affected systems from OT network",
         "description": "Network-isolate affected hosts. Prevent wiper from spreading "
                        "to backup historian or remaining operational workstations."},
        {"title": "4. Notify — CERT-In, CEA, CMD",
         "description": "This is a P0 incident. Notify CISO, CMD, CEA, and CERT-In. "
                        "CEA notification required per Power Sector Cyber Security Guidelines."},
        {"title": "5. Restore — Recovery from gold images",
         "description": "Rebuild EMS/SCADA from verified clean backups. "
                        "Validate config integrity before reconnecting to field devices."},
    ],
}

# Default tasks for unrecognised anomaly types
DEFAULT_TASKS = [
    {"title": "1. Triage — Validate alert",
     "description": "Review raw detection data. Determine if true positive or false alarm."},
    {"title": "2. Scope — Assess impact",
     "description": "Identify affected assets, time window, and potential business impact."},
    {"title": "3. Contain — Implement immediate controls",
     "description": "Apply containment measures appropriate to the threat vector."},
    {"title": "4. Investigate — Root cause analysis",
     "description": "Determine how the event occurred and whether it is part of a campaign."},
    {"title": "5. Close — Document findings",
     "description": "Write closure notes. Update detection rules if false positive."},
]


def thehive_request(method: str, endpoint: str,
                    data: dict = None) -> tuple:
    """Make a TheHive API call. Returns (status_code, response_dict)."""
    url = f"{THEHIVE_URL}/api{endpoint}"
    headers = {
        "Authorization": f"Bearer {THEHIVE_KEY}",
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.code, {"error": body}
    except Exception as e:
        return 0, {"error": str(e)}


def build_case(event: dict) -> dict:
    """Build a TheHive case payload from an anomaly detection event."""
    sev = event.get("severity", "Medium")
    th = SEV_TO_THEHIVE.get(sev, SEV_TO_THEHIVE["Medium"])
    atype = event.get("anomaly_type", "Unknown")
    technique = event.get("technique", "Unknown")
    ts = event.get("timestamp", "")[:16]
    confidence = event.get("confidence", 0)
    detector = event.get("detector", "Unknown")
    description_raw = event.get("description", "")
    true_label = event.get("true_label", "Unknown")

    # Build structured case description
    description = f"""## TANGEDCO ICS Security Incident

**Alert ID:** TNG-{event.get('index', '?'):0>5}  
**Timestamp:** {ts}  
**Detector:** {detector}  
**Confidence:** {confidence}%  
**True Label (Lab):** {true_label}  

---

### Detection Summary
{description_raw}

### ATT&CK for ICS Mapping
**Technique:** {technique}  
See: https://attack.mitre.org/techniques/{technique.split('/')[0].strip()}/

### Affected Asset / Feature
**Feature:** {event.get('feature', 'Unknown')}  
**Observed Value:** {event.get('value', 'N/A')}  
**Expected Range:** {event.get('expected_range', 'N/A')}  

### ISO 27001 Controls Implicated
See TANGEDCO Risk Register for full Annex A control mapping.

### Response Playbook
Refer to tasks below. Priority order is 1 → N.
"""

    tags = [
        "TANGEDCO",
        "ICS-OT",
        f"ATT&CK:{technique.split('/')[0].strip()}",
        f"SEVERITY:{sev}",
        f"DETECTOR:{detector.split(':')[0]}",
        atype.replace("_", "-"),
    ]

    return {
        "title": f"[{sev.upper()}] TANGEDCO ICS: {atype.replace('_', ' ')} — {ts}",
        "description": description,
        "severity": th["severity"],
        "tlp": th["tlp"],
        "pap": th["pap"],
        "tags": tags,
        "flag": sev == "Critical",
        "status": "New",
        "assignee": "soc_tier1@tangedco.gov.in",
    }


def build_tasks(anomaly_type: str) -> list:
    """Get investigation tasks for this anomaly type."""
    # Try to match by prefix
    for key in INVESTIGATION_TASKS:
        if key.lower() in anomaly_type.lower() or anomaly_type.lower() in key.lower():
            return INVESTIGATION_TASKS[key]
    return DEFAULT_TASKS


def build_observables(event: dict) -> list:
    """Extract TheHive observables (IoCs) from event."""
    obs = []
    technique = event.get("technique", "")

    # Add ATT&CK technique as observable
    for t in technique.split("/"):
        t = t.strip()
        if t.startswith("T"):
            obs.append({
                "dataType": "other",
                "data": t,
                "message": f"MITRE ATT&CK for ICS technique",
                "tags": ["ATT&CK-ICS", "TANGEDCO"],
            })

    # Add detected value as observable
    val = event.get("value")
    if val and float(val or 0) > 0:
        obs.append({
            "dataType": "other",
            "data": f"Grid demand: {float(val):.1f} MW",
            "message": "Anomalous SCADA sensor reading",
            "tags": ["SCADA", "sensor-data"],
        })

    return obs


def create_case_in_thehive(event: dict, dry_run: bool = False) -> str:
    """Create a full TheHive case with tasks and observables."""
    case_payload = build_case(event)
    tasks = build_tasks(event.get("anomaly_type", ""))
    observables = build_observables(event)

    if dry_run:
        print(f"\n{'─'*50}")
        print(f"[DRY RUN] Would create case:")
        print(f"  Title    : {case_payload['title'][:70]}")
        print(f"  Severity : {case_payload['severity']} | TLP: {case_payload['tlp']}")
        print(f"  Tags     : {', '.join(case_payload['tags'])}")
        print(f"  Tasks    : {len(tasks)}")
        print(f"  Flagged  : {case_payload['flag']}")
        return "dry-run"

    # Create case
    status, resp = thehive_request("POST", "/v1/case", case_payload)
    if status not in (200, 201):
        print(f"  [!] Case creation failed ({status}): {resp.get('error', '')[:100]}")
        return None

    case_id = resp.get("_id") or resp.get("id")

    # Add tasks
    for task in tasks:
        thehive_request("POST", f"/v1/case/{case_id}/task", task)
        time.sleep(0.1)

    # Add observables
    for obs in observables:
        thehive_request("POST", f"/v1/case/{case_id}/observable", obs)

    return case_id


def main():
    parser = argparse.ArgumentParser(
        description="Create TheHive cases from TANGEDCO anomaly detections"
    )
    parser.add_argument("--csv",
                        default="../anomaly-detection/output/anomaly_detections.csv")
    parser.add_argument("--severity", nargs="+",
                        default=["Critical", "High"],
                        choices=["Critical", "High", "Medium", "Low"],
                        help="Severities to create cases for (default: Critical High)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print cases without creating in TheHive")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max cases to create (default: 50)")
    args = parser.parse_args()

    if not args.dry_run and not THEHIVE_KEY:
        print("[!] THEHIVE_API_KEY not set.")
        print("    Set it: export THEHIVE_API_KEY='your_api_key'")
        print("    Or use --dry-run to test without TheHive.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"TANGEDCO → TheHive Case Creator")
    print(f"Mode: {'DRY RUN' if args.dry_run else f'LIVE → {THEHIVE_URL}'}")
    print(f"Severities: {args.severity}")
    print(f"{'='*60}\n")

    if not Path(args.csv).exists():
        print(f"[!] CSV not found: {args.csv}")
        sys.exit(1)

    with open(args.csv, newline="", encoding="utf-8") as f:
        events = [r for r in csv.DictReader(f)
                  if r.get("severity") in args.severity]

    print(f"[*] Found {len(events)} events matching severity filter")
    events = events[:args.limit]
    print(f"[*] Processing {len(events)} events (limit: {args.limit})\n")

    created = 0
    failed = 0
    for ev in events:
        result = create_case_in_thehive(ev, dry_run=args.dry_run)
        if result:
            created += 1
            if not args.dry_run:
                sev = ev.get("severity", "?")
                atype = ev.get("anomaly_type", "?")[:40]
                print(f"  [+] Case created: {result} | [{sev}] {atype}")
                time.sleep(0.3)
        else:
            failed += 1

    print(f"\n{'='*60}")
    print(f"Done. Cases created: {created} | Failed: {failed}")
    if not args.dry_run:
        print(f"View at: {THEHIVE_URL}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
