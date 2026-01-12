"""
feed_alerts.py
──────────────────────────────────────────────────────────────────
Bridges the TANGEDCO Python anomaly detection tool → Wazuh SIEM.

Takes the anomaly_detections.csv output from anomaly_detector.py
and feeds each detection into Wazuh as a structured syslog event
that the tangedco_decoder.xml can parse.

Two modes:
  --historical   Feed all existing detections (for lab setup / demo)
  --live         Watch anomaly_detections.csv for new rows and feed in real-time

Usage:
  python feed_alerts.py --historical --csv ../anomaly-detection/output/anomaly_detections.csv
  python feed_alerts.py --live --csv ../anomaly-detection/output/anomaly_detections.csv
  
  # Feed to remote Wazuh manager:
  python feed_alerts.py --historical --wazuh-host 192.168.1.100 --wazuh-port 514
"""

import argparse
import csv
import json
import socket
import sys
import time
import os
from datetime import datetime
from pathlib import Path


# ── Wazuh syslog target ──────────────────────────────────────────────────────
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 514   # Wazuh syslog listener
SYSLOG_FACILITY = 1  # user-level messages
SYSLOG_SEVERITY_MAP = {
    "Critical": 2,   # syslog CRITICAL
    "High":     3,   # syslog ERROR
    "Medium":   4,   # syslog WARNING
    "Low":      6,   # syslog INFO
}

# ── Threat actor enrichment ──────────────────────────────────────────────────
TECHNIQUE_TO_ACTOR = {
    "T0813": ["Sandworm Team", "TEMP.Veles"],
    "T0816": ["Sandworm Team", "Dragonfly"],
    "T0855": ["Sandworm Team", "TEMP.Veles", "Dragonfly 2.0"],
    "T0856": ["TEMP.Veles"],
    "T0830": ["TEMP.Veles", "APT33"],
    "T0859": ["Dragonfly", "APT33", "Volt Typhoon"],
    "T0882": ["Sandworm Team", "APT28"],
    "T1486": ["FIN12", "Wizard Spider", "LockBit"],
    "T1490": ["Wizard Spider", "FIN12"],
    "T0866": ["Volt Typhoon", "Dragonfly"],
    "T0886": ["Dragonfly", "APT33"],
}

CVE_CONTEXT = {
    "T0855": ["CVE-2022-26134", "CVE-2021-34527"],
    "T0866": ["CVE-2023-46604", "CVE-2022-0028"],
    "T0816": ["CVE-2019-0708 (BlueKeep)"],
    "T1486": ["CVE-2021-44228 (Log4Shell)"],
}


def syslog_priority(facility: int, severity: int) -> int:
    return (facility * 8) + severity


def format_syslog_message(event: dict, host: str = "tangedco-scada") -> str:
    """
    Format event as RFC 3164 syslog message that Wazuh can receive
    and the tangedco_decoder.xml can parse.
    """
    sev = event.get("severity", "Medium")
    pri = syslog_priority(SYSLOG_FACILITY, SYSLOG_SEVERITY_MAP.get(sev, 6))
    ts = datetime.now().strftime("%b %d %H:%M:%S")

    # Enrich with threat intel
    techniques = event.get("technique", "Unknown").split("/")
    actors = set()
    cves = set()
    for t in techniques:
        t = t.strip()
        actors.update(TECHNIQUE_TO_ACTOR.get(t, []))
        cves.update(CVE_CONTEXT.get(t, []))

    # Build the JSON payload that tangedco_decoder parses
    payload = json.dumps({
        "source": "tangedco_anomaly",
        "timestamp": event.get("timestamp", ts),
        "anomaly_id": f"TNG-{int(event.get("index", 0) or 0):05d}",
        "anomaly_type": event.get("anomaly_type", "Unknown"),
        "severity": sev,
        "detector": event.get("detector", "Unknown"),
        "feature": event.get("feature", "Unknown"),
        "value": float(event.get("value", 0) or 0),
        "confidence": int(event.get("confidence", 0) or 0),
        "technique": event.get("technique", "Unknown"),
        "src_zone": _infer_zone(event.get("feature", "")),
        "description": event.get("description", "")[:200],
        "threat_actors": list(actors)[:3],
        "related_cves": list(cves)[:3],
        "true_label": event.get("true_label", "Unknown"),
    }, separators=(",", ":"))

    return f"<{pri}>{ts} {host} tangedco-ids: {payload}"


def _infer_zone(feature: str) -> str:
    """Map feature name to IEC 62443 zone."""
    feature = feature.lower()
    if "scada" in feature or "ems" in feature or "historian" in feature:
        return "Z-3_Operations"
    if "hmi" in feature or "workstation" in feature or "plc" in feature:
        return "Z-4_Control"
    if "rtu" in feature or "substation" in feature:
        return "Z-5_Field"
    if "enterprise" in feature or "corporate" in feature:
        return "Z-1_Enterprise"
    return "Z-3_Operations"


def send_udp_syslog(message: str, host: str, port: int) -> bool:
    """Send syslog message via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (host, port))
        sock.close()
        return True
    except Exception as e:
        print(f"  [!] UDP send failed: {e}", file=sys.stderr)
        return False


def send_tcp_syslog(message: str, host: str, port: int) -> bool:
    """Send syslog message via TCP (more reliable, used for production)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send((message + "\n").encode("utf-8"))
        sock.close()
        return True
    except Exception as e:
        print(f"  [!] TCP send failed: {e}", file=sys.stderr)
        return False


def print_local_event(event: dict, message: str):
    """Print formatted event to console (local mode / testing)."""
    sev = event.get("severity", "Medium")
    colors = {
        "Critical": "\033[91m",  # bright red
        "High":     "\033[93m",  # yellow
        "Medium":   "\033[33m",  # orange
        "Low":      "\033[92m",  # green
    }
    reset = "\033[0m"
    color = colors.get(sev, "")
    ts = event.get("timestamp", "")[:16]
    atype = event.get("anomaly_type", "Unknown")[:35]
    tech = event.get("technique", "Unknown")[:20]
    conf = event.get("confidence", 0)
    print(f"{color}[{sev:8s}]{reset} {ts} | {atype:<35s} | {tech:<20s} | Conf:{int(conf or 0):3d}%")


def feed_historical(csv_path: str, host: str, port: int,
                    delay: float = 0.1, local: bool = False):
    """
    Feed all rows from anomaly CSV into Wazuh.
    Use delay to simulate real-time feed (default 100ms between events).
    """
    print(f"\n{'='*60}")
    print(f"TANGEDCO → Wazuh Alert Feed (Historical Mode)")
    print(f"Source: {csv_path}")
    print(f"Target: {'LOCAL (console only)' if local else f'{host}:{port}'}")
    print(f"{'='*60}\n")

    if not Path(csv_path).exists():
        print(f"[!] CSV not found: {csv_path}")
        print("    Run the anomaly detector first:")
        print("    cd ../anomaly-detection && python main.py")
        sys.exit(1)

    stats = {"total": 0, "sent": 0, "failed": 0, "by_sev": {}}

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"[*] Loaded {len(rows)} anomaly events from CSV\n")

    for row in rows:
        msg = format_syslog_message(row)
        stats["total"] += 1
        sev = row.get("severity", "Unknown")
        stats["by_sev"][sev] = stats["by_sev"].get(sev, 0) + 1

        if local:
            print_local_event(row, msg)
            stats["sent"] += 1
        else:
            ok = send_udp_syslog(msg, host, port)
            if ok:
                stats["sent"] += 1
                print_local_event(row, msg)
            else:
                stats["failed"] += 1
        time.sleep(delay)

    print(f"\n{'='*60}")
    print(f"Feed complete. Summary:")
    print(f"  Total events : {stats['total']}")
    print(f"  Sent         : {stats['sent']}")
    print(f"  Failed       : {stats['failed']}")
    for sev, n in sorted(stats["by_sev"].items()):
        print(f"  {sev:12s}: {n}")
    print(f"{'='*60}")


def feed_live(csv_path: str, host: str, port: int,
              poll_interval: float = 5.0, local: bool = False):
    """
    Watch anomaly CSV for new rows and feed them into Wazuh in real-time.
    Useful for connecting to the live anomaly detection pipeline.
    """
    print(f"\n[*] Live feed mode — watching: {csv_path}")
    print(f"    Polling every {poll_interval}s. Press Ctrl+C to stop.\n")

    seen_indices = set()

    while True:
        try:
            if not Path(csv_path).exists():
                time.sleep(poll_interval)
                continue

            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    idx = row.get("index", "")
                    if idx not in seen_indices:
                        seen_indices.add(idx)
                        msg = format_syslog_message(row)
                        if local:
                            print_local_event(row, msg)
                        else:
                            send_udp_syslog(msg, host, port)
                            print_local_event(row, msg)

            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("\n[*] Live feed stopped.")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Feed TANGEDCO anomaly detections into Wazuh SIEM"
    )
    parser.add_argument("--csv", default="../anomaly-detection/output/anomaly_detections.csv",
                        help="Path to anomaly_detections.csv")
    parser.add_argument("--wazuh-host", default=DEFAULT_HOST,
                        help="Wazuh manager IP (default: localhost)")
    parser.add_argument("--wazuh-port", type=int, default=DEFAULT_PORT,
                        help="Wazuh syslog port (default: 514)")
    parser.add_argument("--historical", action="store_true",
                        help="Feed all existing detections")
    parser.add_argument("--live", action="store_true",
                        help="Watch CSV for new events and feed in real-time")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Delay between events in historical mode (default: 0.05s)")
    parser.add_argument("--local", action="store_true",
                        help="Print to console only — no Wazuh connection needed (for testing)")
    args = parser.parse_args()

    if not args.historical and not args.live:
        parser.print_help()
        print("\n[!] Specify --historical or --live")
        sys.exit(1)

    if args.historical:
        feed_historical(args.csv, args.wazuh_host, args.wazuh_port,
                        args.delay, args.local)
    elif args.live:
        feed_live(args.csv, args.wazuh_host, args.wazuh_port,
                  5.0, args.local)


if __name__ == "__main__":
    main()
