"""
main.py
-------
TANGEDCO ICS Anomaly Detection Tool — Entry Point

Usage:
    python main.py                          # generate synthetic data + run full pipeline
    python main.py --csv your_data.csv      # use your own CSV (Kaggle format)
    python main.py --no-plots               # skip chart generation
    python main.py --help                   # show options

Output (in output/ folder):
    anomaly_detections.csv   — all detected anomalies with ATT&CK mappings
    summary_report.txt       — human-readable text report
    plot1_full_timeline.png  — full year demand with anomalies
    plot2_attack_zooms.png   — zoomed attack windows
    plot3_detector_comparison.png — method comparison
    plot4_attack_matrix.png  — ATT&CK ICS coverage matrix
"""

import os
import sys
import argparse

# Ensure src/ is on the path when run from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from generate_data import main as gen_data
from anomaly_detector import run_detection
from visualize import generate_all_plots
import pandas as pd
from datetime import datetime


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║   TANGEDCO ICS Anomaly Detection Tool                        ║
║   Tamil Nadu Generation & Distribution Corporation           ║
║                                                              ║
║   Framework : ISO/IEC 27001:2022 · IEC 62443                ║
║   Techniques: MITRE ATT&CK for ICS                          ║
║   Methods   : Z-Score · IQR · Isolation Forest · OT Rules   ║
╚══════════════════════════════════════════════════════════════╝
"""


def write_summary_report(df: pd.DataFrame,
                          results: pd.DataFrame,
                          path: str = "output/summary_report.txt"):
    """Write a human-readable text summary of all findings."""
    lines = []
    lines.append("=" * 70)
    lines.append("TANGEDCO ICS ANOMALY DETECTION — SUMMARY REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("DATASET SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total observations : {len(df):,} hours "
                 f"({len(df)//24} days)")
    lines.append(f"  Date range         : {df['timestamp'].min().date()} to "
                 f"{df['timestamp'].max().date()}")
    lines.append(f"  True anomalies     : {df['anomaly'].sum()} hours "
                 f"({df['anomaly'].mean():.1%} of dataset)")
    lines.append("")
    lines.append("DETECTION SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total detections   : {len(results)}")
    for sev in ["Critical", "High", "Medium", "Low"]:
        n = (results["severity"] == sev).sum()
        lines.append(f"  {sev:12s}      : {n}")
    lines.append("")
    lines.append("ATTACK SCENARIOS DETECTED")
    lines.append("-" * 40)

    attack_types = df[df["anomaly"] == 1]["anomaly_type"].unique()
    for atype in attack_types:
        attack_hours = (df["anomaly_type"] == atype).sum()
        detected = results[
            results["true_label"].str.contains(atype.split("_")[0], na=False)
        ]
        lines.append(f"\n  [{atype.replace('_', ' ')}]")
        lines.append(f"    Duration injected : {attack_hours} hours")
        lines.append(f"    Detections        : {len(detected)}")
        if len(detected) > 0:
            techniques = detected["technique"].unique()
            lines.append(f"    ATT&CK techniques : {', '.join(techniques)}")
            best_det = detected.sort_values("confidence", ascending=False).iloc[0]
            lines.append(f"    Highest confidence: {best_det['confidence']}% "
                         f"via {best_det['detector']}")

    lines.append("")
    lines.append("MITRE ATT&CK FOR ICS COVERAGE")
    lines.append("-" * 40)
    technique_counts = {}
    for t in results["technique"].dropna():
        for part in t.split("/"):
            part = part.strip()
            technique_counts[part] = technique_counts.get(part, 0) + 1
    for tech, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {tech:30s} : {count} detections")

    lines.append("")
    lines.append("TOP 15 HIGHEST-CONFIDENCE DETECTIONS")
    lines.append("-" * 40)
    top = results.sort_values("confidence", ascending=False).head(15)
    for _, row in top.iterrows():
        lines.append(
            f"  [{row['severity']:8s}] [{row['confidence']:3d}%] "
            f"{row['timestamp'][:16]}  {row['detector'][:30]}  "
            f"Technique: {row['technique']}"
        )

    lines.append("")
    lines.append("DETECTION METHODOLOGY")
    lines.append("-" * 40)
    lines.append("  1. Z-Score (rolling 24h window, 3σ threshold)")
    lines.append("     Detects: sudden demand spikes, data dropouts")
    lines.append("  2. IQR (per-hour conditioned, 2.5× fence)")
    lines.append("     Detects: hour-of-day outliers missed by global Z-score")
    lines.append("  3. Isolation Forest (multi-feature, 2% contamination)")
    lines.append("     Detects: multi-dimensional combinations of subtle anomalies")
    lines.append("  4. OT Rule Engine (6 ICS-specific rules)")
    lines.append("     Detects: SCADA dropout, frequency excursion, off-hours")
    lines.append("     access, sensor flatline, power factor crash")
    lines.append("")
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 40)
    lines.append("  1. Deploy Claroty or Dragos OT NDR for real-time equivalent")
    lines.append("     of this detection logic on live SCADA traffic.")
    lines.append("  2. Feed detections into SIEM (QRadar/Sentinel) alongside")
    lines.append("     IT security events for unified SOC correlation.")
    lines.append("  3. Tune IQR thresholds seasonally — Tamil Nadu peak demand")
    lines.append("     shifts significantly March–June (summer cooling load).")
    lines.append("  4. Add DNP3/IEC 104 protocol-level analysis for T0855")
    lines.append("     detection at the command level (requires OT NDR tap).")
    lines.append("  5. Implement automated SOAR response for Critical alerts:")
    lines.append("     isolate segment, capture PCAP, alert OT security lead.")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Summary report saved: {path}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="TANGEDCO ICS Anomaly Detection Tool"
    )
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to existing CSV (Kaggle format). "
                             "If omitted, synthetic data is generated.")
    parser.add_argument("--no-plots", action="store_true",
                        help="Skip chart generation (faster)")
    parser.add_argument("--days", type=int, default=365,
                        help="Days of synthetic data to generate (default: 365)")
    args = parser.parse_args()

    # ── Create output dir ─────────────────────────────────────────────────
    os.makedirs("output", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    # ── Step 1: Get data ──────────────────────────────────────────────────
    csv_path = args.csv or "data/tangedco_grid_data.csv"

    if args.csv:
        print(f"[*] Using provided dataset: {args.csv}")
    else:
        if not os.path.exists(csv_path):
            print("[*] No dataset found. Generating synthetic data...")
            gen_data()
        else:
            print(f"[*] Using existing dataset: {csv_path}")

    # ── Step 2: Run detectors ─────────────────────────────────────────────
    results = run_detection(csv_path)

    # ── Step 3: Load df for plotting/reporting ────────────────────────────
    df = pd.read_csv(csv_path, parse_dates=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

    # ── Step 4: Visualizations ────────────────────────────────────────────
    if not args.no_plots:
        generate_all_plots(df, results)
    else:
        print("[*] Skipping plots (--no-plots)")

    # ── Step 5: Summary report ────────────────────────────────────────────
    write_summary_report(df, results)

    # ── Done ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print("Output files:")
    for f in os.listdir("output"):
        size = os.path.getsize(f"output/{f}")
        print(f"  output/{f:<40s} ({size/1024:.1f} KB)")
    print("\nNext steps:")
    print("  - Download the real Kaggle dataset:")
    print("    kaggle.com/datasets/pythonafroz/tamilnadu-electricity-board-hourly-readings")
    print("  - Run: python main.py --csv your_kaggle_file.csv")
    print("  - Upload output/ to GitHub and link in README")


if __name__ == "__main__":
    main()
