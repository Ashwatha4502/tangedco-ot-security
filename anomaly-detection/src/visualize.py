"""
visualize.py
------------
Generates all charts for the TANGEDCO anomaly detection report.

Outputs 4 plots saved to output/:
  1. Full year demand timeline with anomalies highlighted
  2. Attack scenario deep-dives (zoomed windows around each attack)
  3. Detector comparison (which method caught what)
  4. Severity and ATT&CK technique distribution
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # headless rendering for servers
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.lines import Line2D

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.facecolor": "#06101f",
    "axes.facecolor":   "#0a1628",
    "axes.edgecolor":   "#1e3050",
    "axes.labelcolor":  "#8899bb",
    "axes.titlecolor":  "#cdd6f4",
    "text.color":       "#cdd6f4",
    "xtick.color":      "#405070",
    "ytick.color":      "#405070",
    "grid.color":       "#172035",
    "grid.alpha":       0.6,
    "legend.facecolor": "#0a1628",
    "legend.edgecolor": "#1e3050",
    "font.family":      "monospace",
    "axes.grid":        True,
    "grid.linestyle":   "--",
})

COLORS = {
    "normal":     "#3b82f6",
    "Critical":   "#ef4444",
    "High":       "#f97316",
    "Medium":     "#eab308",
    "Low":        "#22c55e",
    "annotation": "#f5a623",
    "zscore":     "#06b6d4",
    "iqr":        "#a855f7",
    "if":         "#ec4899",
    "rule":       "#f5a623",
}

ATTACK_COLORS = {
    "Ransomware_SCADA_Blackout":          "#ef4444",
    "Demand_Manipulation_Unauthorised_Command": "#f97316",
    "Sensor_Spoofing_MITM":               "#eab308",
    "OffHours_Privileged_Access":          "#22c55e",
    "Loss_of_View_SCADA_Wiper":            "#ec4899",
    "Normal":                              "#3b82f6",
}


def plot_1_full_timeline(df: pd.DataFrame,
                          results: pd.DataFrame,
                          save_path: str = "output/plot1_full_timeline.png"):
    """
    Plot 1: Full-year demand with detected anomalies overlaid.
    Shows the 'big picture' — where in the year attacks occurred.
    """
    fig, axes = plt.subplots(3, 1, figsize=(18, 12),
                              gridspec_kw={"height_ratios": [3, 1, 1]})
    fig.suptitle("TANGEDCO Grid — Full Year Demand & Detected Anomalies\n"
                 "ISO/IEC 27001:2022 · MITRE ATT&CK for ICS",
                 fontsize=14, fontweight="bold", color="#f5a623", y=0.98)

    # ── Top: demand timeline ──────────────────────────────────────────────
    ax = axes[0]
    demand = df["total_demand_mw"].copy()

    ax.plot(df["timestamp"], demand, color=COLORS["normal"],
            linewidth=0.6, alpha=0.7, label="Grid Demand (MW)", zorder=2)

    # Shade true attack periods
    attack_types = df[df["anomaly"] == 1]["anomaly_type"].unique()
    for atype in attack_types:
        mask = df["anomaly_type"] == atype
        indices = df[mask].index
        if len(indices) == 0:
            continue
        color = ATTACK_COLORS.get(atype, "#ffffff")
        # Plot as vertical band
        x_min = df.loc[indices[0], "timestamp"]
        x_max = df.loc[indices[-1], "timestamp"]
        ax.axvspan(x_min, x_max, alpha=0.3, color=color, zorder=1)
        ax.text(x_min, ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 15000,
                atype.replace("_", "\n"), fontsize=6.5,
                color=color, va="top", rotation=0, zorder=5)

    # Mark detection points
    for sev in ["Critical", "High", "Medium"]:
        det_idx = results[results["severity"] == sev]["index"].tolist()
        det_ts = df.loc[[i for i in det_idx if i in df.index], "timestamp"]
        det_vals = demand.loc[[i for i in det_idx if i in demand.index]]
        ax.scatter(det_ts, det_vals.values,
                   color=COLORS[sev], s=25, zorder=6,
                   label=f"{sev} Detection", marker="^", alpha=0.85)

    ax.set_ylabel("Demand (MW)", fontsize=10)
    ax.set_title("Total Grid Demand with Attack Annotations", fontsize=11)
    ax.legend(loc="upper right", fontsize=8, ncol=3)
    ax.set_xlim(df["timestamp"].min(), df["timestamp"].max())

    # ── Middle: frequency ─────────────────────────────────────────────────
    ax2 = axes[1]
    ax2.plot(df["timestamp"], df["frequency_hz"],
             color="#14b8a6", linewidth=0.6, alpha=0.8)
    ax2.axhline(50.2, color="#ef4444", linestyle="--", linewidth=0.8, alpha=0.6, label="Alert threshold")
    ax2.axhline(49.8, color="#ef4444", linestyle="--", linewidth=0.8, alpha=0.6)
    ax2.set_ylabel("Frequency (Hz)", fontsize=9)
    ax2.set_title("Grid Frequency", fontsize=10)
    ax2.legend(fontsize=8)
    ax2.set_xlim(df["timestamp"].min(), df["timestamp"].max())

    # ── Bottom: anomaly flags ─────────────────────────────────────────────
    ax3 = axes[2]
    sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for _, row in results.iterrows():
        if row["index"] in df.index:
            ts = df.loc[row["index"], "timestamp"]
            ax3.bar(ts, sev_map.get(row["severity"], 1),
                    width=pd.Timedelta(hours=3),
                    color=COLORS.get(row["severity"], "#888"),
                    alpha=0.8)
    ax3.set_ylabel("Severity", fontsize=9)
    ax3.set_yticks([1, 2, 3, 4])
    ax3.set_yticklabels(["Low", "Med", "High", "Crit"], fontsize=7)
    ax3.set_title("Detected Anomaly Timeline", fontsize=10)
    ax3.set_xlim(df["timestamp"].min(), df["timestamp"].max())

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [+] Saved: {save_path}")


def plot_2_attack_zooms(df: pd.DataFrame,
                         save_path: str = "output/plot2_attack_zooms.png"):
    """
    Plot 2: Zoom into each of the 5 attack windows to show exactly
    what the anomaly looks like in the data.
    """
    attacks = df[df["anomaly"] == 1]["anomaly_type"].unique()
    n = len(attacks)
    fig, axes = plt.subplots(n, 1, figsize=(16, 4 * n))
    fig.suptitle("Attack Scenario Deep-Dives — Demand Signal Around Each Incident",
                 fontsize=13, fontweight="bold", color="#f5a623")

    for i, atype in enumerate(attacks):
        ax = axes[i] if n > 1 else axes
        mask = df["anomaly_type"] == atype
        attack_indices = df[mask].index
        if len(attack_indices) == 0:
            continue

        # Show 48h window centred on attack
        centre = attack_indices[len(attack_indices) // 2]
        window_start = max(0, centre - 24)
        window_end   = min(len(df) - 1, centre + 24)
        window = df.loc[window_start:window_end].copy()

        color = ATTACK_COLORS.get(atype, "#ffffff")

        # Normal background
        normal_mask = window["anomaly_type"] == "Normal"
        attack_wmask = window["anomaly_type"] == atype

        ax.plot(window.loc[normal_mask, "timestamp"],
                window.loc[normal_mask, "total_demand_mw"].fillna(0),
                color=COLORS["normal"], linewidth=1.5, label="Normal", zorder=2)

        # Attack period
        if attack_wmask.any():
            ax.fill_between(
                window.loc[attack_wmask, "timestamp"],
                0,
                window.loc[attack_wmask, "total_demand_mw"].fillna(0),
                color=color, alpha=0.4, zorder=3, label=atype.replace("_", " ")
            )
            ax.plot(window.loc[attack_wmask, "timestamp"],
                    window.loc[attack_wmask, "total_demand_mw"].fillna(0),
                    color=color, linewidth=2, zorder=4)

        # Annotate ATT&CK technique
        technique = df.loc[attack_indices[0], "attack_technique"]
        ax.set_title(f"{atype.replace('_', ' ')}  ·  ATT&CK ICS: {technique}",
                     fontsize=10, color=color)
        ax.set_ylabel("Demand (MW)", fontsize=9)
        ax.legend(loc="upper right", fontsize=8)

        # Mark attack start/end
        ax.axvline(df.loc[attack_indices[0], "timestamp"],
                   color=color, linestyle="--", linewidth=1, alpha=0.7)
        ax.axvline(df.loc[attack_indices[-1], "timestamp"],
                   color=color, linestyle="--", linewidth=1, alpha=0.7)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [+] Saved: {save_path}")


def plot_3_detector_comparison(results: pd.DataFrame,
                                save_path: str = "output/plot3_detector_comparison.png"):
    """
    Plot 3: Which detectors caught what. Useful for showing the layered
    defence-in-depth approach.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Detection Method Analysis — Layered Defence Coverage",
                 fontsize=13, fontweight="bold", color="#f5a623")

    # ── Detections by method ──────────────────────────────────────────────
    ax = axes[0]
    det_counts = results["detector"].str.split(":").str[0].value_counts()
    bar_colors = []
    for label in det_counts.index:
        if "Z-Score" in label:       bar_colors.append(COLORS["zscore"])
        elif "IQR" in label:         bar_colors.append(COLORS["iqr"])
        elif "Isolation" in label:   bar_colors.append(COLORS["if"])
        else:                        bar_colors.append(COLORS["rule"])

    bars = ax.barh(det_counts.index, det_counts.values,
                   color=bar_colors, alpha=0.85, edgecolor="#1e3050")
    for bar, val in zip(bars, det_counts.values):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9, color="#cdd6f4")
    ax.set_xlabel("Anomalies Detected", fontsize=10)
    ax.set_title("Detections per Method", fontsize=11)

    # ── Severity distribution ─────────────────────────────────────────────
    ax2 = axes[1]
    sev_counts = results["severity"].value_counts().reindex(
        ["Critical", "High", "Medium", "Low"], fill_value=0
    )
    sev_colors = [COLORS[s] for s in sev_counts.index]
    wedges, texts, autotexts = ax2.pie(
        sev_counts.values,
        labels=sev_counts.index,
        colors=sev_colors,
        autopct="%1.0f%%",
        startangle=90,
        wedgeprops={"edgecolor": "#06101f", "linewidth": 2},
    )
    for t in texts + autotexts:
        t.set_color("#cdd6f4")
        t.set_fontsize(10)
    ax2.set_title("Severity Distribution", fontsize=11)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [+] Saved: {save_path}")


def plot_4_attack_matrix(results: pd.DataFrame,
                          save_path: str = "output/plot4_attack_matrix.png"):
    """
    Plot 4: ATT&CK for ICS technique heatmap — shows which techniques
    were detected and how many times. This is the kind of thing you'd
    show a CISO or in a SOC review.
    """
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.suptitle("MITRE ATT&CK for ICS — Detection Coverage Matrix\n"
                 "TANGEDCO SCADA Environment",
                 fontsize=13, fontweight="bold", color="#f5a623")

    techniques = {
        "T0813 – Denial of View":            "Impact",
        "T0816 – Device Restart/Shutdown":   "Impact",
        "T0826 – Loss of Availability":      "Impact",
        "T0830 – MITM":                      "Lateral Movement",
        "T0855 – Unauthorised Command":      "Impair Process Control",
        "T0856 – Spoof Reporting Message":   "Collection",
        "T0859 – Valid Accounts":            "Persistence",
        "T0882 – Theft of Operational Data": "Collection",
    }

    # Count how many detections reference each technique
    counts = {}
    for tech in techniques:
        short = tech.split("–")[0].strip()
        n = results["technique"].str.contains(short, na=False).sum()
        counts[tech] = n

    techs = list(techniques.keys())
    cats  = [techniques[t] for t in techs]
    vals  = [counts[t] for t in techs]

    cat_colors = {
        "Impact":                "#ef4444",
        "Lateral Movement":      "#f97316",
        "Impair Process Control":"#eab308",
        "Collection":            "#22c55e",
        "Persistence":           "#06b6d4",
    }
    bar_colors = [cat_colors[c] for c in cats]

    bars = ax.barh(techs, vals, color=bar_colors, alpha=0.8,
                   edgecolor="#1e3050", height=0.6)
    for bar, val in zip(bars, vals):
        if val > 0:
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", fontsize=9, color="#cdd6f4")

    # Category legend
    legend_patches = [mpatches.Patch(color=c, label=k)
                       for k, c in cat_colors.items()]
    ax.legend(handles=legend_patches, loc="lower right",
              fontsize=9, title="Tactic", title_fontsize=9)

    ax.set_xlabel("Detection Count", fontsize=10)
    ax.set_title("Technique Detection Frequency", fontsize=11)
    ax.invert_yaxis()

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [+] Saved: {save_path}")


def generate_all_plots(df: pd.DataFrame, results: pd.DataFrame):
    print("\n[*] Generating visualizations...")
    plot_1_full_timeline(df, results)
    plot_2_attack_zooms(df)
    plot_3_detector_comparison(results)
    plot_4_attack_matrix(results)
    print("[+] All plots generated in output/")
