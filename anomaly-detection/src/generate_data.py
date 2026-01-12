"""
generate_data.py
----------------
Generates a synthetic TANGEDCO-style electricity dataset based on the
real Kaggle Tamil Nadu Electricity Board hourly readings format.

Injects 5 realistic cyberattack anomaly scenarios mapped to MITRE ATT&CK for ICS.
Run this if you don't have the Kaggle dataset yet.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# ── Reproducibility ──────────────────────────────────────────────────────────
np.random.seed(42)


def generate_normal_demand(hours: int) -> np.ndarray:
    """
    Simulate realistic Tamil Nadu electricity demand patterns.
    Captures: daily seasonality, weekly seasonality, temperature-driven
    summer peaks, and random noise.
    """
    t = np.arange(hours)

    # Base load (MW) — TANGEDCO serves ~3 crore consumers
    base = 9500

    # Daily cycle: peaks at 18:00–21:00, trough at 03:00–05:00
    daily = 1800 * np.sin(2 * np.pi * (t % 24 - 6) / 24)

    # Weekly cycle: lower on Sundays (industrial demand drops)
    weekly = 400 * np.sin(2 * np.pi * (t % 168) / 168)

    # Seasonal cycle: summer peak (Tamil Nadu: March–June is hottest)
    seasonal = 600 * np.sin(2 * np.pi * t / (24 * 365) - np.pi / 2)

    # Random noise (grid fluctuations, measurement jitter)
    noise = np.random.normal(0, 180, hours)

    demand = base + daily + weekly + seasonal + noise
    return np.clip(demand, 4000, 16000)


def generate_dataset(start_date: str = "2023-01-01",
                     days: int = 365) -> pd.DataFrame:
    """
    Build the full hourly dataset with zone-wise breakdown.
    Format mirrors the Kaggle Tamil Nadu Electricity Board dataset.
    """
    hours = days * 24
    start = datetime.strptime(start_date, "%Y-%m-%d")
    timestamps = [start + timedelta(hours=i) for i in range(hours)]

    # Total grid demand
    total_demand = generate_normal_demand(hours)

    # Zone-wise split (approximate real Tamil Nadu distribution)
    # Chennai Metro gets ~28%, North TN ~22%, South TN ~25%, West TN ~25%
    zone_fractions = {
        "Chennai_Metro":  0.28,
        "North_TamilNadu": 0.22,
        "South_TamilNadu": 0.25,
        "West_TamilNadu":  0.25,
    }

    df = pd.DataFrame({"timestamp": timestamps, "total_demand_mw": total_demand})
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek  # 0=Monday
    df["month"] = df["timestamp"].dt.month
    df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype(int)

    # Zone demands
    for zone, frac in zone_fractions.items():
        zone_noise = np.random.normal(0, 50, hours)
        df[f"demand_{zone}_mw"] = np.clip(
            total_demand * frac + zone_noise, 500, 6000
        )

    # Grid frequency (normal: 49.9–50.1 Hz)
    df["frequency_hz"] = np.random.normal(50.0, 0.05, hours)
    df["frequency_hz"] = np.clip(df["frequency_hz"], 49.5, 50.5)

    # Power factor (normal: 0.92–0.98)
    df["power_factor"] = np.random.normal(0.95, 0.015, hours)
    df["power_factor"] = np.clip(df["power_factor"], 0.70, 1.0)

    # Transmission losses (normal: 18–22%)
    df["transmission_loss_pct"] = np.random.normal(20, 1.2, hours)
    df["transmission_loss_pct"] = np.clip(df["transmission_loss_pct"], 12, 35)

    # SCADA data quality flag (1 = good, 0 = missing/bad)
    df["scada_data_quality"] = 1

    # Anomaly label (0 = normal, will be updated below)
    df["anomaly"] = 0
    df["anomaly_type"] = "Normal"
    df["attack_technique"] = ""

    return df


# ── ATTACK INJECTION FUNCTIONS ───────────────────────────────────────────────

def inject_ransomware_disruption(df: pd.DataFrame,
                                  start_idx: int) -> pd.DataFrame:
    """
    Scenario A: Ransomware hits IT systems. OT team shuts SCADA precautionarily.
    Effect: Data dropout (SCADA goes dark for 6–8 hours), then sudden
    demand swing as manual operations struggle with load balancing.

    MITRE ATT&CK ICS: T0816 – Device Restart/Shutdown, T0882 – Data Theft
    """
    duration = 8  # hours of SCADA blackout
    end_idx = min(start_idx + duration, len(df))

    print(f"  [INJECT] Ransomware/IT-OT Disruption @ index {start_idx} "
          f"({df.loc[start_idx,'timestamp']})")

    # SCADA data goes dark
    df.loc[start_idx:end_idx, "scada_data_quality"] = 0
    df.loc[start_idx:end_idx, "total_demand_mw"] = np.nan

    # After outage: manual operations cause large swings
    recovery = end_idx + 1
    recovery_end = min(recovery + 4, len(df))
    swing = np.random.uniform(1800, 2800, recovery_end - recovery)
    df.loc[recovery:recovery_end - 1, "total_demand_mw"] += swing

    df.loc[start_idx:recovery_end, "anomaly"] = 1
    df.loc[start_idx:recovery_end, "anomaly_type"] = "Ransomware_SCADA_Blackout"
    df.loc[start_idx:recovery_end, "attack_technique"] = "T0816/T0882"

    return df


def inject_demand_manipulation(df: pd.DataFrame,
                                start_idx: int) -> pd.DataFrame:
    """
    Scenario B: Adversary sends unauthorised commands to grid assets.
    Effect: Sudden unexplained demand spike — load suddenly appears or
    disappears as breakers are opened/closed remotely.

    MITRE ATT&CK ICS: T0855 – Unauthorised Command Message
    """
    duration = 3
    end_idx = min(start_idx + duration, len(df))

    print(f"  [INJECT] Demand Manipulation (Unauthorised Commands) @ index "
          f"{start_idx} ({df.loc[start_idx,'timestamp']})")

    # Sudden demand drop (breakers opened) followed by spike (reconnection surge)
    df.loc[start_idx:start_idx + 1, "total_demand_mw"] *= 0.45  # breakers open
    df.loc[start_idx + 2:end_idx, "total_demand_mw"] *= 1.65    # reconnection surge
    n_rows = len(df.loc[start_idx:end_idx])
    df.loc[start_idx:end_idx, "frequency_hz"] += np.random.uniform(0.3, 0.6, n_rows)

    df.loc[start_idx:end_idx, "anomaly"] = 1
    df.loc[start_idx:end_idx, "anomaly_type"] = "Demand_Manipulation_Unauthorised_Command"
    df.loc[start_idx:end_idx, "attack_technique"] = "T0855"

    return df


def inject_sensor_spoofing(df: pd.DataFrame,
                            start_idx: int) -> pd.DataFrame:
    """
    Scenario C: Adversary manipulates sensor readings sent to SCADA historian.
    Effect: Readings freeze or flatline — sensor appears stuck at one value.
    Classic indicator of man-in-the-middle on ICS protocol.

    MITRE ATT&CK ICS: T0856 – Spoof Reporting Message, T0830 – MITM
    """
    duration = 12
    end_idx = min(start_idx + duration, len(df))

    print(f"  [INJECT] Sensor Spoofing / MITM @ index {start_idx} "
          f"({df.loc[start_idx,'timestamp']})")

    # Freeze the reading at the value just before the attack
    frozen_val = df.loc[start_idx, "total_demand_mw"]
    df.loc[start_idx:end_idx, "total_demand_mw"] = frozen_val
    df.loc[start_idx:end_idx, "frequency_hz"] = 50.01  # suspiciously stable

    # Chennai Metro zone also frozen (that's the targeted zone)
    frozen_zone = df.loc[start_idx, "demand_Chennai_Metro_mw"]
    df.loc[start_idx:end_idx, "demand_Chennai_Metro_mw"] = frozen_zone

    df.loc[start_idx:end_idx, "anomaly"] = 1
    df.loc[start_idx:end_idx, "anomaly_type"] = "Sensor_Spoofing_MITM"
    df.loc[start_idx:end_idx, "attack_technique"] = "T0856/T0830"

    return df


def inject_offhours_access(df: pd.DataFrame,
                            start_idx: int) -> pd.DataFrame:
    """
    Scenario D: Adversary uses stolen credentials for SCADA access at 03:00.
    Effect: Unusual small demand changes at an hour that is normally dead-quiet
    — an operator making minor load adjustments at 3am is a red flag.

    MITRE ATT&CK ICS: T0859 – Valid Accounts (Privileged)
    """
    # Force the anomaly to happen at 03:00
    # Find next 03:00 from start_idx
    for offset in range(24):
        idx = start_idx + offset
        if idx < len(df) and df.loc[idx, "hour"] == 3:
            start_idx = idx
            break

    end_idx = min(start_idx + 2, len(df))

    print(f"  [INJECT] Off-Hours Privileged Access @ index {start_idx} "
          f"({df.loc[start_idx,'timestamp']})")

    # Small, precise demand change at 03:00 (not natural — looks like command)
    df.loc[start_idx:end_idx, "total_demand_mw"] += 420  # suspiciously round
    df.loc[start_idx:end_idx, "power_factor"] -= 0.08   # power factor drops slightly

    df.loc[start_idx:end_idx, "anomaly"] = 1
    df.loc[start_idx:end_idx, "anomaly_type"] = "OffHours_Privileged_Access"
    df.loc[start_idx:end_idx, "attack_technique"] = "T0859"

    return df


def inject_loss_of_view(df: pd.DataFrame,
                         start_idx: int) -> pd.DataFrame:
    """
    Scenario E: Wiper malware kills SCADA historian.
    Effect: Entire monitoring stream goes to zero/null — not a power outage
    (grid is still running) but SCADA sees nothing. Critical blind spot.

    MITRE ATT&CK ICS: T0813 – Denial of View
    """
    duration = 5
    end_idx = min(start_idx + duration, len(df))

    print(f"  [INJECT] Loss of View (SCADA Wiper) @ index {start_idx} "
          f"({df.loc[start_idx,'timestamp']})")

    # All readings drop to zero (historian wiped, not actual grid failure)
    for col in ["total_demand_mw", "demand_Chennai_Metro_mw",
                "demand_North_TamilNadu_mw", "demand_South_TamilNadu_mw",
                "demand_West_TamilNadu_mw", "frequency_hz"]:
        df.loc[start_idx:end_idx, col] = 0

    df.loc[start_idx:end_idx, "scada_data_quality"] = 0
    df.loc[start_idx:end_idx, "anomaly"] = 1
    df.loc[start_idx:end_idx, "anomaly_type"] = "Loss_of_View_SCADA_Wiper"
    df.loc[start_idx:end_idx, "attack_technique"] = "T0813"

    return df


def inject_all_attacks(df: pd.DataFrame) -> pd.DataFrame:
    """
    Inject all 5 attack scenarios at spread-out points across the year.
    Chosen during business hours / off-hours to make them realistic.
    """
    total = len(df)
    print("\n[*] Injecting cyberattack anomalies into dataset...")

    # Spread attacks across the year at realistic times
    injection_points = {
        "ransomware":   int(total * 0.12),   # ~Feb, during business hours
        "demand_manip": int(total * 0.28),   # ~Apr, evening peak
        "sensor_spoof": int(total * 0.45),   # ~Jun, summer peak season
        "offhours":     int(total * 0.61),   # ~Aug, 03:00 access
        "loss_of_view": int(total * 0.80),   # ~Oct
    }

    df = inject_ransomware_disruption(df, injection_points["ransomware"])
    df = inject_demand_manipulation(df, injection_points["demand_manip"])
    df = inject_sensor_spoofing(df, injection_points["sensor_spoof"])
    df = inject_offhours_access(df, injection_points["offhours"])
    df = inject_loss_of_view(df, injection_points["loss_of_view"])

    n_anomaly = df["anomaly"].sum()
    print(f"[*] Injection complete. Total anomalous hours: {n_anomaly} "
          f"({n_anomaly/total*100:.1f}% of dataset)\n")

    return df


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("TANGEDCO Synthetic Dataset Generator")
    print("Based on: Tamil Nadu Electricity Board Hourly Readings")
    print("=" * 60)

    print("\n[*] Generating 365 days of normal grid operations...")
    df = generate_dataset(start_date="2023-01-01", days=365)

    df = inject_all_attacks(df)

    out_path = "data/tangedco_grid_data.csv"
    df.to_csv(out_path, index=False)

    print(f"[+] Dataset saved: {out_path}")
    print(f"    Shape: {df.shape}")
    print(f"    Columns: {list(df.columns)}")
    print(f"\n    Attack breakdown:")
    for at in df[df["anomaly"] == 1]["anomaly_type"].unique():
        n = (df["anomaly_type"] == at).sum()
        print(f"    - {at}: {n} hours")

    return df


if __name__ == "__main__":
    main()
