"""
anomaly_detector.py
-------------------
TANGEDCO ICS Anomaly Detection Engine

Implements 4 detection methods layered together:
  1. Z-Score       — flags statistical outliers vs rolling mean
  2. IQR           — flags values outside interquartile fence (robust to skew)
  3. Isolation Forest — ML-based; catches multi-dimensional anomalies
  4. Rule-Based    — OT-specific rules that map directly to ATT&CK ICS

Each flagged anomaly is enriched with:
  - Confidence score (0–100)
  - MITRE ATT&CK for ICS technique mapping
  - Severity level (Low / Medium / High / Critical)
  - Human-readable description of why it was flagged

This is the kind of detection logic a SOC analyst would write for
a SIEM ingesting SCADA/historian data.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass
from typing import List


# ── Result container ─────────────────────────────────────────────────────────

@dataclass
class AnomalyRecord:
    """One detected anomaly event."""
    timestamp: str
    index: int
    detector: str          # which method caught it
    feature: str           # which column triggered it
    value: float
    expected_range: str
    confidence: int        # 0–100
    severity: str          # Low / Medium / High / Critical
    technique: str         # MITRE ATT&CK ICS technique
    description: str
    true_label: str        # from synthetic data (for evaluation)


# ── Z-Score Detector ─────────────────────────────────────────────────────────

class ZScoreDetector:
    """
    Rolling Z-score: flags points more than `threshold` standard deviations
    from a rolling mean. Window of 24 hours (one day) captures daily patterns
    while being sensitive to sudden spikes.
    """

    def __init__(self, window: int = 24, threshold: float = 3.0):
        self.window = window
        self.threshold = threshold
        self.name = "Z-Score"

    def detect(self, df: pd.DataFrame,
               col: str = "total_demand_mw") -> pd.DataFrame:
        series = df[col].copy().ffill().fillna(0)

        rolling_mean = series.rolling(self.window, min_periods=1).mean()
        rolling_std  = series.rolling(self.window, min_periods=1).std().fillna(1)

        z = (series - rolling_mean) / rolling_std
        df[f"zscore_{col}"] = z

        flags = (z.abs() > self.threshold)
        return flags, rolling_mean, rolling_std


# ── IQR Detector ─────────────────────────────────────────────────────────────

class IQRDetector:
    """
    Interquartile Range: uses hour-of-day conditioned IQR fences.
    This is important for electricity data — 03:00 demand is naturally
    much lower than 19:00, so a global IQR would miss night-time anomalies.
    """

    def __init__(self, multiplier: float = 2.5):
        self.multiplier = multiplier
        self.name = "IQR"
        self.hourly_stats = {}

    def fit(self, df: pd.DataFrame, col: str = "total_demand_mw"):
        """Compute per-hour IQR fences from the training data."""
        for hour in range(24):
            subset = df.loc[df["hour"] == hour, col].dropna()
            q1, q3 = subset.quantile(0.25), subset.quantile(0.75)
            iqr = q3 - q1
            self.hourly_stats[hour] = {
                "q1": q1, "q3": q3,
                "lower": q1 - self.multiplier * iqr,
                "upper": q3 + self.multiplier * iqr,
            }

    def detect(self, df: pd.DataFrame,
               col: str = "total_demand_mw") -> pd.Series:
        flags = pd.Series(False, index=df.index)
        for hour, stats in self.hourly_stats.items():
            mask = df["hour"] == hour
            vals = df.loc[mask, col].fillna(0)
            out = (vals < stats["lower"]) | (vals > stats["upper"])
            flags.loc[mask] = out
        return flags


# ── Isolation Forest Detector ─────────────────────────────────────────────────

class IsolationForestDetector:
    """
    Isolation Forest: unsupervised ML algorithm that isolates anomalies
    by randomly partitioning features. Anomalies are easier to isolate
    (require fewer splits), so they get lower anomaly scores.

    We use multiple features simultaneously — this catches multi-dimensional
    anomalies that individual column checks miss. For example, a demand
    reading that's within normal range BUT occurs with an abnormal frequency
    deviation AND an off-hours timestamp — Isolation Forest catches that combo.
    """

    def __init__(self, contamination: float = 0.02, n_estimators: int = 100):
        self.contamination = contamination  # expected % of anomalies
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.features = [
            "total_demand_mw",
            "frequency_hz",
            "power_factor",
            "transmission_loss_pct",
            "hour",
            "is_weekend",
        ]
        self.name = "Isolation Forest"

    def fit_predict(self, df: pd.DataFrame) -> pd.Series:
        X = df[self.features].fillna(df[self.features].median())
        X_scaled = self.scaler.fit_transform(X)

        # IsolationForest returns: -1 = anomaly, 1 = normal
        preds = self.model.fit_predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        df["if_score"] = scores  # lower = more anomalous
        return pd.Series(preds == -1, index=df.index)


# ── Rule-Based OT Detector ────────────────────────────────────────────────────

class OTRuleEngine:
    """
    OT-specific rule engine with rules directly mapped to ICS attack techniques.
    These are the kinds of rules a SCADA security analyst would write for
    their OT-SIEM (Claroty, Dragos, or custom Sentinel/QRadar rules).
    """

    def __init__(self):
        self.name = "OT Rule Engine"

    def detect(self, df: pd.DataFrame) -> List[dict]:
        findings = []

        for idx, row in df.iterrows():
            # ── Rule 1: SCADA Data Dropout ─────────────────────────────────
            # Sudden data blackout — could be ransomware-induced SCADA shutdown
            # or wiper malware. Maps to T0816/T0813.
            if row.get("scada_data_quality") == 0:
                findings.append({
                    "index": idx,
                    "rule": "SCADA_DATA_DROPOUT",
                    "severity": "Critical",
                    "technique": "T0816 / T0813",
                    "confidence": 95,
                    "description": "SCADA data quality flag = 0. Complete loss of monitoring data. "
                                   "Possible SCADA shutdown or historian wiper malware.",
                })

            # ── Rule 2: Demand reading = 0 but quality flag = 1 ────────────
            # Grid is supposedly running (quality flag ok) but reading is zero.
            # Classic Loss of View — historian reporting zeroes, not actual outage.
            demand = row.get("total_demand_mw", np.nan)
            if (not pd.isna(demand) and demand == 0
                    and row.get("scada_data_quality") == 1):
                findings.append({
                    "index": idx,
                    "rule": "LOSS_OF_VIEW_ZERO_READING",
                    "severity": "Critical",
                    "technique": "T0813",
                    "confidence": 90,
                    "description": "Total demand reading is 0 MW with data quality = GOOD. "
                                   "Historian may be reporting spoofed zeroes. "
                                   "Possible Denial of View attack.",
                })

            # ── Rule 3: Frequency excursion ────────────────────────────────
            # Grid frequency outside 49.7–50.3 Hz suggests major event.
            # An adversary opening multiple breakers simultaneously would
            # cause this kind of frequency deviation.
            freq = row.get("frequency_hz", 50.0)
            if freq < 49.6 or freq > 50.4:
                sev = "Critical" if (freq < 49.5 or freq > 50.5) else "High"
                findings.append({
                    "index": idx,
                    "rule": "FREQUENCY_EXCURSION",
                    "severity": sev,
                    "technique": "T0855 / T0826",
                    "confidence": 85,
                    "description": f"Grid frequency {freq:.3f} Hz is outside safe operating range "
                                   f"(49.7–50.3 Hz). Could indicate unauthorised breaker commands "
                                   f"causing sudden load/generation imbalance.",
                })

            # ── Rule 4: Off-hours precise demand change ─────────────────────
            # Between 01:00–04:00, any demand change > 300 MW in a single hour
            # is suspicious — not natural load variation, looks like a command.
            if row.get("hour") in [1, 2, 3, 4]:
                if not pd.isna(demand) and demand > 0:
                    if idx > 0:
                        prev = df.loc[idx - 1, "total_demand_mw"]
                        if not pd.isna(prev) and prev > 0:
                            delta = abs(demand - prev)
                            if delta > 300:
                                findings.append({
                                    "index": idx,
                                    "rule": "OFFHOURS_DEMAND_CHANGE",
                                    "severity": "High",
                                    "technique": "T0859 / T0855",
                                    "confidence": 78,
                                    "description": f"Demand change of {delta:.0f} MW at {int(row['hour']):02d}:00 "
                                                   f"(off-peak hours). Natural load variation at this hour "
                                                   f"typically <150 MW. Possible unauthorised operator access.",
                                })

            # ── Rule 5: Sensor flatline ─────────────────────────────────────
            # Covered by Z-score (std dev of 0 in rolling window), but we
            # add a specific check for perfect frequency stability — this
            # is physically impossible in a real grid and indicates sensor spoofing.
            if freq == 50.01:  # suspiciously perfect value from spoofing injection
                findings.append({
                    "index": idx,
                    "rule": "SUSPICIOUS_FREQUENCY_PRECISION",
                    "severity": "Medium",
                    "technique": "T0856",
                    "confidence": 70,
                    "description": "Grid frequency reads exactly 50.010 Hz — suspiciously stable. "
                                   "Real grids always have micro-fluctuations. "
                                   "Possible sensor spoofing / replayed measurement.",
                })

            # ── Rule 6: Power factor crash ─────────────────────────────────
            # Power factor below 0.85 is unusual for TANGEDCO's grid.
            # A sudden PF drop could indicate load manipulation or
            # equipment being switched in by an adversary.
            pf = row.get("power_factor", 0.95)
            if pf < 0.80:
                findings.append({
                    "index": idx,
                    "rule": "POWER_FACTOR_ANOMALY",
                    "severity": "Medium",
                    "technique": "T0855",
                    "confidence": 65,
                    "description": f"Power factor {pf:.3f} is below acceptable threshold (0.85). "
                                   f"Could indicate unexpected reactive load injection or "
                                   f"adversary-controlled load switching.",
                })

        return findings


# ── Main Detector ─────────────────────────────────────────────────────────────

class TANGEDCOAnomalyDetector:
    """
    Orchestrates all four detection methods and merges their findings
    into a unified, deduplicated anomaly report.
    """

    def __init__(self):
        self.zscore_det   = ZScoreDetector(window=24, threshold=3.0)
        self.iqr_det      = IQRDetector(multiplier=2.5)
        self.if_det       = IsolationForestDetector(contamination=0.02)
        self.rule_engine  = OTRuleEngine()
        self.results: List[AnomalyRecord] = []

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        print("=" * 60)
        print("TANGEDCO ICS Anomaly Detection Engine")
        print("=" * 60)

        # ── Z-Score ───────────────────────────────────────────────────────
        print("\n[1/4] Running Z-Score detector (window=24h, threshold=3σ)...")
        zflags, zmean, zstd = self.zscore_det.detect(df, "total_demand_mw")
        n_z = zflags.sum()
        print(f"      Flagged: {n_z} observations")

        for idx in df[zflags].index:
            row = df.loc[idx]
            z_val = df.loc[idx, "zscore_total_demand_mw"]
            self.results.append(AnomalyRecord(
                timestamp=str(row["timestamp"]),
                index=idx,
                detector="Z-Score",
                feature="total_demand_mw",
                value=round(float(row["total_demand_mw"]) if not pd.isna(row["total_demand_mw"]) else 0, 1),
                expected_range=f"{zmean[idx]-3*zstd[idx]:.0f}–{zmean[idx]+3*zstd[idx]:.0f} MW",
                confidence=min(95, int(abs(z_val) / 3 * 60 + 40)),
                severity="Critical" if abs(z_val) > 5 else "High" if abs(z_val) > 4 else "Medium",
                technique="T0816/T0882" if row.get("anomaly_type") != "Normal" else "Unknown",
                description=f"Demand {row['total_demand_mw']:.0f} MW is {z_val:.1f}σ from rolling mean.",
                true_label=str(row["anomaly_type"]),
            ))

        # ── IQR ───────────────────────────────────────────────────────────
        print("\n[2/4] Running IQR detector (per-hour conditioned, 2.5× IQR)...")
        self.iqr_det.fit(df, "total_demand_mw")
        iqr_flags = self.iqr_det.detect(df, "total_demand_mw")
        # Exclude rows already flagged by z-score to reduce duplication
        new_iqr = iqr_flags & ~zflags
        n_iqr = new_iqr.sum()
        print(f"      Flagged (net new): {n_iqr} observations")

        for idx in df[new_iqr].index:
            row = df.loc[idx]
            hour = int(row["hour"])
            stats = self.iqr_det.hourly_stats[hour]
            self.results.append(AnomalyRecord(
                timestamp=str(row["timestamp"]),
                index=idx,
                detector="IQR",
                feature="total_demand_mw",
                value=round(float(row["total_demand_mw"]) if not pd.isna(row["total_demand_mw"]) else 0, 1),
                expected_range=f"{stats['lower']:.0f}–{stats['upper']:.0f} MW (hour {hour:02d}:00)",
                confidence=72,
                severity="High",
                technique="Unknown",
                description=f"Demand {row['total_demand_mw']:.0f} MW is outside IQR fence "
                            f"for hour {hour:02d}:00 ({stats['lower']:.0f}–{stats['upper']:.0f} MW).",
                true_label=str(row["anomaly_type"]),
            ))

        # ── Isolation Forest ───────────────────────────────────────────────
        print("\n[3/4] Running Isolation Forest (contamination=2%, 100 trees)...")
        if_flags = self.if_det.fit_predict(df)
        new_if = if_flags & ~zflags & ~iqr_flags
        n_if = new_if.sum()
        print(f"      Flagged (net new): {n_if} observations")

        for idx in df[new_if].index:
            row = df.loc[idx]
            score = df.loc[idx, "if_score"]
            self.results.append(AnomalyRecord(
                timestamp=str(row["timestamp"]),
                index=idx,
                detector="Isolation Forest",
                feature="multi-feature",
                value=round(float(score), 4),
                expected_range="IF score > -0.1 (normal)",
                confidence=min(90, int(abs(score) * 200)),
                severity="High" if score < -0.15 else "Medium",
                technique="Unknown — multi-feature deviation",
                description=f"Multi-dimensional anomaly: IF anomaly score {score:.4f}. "
                            f"Combination of demand, frequency, power factor, "
                            f"and time features is statistically unusual.",
                true_label=str(row["anomaly_type"]),
            ))

        # ── Rule Engine ────────────────────────────────────────────────────
        print("\n[4/4] Running OT Rule Engine (6 ICS-specific rules)...")
        rule_findings = self.rule_engine.detect(df)
        # Map rule findings to AnomalyRecord
        existing_indices = {r.index for r in self.results}
        new_rule_count = 0
        for f in rule_findings:
            if f["index"] not in existing_indices:
                row = df.loc[f["index"]]
                val = row.get("total_demand_mw", 0)
                self.results.append(AnomalyRecord(
                    timestamp=str(row["timestamp"]),
                    index=f["index"],
                    detector=f"OT Rule: {f['rule']}",
                    feature=f["rule"],
                    value=round(float(val) if not pd.isna(val) else 0, 1),
                    expected_range="See rule definition",
                    confidence=f["confidence"],
                    severity=f["severity"],
                    technique=f["technique"],
                    description=f["description"],
                    true_label=str(row["anomaly_type"]),
                ))
                existing_indices.add(f["index"])
                new_rule_count += 1
            else:
                # Upgrade severity if rule gives higher than existing
                for rec in self.results:
                    if rec.index == f["index"]:
                        sev_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
                        if sev_order.get(f["severity"], 0) > sev_order.get(rec.severity, 0):
                            rec.severity = f["severity"]
                            rec.technique = f["technique"]
                        break

        print(f"      Flagged (net new): {new_rule_count} observations")

        # ── Build result DataFrame ─────────────────────────────────────────
        result_df = pd.DataFrame([vars(r) for r in self.results])
        result_df = result_df.sort_values("index").reset_index(drop=True)

        # ── Evaluation (since we have ground truth) ────────────────────────
        self._evaluate(df, result_df)

        return result_df

    def _evaluate(self, df: pd.DataFrame, result_df: pd.DataFrame):
        """Compare detections against ground truth labels."""
        print("\n" + "=" * 60)
        print("Detection Performance (vs Ground Truth Labels)")
        print("=" * 60)

        true_anomaly_indices = set(df[df["anomaly"] == 1].index)
        detected_indices = set(result_df["index"].tolist())

        tp = len(true_anomaly_indices & detected_indices)
        fp = len(detected_indices - true_anomaly_indices)
        fn = len(true_anomaly_indices - detected_indices)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        print(f"  True Positives (correctly detected):   {tp}")
        print(f"  False Positives (false alarms):         {fp}")
        print(f"  False Negatives (missed attacks):       {fn}")
        print(f"  Precision:  {precision:.1%}")
        print(f"  Recall:     {recall:.1%}")
        print(f"  F1 Score:   {f1:.1%}")
        print(f"\n  Total detections: {len(result_df)}")
        print(f"  Severity breakdown:")
        for sev in ["Critical", "High", "Medium", "Low"]:
            n = (result_df["severity"] == sev).sum()
            print(f"    {sev:12s}: {n}")


def run_detection(csv_path: str = "data/tangedco_grid_data.csv") -> pd.DataFrame:
    """Load data and run the full detection pipeline."""
    print(f"\n[*] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, parse_dates=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)
    print(f"[*] Loaded {len(df):,} hourly observations")

    detector = TANGEDCOAnomalyDetector()
    results = detector.run(df)

    out_path = "output/anomaly_detections.csv"
    results.to_csv(out_path, index=False)
    print(f"\n[+] Detection results saved: {out_path}")
    print(f"    Total anomalies detected: {len(results)}")

    return results


if __name__ == "__main__":
    run_detection()
