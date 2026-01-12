# TANGEDCO OT/IT Cybersecurity Portfolio Project

**Tamil Nadu Generation and Distribution Corporation Limited**  
A two-part cybersecurity portfolio project covering ICS/OT risk management and anomaly detection for a real-world critical infrastructure operator.

---

## Project Structure

```
tangedco-ot-security/
│
├── dashboard/
│   └── index.html              ← Interactive risk dashboard (open in browser)
│
├── anomaly-detection/
│   ├── main.py                 ← Entry point — run this
│   ├── requirements.txt
│   ├── data/
│   │   └── tangedco_grid_data.csv   ← Synthetic/Kaggle dataset goes here
│   ├── src/
│   │   ├── generate_data.py    ← Synthetic dataset generator
│   │   ├── anomaly_detector.py ← Core detection engine (4 methods)
│   │   └── visualize.py        ← Chart generation
│   └── output/
│       ├── anomaly_detections.csv
│       ├── summary_report.txt
│       └── *.png               ← Generated charts
│
└── README.md
```

---

## Part 1 — Interactive Risk Dashboard

**File:** `dashboard/index.html`  
**Deploy:** Upload to GitHub Pages (Settings → Pages → main branch /root). Zero config.

A fully client-side dashboard covering:

| Tab | What it shows |
|-----|--------------|
| Overview | Risk heat map, stat cards, ISO 27001 gap summary |
| Risk Register | All 16 risks — searchable, filterable, sortable |
| IEC 62443 Zones | 6-zone Purdue Model architecture with current vs target SL |
| Attack Scenarios | 3 MITRE ATT&CK for ICS attack chains with IOCs |
| SIEM Use Cases | 10 detection rules with logic, expandable |

**Tech:** Vanilla HTML/CSS/JS — no frameworks, no dependencies, single file.

---

## Part 2 — ICS Anomaly Detection Tool

### What it does

Detects cyberattack-induced anomalies in electricity grid time-series data using a **layered detection approach** (defence in depth applied to data):

```
Raw Grid Data
     │
     ├── [1] Z-Score          Rolling 24h window, 3σ threshold
     ├── [2] IQR              Per-hour conditioned fences (captures daily pattern)
     ├── [3] Isolation Forest Multi-feature ML (demand + frequency + power factor + time)
     └── [4] OT Rule Engine   6 ICS-specific rules mapped to MITRE ATT&CK for ICS
                                    │
                                    ▼
                         Unified Anomaly Report
                   (severity, technique, confidence, description)
```

### 5 Attack Scenarios Simulated

| Scenario | ATT&CK ICS Technique | Effect in Data |
|----------|---------------------|----------------|
| Ransomware + IT/OT Pivot | T0816, T0882 | SCADA data blackout → erratic demand post-recovery |
| Demand Manipulation (Industroyer-class) | T0855 | Sudden demand drop + frequency spike |
| Sensor Spoofing / MITM | T0856, T0830 | Readings freeze at one value — physically impossible |
| Off-Hours Privileged Access | T0859 | Precise demand change at 03:00 — not natural variation |
| Loss of View (SCADA Wiper) | T0813 | All readings → 0 while grid is still running |

### Detection Performance

```
True Positives (correctly detected):   36 / 40 attack hours
False Negatives (missed):               4 / 40 attack hours
Recall:     90%
Precision:  ~4.5%  (high false alarm rate — see note below)
```

> **On the precision/recall tradeoff:** In ICS security, **high recall is the correct design choice**. Missing a real attack (false negative) has catastrophic consequences — grid outages, safety incidents. Investigating a false alarm costs analyst time. This tool is designed to flag anything suspicious and let a human OT analyst triage. In production, false positive rate would be reduced by tuning thresholds against real baseline data and adding protocol-level telemetry (Claroty/Dragos NDR feeds).

### Installation & Usage

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/tangedco-ot-security.git
cd tangedco-ot-security/anomaly-detection

# 2. Install dependencies
pip install -r requirements.txt

# 3a. Run with synthetic data (auto-generated)
python main.py

# 3b. Run with real Kaggle data
# Download from: kaggle.com/datasets/pythonafroz/tamilnadu-electricity-board-hourly-readings
python main.py --csv path/to/kaggle_data.csv

# 4. Skip chart generation (faster)
python main.py --no-plots
```

### Output Files

| File | Description |
|------|-------------|
| `output/anomaly_detections.csv` | All detected anomalies with ATT&CK mappings, confidence, severity |
| `output/summary_report.txt` | Human-readable findings report |
| `output/plot1_full_timeline.png` | Full-year demand with annotated attack periods |
| `output/plot2_attack_zooms.png` | Zoomed windows for each of the 5 attack scenarios |
| `output/plot3_detector_comparison.png` | Method comparison + severity distribution |
| `output/plot4_attack_matrix.png` | ATT&CK ICS technique detection coverage matrix |

---

## Frameworks & Standards Referenced

| Standard | Application |
|----------|------------|
| **ISO/IEC 27001:2022** | Risk assessment structure, Annex A control mapping |
| **IEC 62443** | OT zone & conduit model, Security Level definitions |
| **MITRE ATT&CK for ICS** | Attack technique mapping for all anomaly types |
| **NIST SP 800-82 Rev. 3** | OT security guidance |
| **CEA Cyber Security Guidelines (2023)** | India power sector compliance context |

---

## Skills Demonstrated

- **OT/ICS Security** — SCADA threat modelling, IEC 62443 zone architecture, ICS protocol vulnerabilities (Modbus, DNP3, IEC 104)
- **Anomaly Detection** — Statistical methods (Z-score, IQR), ML (Isolation Forest), rule-based detection engineering
- **GRC / Risk Management** — ISO 27001:2022 risk register, gap analysis, semi-quantitative scoring
- **SIEM Engineering** — Detection use case design, ATT&CK technique mapping, SOAR integration concepts
- **Python** — pandas, scikit-learn, matplotlib, modular project structure
- **Frontend** — Vanilla JS dashboard, single-file deployable to GitHub Pages

---

## Data Sources

- **Synthetic data:** Generated by `src/generate_data.py` — mimics Tamil Nadu Electricity Board hourly readings format
- **Real data (optional):** [Kaggle — Tamil Nadu Electricity Board Hourly Readings](https://www.kaggle.com/datasets/pythonafroz/tamilnadu-electricity-board-hourly-readings)
- **Threat intelligence:** India power sector intrusions documented by Recorded Future (2021–2022), CEA Cyber Security Guidelines

---

*Built as a cybersecurity portfolio project demonstrating OT/ICS security, ISO 27001:2022 risk management, and data-driven anomaly detection for critical infrastructure.*
