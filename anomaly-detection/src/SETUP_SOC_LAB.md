# TANGEDCO SOC Lab — Full Setup Guide

**Stack:** Wazuh 4.7 + ELK 7.17 + TheHive 5.2 + MISP + Cortex  
**Time to deploy:** ~30–45 minutes  
**RAM required:** 16GB minimum (12GB allocated to Docker)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     TANGEDCO SOC LAB                             │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Python Tool  │───▶│ Wazuh SIEM   │───▶│ TheHive          │   │
│  │ (anomaly     │    │ (detection   │    │ (incident mgmt   │   │
│  │  detections) │    │  + rules)    │    │  + triage)       │   │
│  └──────────────┘    └──────┬───────┘    └────────┬─────────┘   │
│                             │                     │             │
│                    ┌────────▼───────┐    ┌────────▼─────────┐   │
│                    │ Elasticsearch  │    │ MISP              │   │
│                    │ + Kibana       │    │ (threat intel     │   │
│                    │ (dashboards)   │    │  + IOC feeds)     │   │
│                    └────────────────┘    └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘

Ports:
  Wazuh Dashboard : https://localhost:443
  Kibana          : http://localhost:5601
  TheHive         : http://localhost:9000
  MISP            : http://localhost:8080
  Cortex          : http://localhost:9001
```

---

## Step 1 — Prerequisites

### Install Docker Desktop
```bash
# macOS
brew install --cask docker

# Ubuntu/Debian
sudo apt update && sudo apt install docker.io docker-compose -y
sudo systemctl enable --now docker
sudo usermod -aG docker $USER  # then log out and back in
```

### Allocate RAM to Docker
- Open Docker Desktop → Settings → Resources
- Set Memory to **12GB** (leave 4GB for your OS)
- Set CPUs to at least **4**
- Apply and restart Docker

### Clone this repo
```bash
git clone https://github.com/YOUR_USERNAME/tangedco-soc-lab.git
cd tangedco-soc-lab
```

---

## Step 2 — Deploy the Stack

```bash
# Set required permissions for Wazuh
mkdir -p wazuh/rules wazuh/decoders kibana thehive/config

# Start everything (detached mode)
docker-compose up -d

# Watch startup progress
docker-compose logs -f

# Check all containers are healthy (~3-5 minutes)
docker-compose ps
```

Expected output once healthy:
```
NAME                STATUS          PORTS
wazuh.manager       running         0.0.0.0:514->514/udp, 0.0.0.0:55000->55000/tcp
wazuh.indexer       running         0.0.0.0:9200->9200/tcp
wazuh.dashboard     running         0.0.0.0:443->5601/tcp
elasticsearch       running (healthy) 0.0.0.0:9201->9200/tcp
kibana              running         0.0.0.0:5601->5601/tcp
thehive             running (healthy) 0.0.0.0:9000->9000/tcp
misp                running         0.0.0.0:8080->80/tcp
cortex              running         0.0.0.0:9001->9001/tcp
```

---

## Step 3 — Install Custom TANGEDCO Rules

```bash
# Copy rules into the running Wazuh container
docker cp wazuh/rules/tangedco_ics_rules.xml \
  $(docker-compose ps -q wazuh.manager):/var/ossec/etc/rules/

docker cp wazuh/decoders/tangedco_decoder.xml \
  $(docker-compose ps -q wazuh.manager):/var/ossec/etc/decoders/

# Restart Wazuh manager to load rules
docker-compose exec wazuh.manager /var/ossec/bin/ossec-control restart

# Verify rules loaded (should see rule IDs 100100-100171)
docker-compose exec wazuh.manager \
  /var/ossec/bin/ossec-logtest -t < /dev/null 2>&1 | grep 10010
```

**Test a rule manually:**
```bash
# Test the SCADA data dropout rule
echo '{"source":"tangedco_anomaly","timestamp":"2024-01-15T03:00:00","anomaly_id":"TNG-01051","anomaly_type":"Loss_of_View_SCADA_Wiper","severity":"Critical","detector":"OT Rule: LOSS_OF_VIEW_ZERO_READING","feature":"scada_quality","value":0,"confidence":95,"technique":"T0813","src_zone":"Z-3_Operations","description":"SCADA data quality flag = 0"}' \
  | docker-compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest
```

---

## Step 4 — Generate and Feed Anomaly Detections

```bash
# Step 4a: Generate the anomaly dataset (if not done already)
cd ../anomaly-detection
python main.py
cd ../tangedco-soc-lab

# Step 4b: Test feed locally (no Wazuh needed)
python scripts/feed_alerts.py \
  --historical \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --local

# Step 4c: Feed into Wazuh (must be running)
python scripts/feed_alerts.py \
  --historical \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --wazuh-host localhost \
  --wazuh-port 514 \
  --delay 0.1

# Step 4d: Live feed mode (continuously watches for new detections)
python scripts/feed_alerts.py \
  --live \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --wazuh-host localhost
```

Watch alerts appear in Wazuh Dashboard at `https://localhost:443`.  
Login: `admin` / `SecretPassword`

---

## Step 5 — Configure TheHive

### Get API key
1. Open `http://localhost:9000`
2. Login: `admin@thehive.local` / `secret`
3. Go to: Settings → API Keys → Create API Key
4. Copy the key

### Set environment variable
```bash
export THEHIVE_API_KEY="your_api_key_here"
```

### Auto-create cases from anomaly detections
```bash
# Dry run first — see what cases would be created
python scripts/thehive_cases.py \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --severity Critical High \
  --dry-run

# Create real cases in TheHive
python scripts/thehive_cases.py \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --severity Critical High \
  --limit 20
```

Each case is auto-populated with:
- Severity, TLP, PAP classifications
- MITRE ATT&CK technique tags
- Pre-structured investigation tasks (8 tasks for ransomware, 5 for SCADA breach, etc.)
- SCADA observables

---

## Step 6 — Configure MISP

### Get API key
1. Open `http://localhost:8080`
2. Login: `admin@admin.test` / `admin`
3. Go to: Administration → Auth Keys → Add Auth Key
4. Copy the key

```bash
export MISP_KEY="your_misp_key_here"
```

### Setup ICS threat intel feeds and profiles
```bash
# Dry run to see what would be configured
python scripts/misp_feeds.py --setup --dry-run
python scripts/misp_feeds.py --import-iocs --dry-run

# Live setup
python scripts/misp_feeds.py --setup
python scripts/misp_feeds.py --import-iocs \
  --csv ../anomaly-detection/output/anomaly_detections.csv

# Generate threat intel report (no MISP needed)
python scripts/misp_feeds.py --report
```

---

## Step 7 — Kibana Dashboard

```bash
# Import TANGEDCO dashboard
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Authorization: Basic $(echo -n 'elastic:SecretPassword' | base64)" \
  --form file=@kibana/tangedco_dashboard.ndjson
```

Open `http://localhost:5601` → Dashboards → TANGEDCO ICS Security

---

## Step 8 — Full Demo Flow (for interviews)

This is the sequence to run when demonstrating the platform:

```bash
# Terminal 1: Start live anomaly feed
python scripts/feed_alerts.py --live \
  --csv ../anomaly-detection/output/anomaly_detections.csv \
  --wazuh-host localhost

# Terminal 2: Watch Wazuh alerts in real-time
docker-compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log \
  | grep -E "tangedco|CRITICAL|HIGH"

# Terminal 3: Auto-create TheHive cases as alerts come in
watch -n 10 "python scripts/thehive_cases.py \
  --severity Critical \
  --limit 5 \
  2>/dev/null | tail -5"
```

Then in your browser, show:
1. **Wazuh Dashboard** — alerts coming in live, rule IDs firing
2. **Kibana** — time-series charts of anomaly types over the year
3. **TheHive** — pre-structured cases with investigation tasks
4. **MISP** — threat actor profiles (Sandworm, Volt Typhoon)
5. **Threat intel report** — `output/threat_intel_report.md`

---

## What to say in interviews

### "Walk me through this project"
> "I built a full SOC lab for TANGEDCO, India's Tamil Nadu state power utility. 
> The stack is Wazuh SIEM with custom ICS detection rules, ELK for visualisation, 
> TheHive for incident management, and MISP for threat intelligence.
> 
> I wrote the detection rules myself — they're mapped to MITRE ATT&CK for ICS 
> and cover 5 real attack scenarios: ransomware with SCADA pivot, nation-state 
> Industroyer2-class attacks, sensor spoofing, off-hours credential abuse, and 
> SCADA wiper malware. The rules also include composite correlations — for example, 
> Rule 100170 fires when it sees off-hours access + lateral movement + anomalous 
> SCADA commands within a 2-hour window, which is the Industroyer2 TTP pattern.
> 
> The Python tool generates a year of synthetic grid data, injects 5 attack scenarios, 
> runs 4 detection methods — statistical (Z-Score, IQR), ML (Isolation Forest), 
> and rule-based — then feeds the results into Wazuh. TheHive automatically 
> creates structured cases with pre-populated investigation tasks, and MISP holds 
> threat actor profiles for Sandworm, Volt Typhoon, and TEMP.Veles."

### "Why ICS/OT security?"
> "Power utilities are the highest-impact target in the cyber threat landscape — 
> a successful SCADA attack affects millions of people directly. India's power sector 
> has documented intrusions from Chinese APTs targeting load dispatch centres. 
> The gap between IT and OT security maturity in Indian utilities is massive, 
> and that's exactly where a GRC+SOC hybrid analyst adds the most value."

### "What's your recall vs precision tradeoff?"
> "The Python anomaly detector achieves 90% recall with ~4.5% precision. 
> In ICS security that's the right trade — you want to miss zero real attacks 
> even at the cost of false alarms. In Wazuh, the composite correlation rules 
> (Rule 100170, 100171) are designed to filter the noise — they only fire when 
> multiple weak signals appear together, which significantly increases precision 
> for the cases that actually get escalated."

---

## Troubleshooting

### Not enough RAM
```bash
# Check Docker memory allocation
docker stats --no-stream

# Reduce by disabling MISP temporarily
docker-compose stop misp misp-db
```

### Wazuh rules not loading
```bash
docker-compose exec wazuh.manager /var/ossec/bin/ossec-logtest -t
# Look for: "Rule file 'tangedco_ics_rules.xml' loaded"
```

### TheHive won't start
```bash
# It needs Elasticsearch to be healthy first
docker-compose logs elasticsearch | tail -20
# Wait for: "started" message then restart TheHive
docker-compose restart thehive
```

### Reset everything (clean start)
```bash
docker-compose down -v   # removes all volumes too
docker-compose up -d
```

---

## GitHub Portfolio Tips

1. Add screenshots to `docs/screenshots/` — Wazuh alert firing, TheHive case with tasks, MISP actor profile
2. Record a 2-minute Loom demo video — embed it in README
3. Add these to your resume bullet point:
   ```
   • Built full SOC lab (Wazuh + ELK + TheHive + MISP) for TANGEDCO ICS environment; 
     authored 20 custom Wazuh detection rules mapped to MITRE ATT&CK for ICS, 
     achieving 90% recall on 5 injected attack scenarios including Industroyer2-class 
     and TRITON-class threats
   ```
4. Pin this repo on your GitHub profile

---

*TANGEDCO SOC Lab — Cybersecurity Portfolio Project*  
*ISO/IEC 27001:2022 · IEC 62443 · MITRE ATT&CK for ICS · Wazuh 4.7 · TheHive 5.2 · MISP*
