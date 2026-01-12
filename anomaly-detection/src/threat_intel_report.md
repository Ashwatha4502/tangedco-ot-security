# TANGEDCO Threat Intelligence Report
**Generated:** 2026-05-01 18:30 UTC
**Classification:** TLP:AMBER — TANGEDCO SOC Internal

---

## Executive Summary

TANGEDCO, as Tamil Nadu's primary electricity utility, faces active targeting from nation-state threat actors with demonstrated capability to disrupt power grid SCADA systems. The most significant threat actors are assessed as **Sandworm Team** (destructive capability via Industroyer2) and **Volt Typhoon** (pre-positioning / espionage with documented India presence).

## Threat Actor Profiles

### Sandworm Team
**Relevance:** `HIGH`  
**Origin:** RU  
**Motivation:** National espionage, sabotage of critical infrastructure

**Known Tools:** BlackEnergy, Industroyer/CRASHOVERRIDE, Industroyer2, Cyclops Blink, NotPetya

**ATT&CK ICS Techniques:** T0855, T0813, T0816, T0882

**Relevance to TANGEDCO:** HIGH — Sandworm directly targets power grid SCADA systems. Industroyer2 uses IEC 104 protocol — same as TANGEDCO EMS.

**Recent Activity:** 2022: Industroyer2 deployed against Ukrainian power infrastructure. India power sector intrusions documented by Recorded Future (2021-2022).

---

### Volt Typhoon
**Relevance:** `HIGH`  
**Origin:** CN  
**Motivation:** Pre-positioning in critical infrastructure for potential disruption

**Known Tools:** Living-off-the-land (LOTL), SOHO router exploitation

**ATT&CK ICS Techniques:** T0859, T0866, T0843

**Relevance to TANGEDCO:** HIGH — Documented intrusions into Indian power grid load dispatch centres (2020-2022, Recorded Future). Uses valid accounts (T0859) — relevant to TANGEDCO PAM gap.

**Recent Activity:** 2023: CISA advisory on Volt Typhoon targeting US critical infrastructure. Indian CERT-In has issued warnings for Indian power utilities.

---

### Dragonfly / Energetic Bear
**Relevance:** `MEDIUM`  
**Origin:** RU  
**Motivation:** Industrial espionage, critical infrastructure reconnaissance

**Known Tools:** Havex RAT, Karagany, Phishery

**ATT&CK ICS Techniques:** T0886, T0859, T0817

**Relevance to TANGEDCO:** MEDIUM — Primarily targets western utilities but techniques (spear-phishing engineers, SCADA reconnaissance) apply to TANGEDCO.

**Recent Activity:** 2020: US DOJ indictments for attacks on energy grid operators.

---

### TEMP.Veles / TRITON Group
**Relevance:** `MEDIUM-HIGH`  
**Origin:** RU  
**Motivation:** Safety system compromise — physical damage potential

**Known Tools:** TRITON/TRISIS malware, CrashOverride

**ATT&CK ICS Techniques:** T0856, T0830, T0839

**Relevance to TANGEDCO:** MEDIUM-HIGH — TANGEDCO thermal plants have Safety Instrumented Systems. TRITON targets Schneider Electric Triconex SIS — widely deployed in India.

**Recent Activity:** 2017: TRITON deployed at Saudi Aramco. Expanding target set beyond Middle East.

---

## Detection Recommendations

| Actor | Primary TTP | Detection Rule | SIEM Use Case |
|-------|-------------|----------------|---------------|
| Sandworm | T0855 IEC 104 commands | Rule 100110-100112 | UC-05 |
| Sandworm | T0813 SCADA wiper | Rule 100101, 100171 | UC-04 |
| Volt Typhoon | T0859 Valid accounts | Rule 100131-100133 | UC-07, UC-10 |
| Volt Typhoon | T0866 VPN exploitation | Rule 100140 | UC-10 |
| TEMP.Veles | T0856 Sensor spoofing | Rule 100102-100103 | UC-05 |
| Dragonfly | T0886 Remote services | Rule 100123 | UC-02 |

## References

- CISA ICS Advisory: AA22-110A (Sandworm / Industroyer2)
- CISA Advisory: AA23-144A (Volt Typhoon)
- Recorded Future: RedEcho — Chinese targeting of Indian power grid (2021)
- CEA Cyber Security Guidelines for Power Sector (2023)
- CERT-In: Advisory CIAD-2022-0009 (ICS threat landscape India)