# Advanced Malicious & Vulnerable Driver Detection (LOLDrivers & BYOVD)

**Author**: Ala Dabat  
**Platform**: Microsoft Defender for Endpoint (MDE) / Microsoft Sentinel  
**Version**: 2025‑11  
**MITRE ATT&CK**:  
- **TA0005 – Defense Evasion**  
- **TA0004 – Privilege Escalation**  
- **T1068 – Exploitation for Privilege Escalation**  
- **T1548 – Abuse Elevation Control Mechanism**  
- **T1562 – Impair Defenses**  

---

## Objective

Detect malicious or vulnerable kernel‑mode drivers being **loaded or staged on endpoints**, including:
- BYOVD (Bring‑Your‑Own‑Vulnerable‑Driver) techniques  
- Unsigned or abused legitimate drivers  
- Delayed activation / dormant driver implants  
- Drivers loaded from non‑system paths or via suspicious processes  

This rule is designed for **SOC‑level threat hunting and detection engineering validation**.

---

##  Context

Attackers increasingly deploy **legitimate but exploitable drivers** to disable EDRs, patch the kernel, or gain SYSTEM‑level access.  
The rule correlates **driver load events**, **file creation timestamps**, and **external threat feeds** (e.g. MISP) to identify:

- Immediate driver loads after drop (<5 minutes) — signs of active exploitation  
-  Dormant drivers loaded after >7 days — stealth implants or delayed activation  
-  Unsigned or anomalous signatures  
- Suspicious load locations (`C:\Users\Public\`, `\AppData\`, etc.)

---

## Detection Logic Overview

1. **File Creation Correlation**  
   - Monitors `.sys` driver files created/moved in non‑system directories.  
   - Compares creation vs. first load time for **delay analysis**.

2. **Driver Load Events**  
   - Queries `DeviceEvents` for `DriverLoad` and `LoadedKernelModule` actions.  
   - Extracts metadata: file name, signer, signature validity, load path.

3. **Feed Enrichment** *(Optional)*  
   - Joins external driver hash feed (MISP/CSV or custom watchlist).  
   - Categorizes as `MALICIOUS`, `VULNERABLE DRIVER`, or `UNKNOWN`.

4. **Heuristic Scoring**  
   - Path, signature, and delay are evaluated for anomaly weighting.  
   - Outputs `PathSuspicious`, `SignatureAnomaly`, and `LoadDelayCategory`.

5. **Hunting Directives**  
   - Inline guidance for analysts: confirm driver, check VT link, pivot across estate.

---

##  Scoring & Heuristic Breakdown

| Heuristic | Condition | Typical Indicator | Weight |
|------------|------------|------------------|--------|
| **Known malicious driver** | Feed `Category == "malicious"` | IOC match | 🔥 High |
| **Vulnerable driver** | Feed `Category == "vulnerable driver"` | Exploitable vendor driver | ⚠️ Medium |
| **Unsigned / Unknown signer** | `SignatureStatus != "Valid"` | Tampered or fake driver | ⚠️ Medium |
| **Non‑system path** | `C:\Users\`, `\AppData\`, `\Temp\`, etc. | Lateral drop or user persistence | ⚠️ Medium |
| **Immediate load (<5m)** | Drop → load within minutes | Active exploit / EDR evasion | ⚠️ Medium |
| **Dormant (>7d)** | Drop → load after >7 days | Stealth or timed activation | ⚠️ Medium |

---

##  Example Outputs (Simulated)

| FileName | Category | PathSuspicious | Delay | Signature | HitClass |
|-----------|-----------|----------------|--------|------------|-----------|
| `aswArPot.sys` | Malicious | ✅ | Normal | ❌ Unsigned | MALICIOUS |
| `dbutil_2_3.sys` | Vulnerable | ✅ | 🕒 >7d | ✔ Valid | VULNERABLE |
| `evilkernel.sys` | Malicious | ✅ | Normal | ❌ Unsigned | MALICIOUS |
| `hookdrv.sys` | Unknown | ✅ | Normal | ✔ Valid | UNKNOWN |

Each result includes a pre‑built VirusTotal link and analyst directives such as:

> *“Confirm driver evilkernel.sys on Endpoint‑661. Category=MALICIOUS.  
> Delay Category=Normal (3 mins). Enrich via VT, pivot hash across estate, check for EDR tampering.”*

---

##  Data Sources

| Table | Description |
|--------|-------------|
| `DeviceEvents` | Detects kernel driver load events |
| `DeviceFileEvents` | Captures file creation and movement (.sys files) |
| `ThreatIntelligenceIndicator` / `externaldata()` | Optional enrichment with MISP, CSV, or Watchlist feed |

---

##  MITRE Alignment

| Tactic | Technique | Description |
|--------|------------|-------------|
| **Defense Evasion (TA0005)** | T1562 | Disabling AV/EDR with kernel drivers |
| **Privilege Escalation (TA0004)** | T1068 | Exploiting vulnerable drivers |
|  | T1548 | Abuse of Elevation Control Mechanism |

---

## Analyst Workflow (HuntingDirectives)

1.  Confirm driver legitimacy via vendor or signing certificate.  
2.  Review `InitiatingProcessFileName` and command line (sc.exe, fltmc, etc.).  
3.  Investigate driver creation path and timeline correlation.  
4.  If `Delayed (>7d)` → look for prior persistence artifacts.  
5.  Open `VT_File` link for hash reputation check.  
6.  Pivot hash across your environment for propagation.  
7.  Examine memory, LSASS, AMSI or kernel tampering post‑load.  
8.  Contain and remediate — isolate host, remove driver, apply WDAC/HVCI block rules.  

---

##  Operational Notes

- `externaldata()` works best in **Sentinel**; replace with a **Watchlist** for production.  
- The rule **correlates delayed activation**, catching stealth BYOVD implants missed by IOC-only detection.  
- `SignatureAnomaly` and `PathSuspicious` can generate **contextual alerts** even without feed hits.  
- Extend with `OrgPrevalence` scoring to suppress benign vendor drivers.

---

## 🧾 Example Query Headline (Copy‑Ready)

```kql
// Advanced LOLDriver Detection — Ala Dabat
// Detects malicious or vulnerable driver loads and delayed activation
// MITRE: TA0005, TA0004 | T1068, T1548, T1562
