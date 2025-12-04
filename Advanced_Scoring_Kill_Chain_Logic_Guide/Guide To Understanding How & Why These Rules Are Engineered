# ADVANCED HUNTING & DETECTION ENGINEERING ARCHITECTURE  
**Author: Ala Dabat**  
**Purpose:** Explain the architecture, scoring logic, kill-chain alignment, and engineering methodology behind advanced hunts in this repository.  
**Scope:**  
- DLL Sideloading (Behaviour + Rare Path + Chain Analysis)  
- OAuth Abuse (Identity Abuse + Allow/Block Modelling)  
- NTDS/LSASS Dumping (Privilege Escalation → Credential Theft → Lateral Movement)  
- Jittered C2 (Network Behavioural Analytics)  

Each section includes:  
- Why the hunt exists (Analytic Purpose)  
- Attack anatomy (How adversaries execute the technique)  
- MITRE ATT&CK Mapping  
- Core logic (partial KQL showing mechanisms)  
- Why JOINs / scoring are needed  
- Analyst pivot tables  
- Recommended responses  

---

# 0. DETECTION ENGINEERING ARCHITECTURE  
This document explains **how advanced hunts in this repository function as a system**.

### Core Principles  
| Component | Role |
|----------|------|
| **Behaviour-first logic** | No dependency on signatures, focuses on anomalous behaviour. |
| **Scoring Engine** | Assigns weighted signals → Low/Medium/High/Critical. |
| **Join Correlation** | Combines processes, network, registry, identity into unified events. |
| **Rare-Path / Prevalence Analytics** | Determines whether behaviour is normal for the organisation. |
| **Kill Chain Alignment** | Every rule maps to: Initial → Execution → PrivEsc → Cred Theft → Lateral Move → Impact. |

### Why Partial Rules Are Used Here  
This guide explains *how* the rules work, not the full production logic.  
Full rules remain in the repository — this guide teaches analysts:

- **What the rule detects**  
- **Why it detects it this way**  
- **What signals make it high-fidelity**  
- **How to pivot from the output**  

---

# 1. DLL SIDELOADING — ADVANCED BEHAVIOUR ENGINEERING  
### Why This Hunt Matters  
DLL sideloading remains one of the **top 3 evasion techniques** used by APTs (2023–2025).  
Microsoft Defender often misses **initial sideloading stages** when:

- A legit EXE loads attacker DLL  
- DLL lives in user-writable paths  
- Command line is benign  
- No malware hash is known yet

This hunt explains **rare path scoring**, **host-process correlation**, and **join mechanics**.

---

## 1.1 MITRE Mapping

| Tactic | Technique |
|--------|-----------|
| Execution | **T1574.002 – DLL Search Order Hijacking** |
| Defense Evasion | **T1036 – Masquerading** |
| Persistence | **T1547.001 – Registry Run Keys** (if dropped DLL persists) |

---

## 1.2 Partial Rule Logic (Hybrid View)

```kql
// 1) Identify DLL loads from suspicious paths
DeviceImageLoadEvents
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\programdata\\|\\temp\\"
| where FileName endswith ".dll"
```

### Why JOIN Is Needed  
DLL loads alone are noise. We JOIN to parent process:

```kql
| join kind=leftouter (
    DeviceProcessEvents
    | project DeviceId, ProcessId, HostProcess=FileName, HostCmd=ProcessCommandLine
) on DeviceId, InitiatingProcessId == ProcessId
```

Now we know **which legitimate EXE was abused**.

---

## 1.3 Scoring Engine (Explained)

| Signal | Weight |
|--------|--------|
| DLL in user-writable path | +4 |
| Rare host (OrgPrevalence == 1) | +3 |
| Unsigned DLL | +3 |
| Parent process unusual | +2 |
| Suspicious command line | +3 |

Final score → mapped to:

- **0–4 → Low**
- **5–7 → Medium**
- **8–10 → High**
- **11+ → Critical**

---

## 1.4 Analyst Pivot Table

| Pivot | Table |
|-------|-------|
| What else did the EXE do? | DeviceProcessEvents |
| Did DLL write anything? | DeviceFileEvents |
| Did DLL cause network traffic? | DeviceNetworkEvents |
| How rare is the DLL? | summarise count() by SHA256 |

---

## 1.5 Recommended Actions  

- Validate EXE signature and expected DLL load order  
- Check for persistence (Run keys, Services)  
- Inspect outbound traffic from host process  
- Compare DLL hash organisation-wide  

---

# 2. OAUTH CONSENT ABUSE — CLOUD IDENTITY ENGINEERING  
### Purpose  
Identity attacks are now the **#1 intrusion vector in 2024–2025**.  
OAuth “Consent Grant Attack” bypasses MFA entirely.

This hunt demonstrates:  
- Cloud-side correlation  
- Allowlist/denylist logic  
- Risk classification  
- Identity → App → IP → User pivots  

---

## 2.1 MITRE Mapping

| Tactic | Technique |
|--------|-----------|
| Initial Access | **T1078.004 – OAuth Token Abuse** |
| Persistence | **T1136 – Cloud Account Abuse** |
| Defense Evasion | **T1550 – Token Impersonation** |

---

## 2.2 Partial Core Logic

```kql
AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppId = tostring(TargetResources[0].id),
         AppDisplayName = tostring(TargetResources[0].displayName)
| where AppDisplayName !in (KnownSafeApps)
```

### Why No JOIN Needed Here  
AuditLogs contains *all* identity, IP, user, and resource fields.  
JOIN only appears if enriching with:

- SignInLogs (user impossible travel)
- User risk (IdentityProtectionRiskEvents)

---

## 2.3 Scoring Breakdown

| Signal | Weight |
|--------|--------|
| AppOnly = True | +5 |
| OnBehalfOfAll = True | +5 |
| Unknown publisher | +4 |
| First time seen in tenant | +3 |

Risk tiers → Low/Moderate/High/Critical.

---

## 2.4 Analyst Pivot Table

| Pivot | Table |
|--------|-------|
| Which user granted consent? | AuditLogs |
| IP reputation of initiator? | Geo info enrichment / VT |
| Any impossible travel? | SignInLogs |
| What permissions were granted? | Target.modifiedProperties |

---

# 3. NTDS / LSASS CREDENTIAL DUMPING  
The highest-impact detection in enterprise security.

This hunt teaches:  
- Cross-table JOIN logic  
- Multi-signal scoring  
- Privilege chain reasoning  

---

## 3.1 MITRE Mapping

| Tactic | Technique |
|--------|-----------|
| Credential Access | **T1003.001 – LSASS Dumping** |
| Privilege Escalation | **T1068 – Exploitation for PrivEsc** |
| Lateral Movement | **T1021 – Remote Service** |

---

## 3.2 Partial Rule Logic

### 1) Process Indicators

```kql
DeviceProcessEvents
| where FileName in ("ntdsutil.exe","rundll32.exe","procdump.exe","python.exe")
| where ProcessCommandLine has_any ("ntds", "lsass", "create full")
```

### 2) File Indicators

```kql
DeviceFileEvents
| where FileName has "ntds.dit" or FileName has "lsass.dmp"
| where ActionType == "FileCreated"
```

### 3) Network Indicators

```kql
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "secretsdump" 
      or InitiatingProcessCommandLine has "ninjacopy"
```

### 4) Correlation

```kql
ProcIndicators
| join kind=leftouter FileIndicators on DeviceId
| join kind=leftouter NetIndicators on DeviceId
```

---

## 3.3 Analyst Pivot Table

| Question | Table |
|----------|-------|
| Was LSASS accessed with SeDebugPrivilege? | DeviceProcessEvents |
| Was a dump file created? | DeviceFileEvents |
| Did attacker exfiltrate dump? | DeviceNetworkEvents |
| Which account executed the process? | DeviceProcessEvents.AccountName |

---

## 3.4 Recommended Actions

- Reset credentials of affected accounts  
- Validate no shadow copies were extracted  
- Check for persistence: scheduled tasks, WMI, services  
- Force logout across domain  

---

# 4. JITTERED C2 — BEHAVIOURAL NETWORK ANALYTICS  
Jittered beaconing evades static IOC-based blocking.  
This hunt explains periodicity analysis + behavioural scoring.

---

## 4.1 MITRE Mapping

| Tactic | Technique |
|--------|-----------|
| Command and Control | **T1071 – Application Protocols** |
| Command and Control | **T1008 – Fallback Channels** |

---

## 4.2 Partial Logic

### Extract inter-arrival timing (IAT)

```kql
DeviceNetworkEvents
| where RemotePort in (80,443)
| summarize Times=make_list(Timestamp) by DeviceId, RemoteIP
```

### Compute jitter

```kql
| extend Sorted=bag_sort(Times)
| extend Deltas=zip(list_slice(Sorted,1), list_slice(Sorted,0,-1))
```

### Score model

| Signal | Weight |
|--------|--------|
| Stable jitter window | +4 |
| Consistent packet size | +3 |
| Single remote IP | +2 |
| No parent process network history | +3 |

---

## 4.3 Analyst Pivot Table

| Question | Table |
|----------|--------|
| What parent process owns beacon? | DeviceProcessEvents |
| Is this IP new to the org? | summarise by RemoteIP |
| Does process also write files? | DeviceFileEvents |
| What child processes spawned? | DeviceProcessEvents (tree rebuild) |

---

# 5. FULL KILL-CHAIN VIEW OF ALL FOUR HUNTS  
```
Initial Access
    ↓
OAuth Abuse  → bypass MFA → create persistence
    ↓
Execution
    ↓
DLL Sideloading → load malicious DLL invisibly
    ↓
Privilege Escalation
    ↓
NTDS/LSASS Dumping → Credential extraction
    ↓
Lateral Movement
    ↓
Jittered C2 → Stealth communication & remote control
```

---

# 6. FINAL ANALYST SUMMARY TABLE

| Hunt Type | What It Detects | Engineering Concepts Demonstrated | Why It Matters |
|-----------|-----------------|-----------------------------------|----------------|
| DLL Sideloading | EXE → malicious DLL load | Rare paths, join correlation, scoring engine | High-fidelity behaviour hunting |
| OAuth Abuse | Token theft / rogue app consent | Identity analytics, allowlists, cloud hunting | Cloud-first intrusion detection |
| NTDS/LSASS Dumping | Credential theft | Cross-table joins, privilege chain, file+network correlation | Detects full domain compromise |
| Jittered C2 | Beaconing malware | Behaviour scoring, periodicity detection | Detects post-exploitation C2 |

---

# 7. CONCLUSION  
This architecture demonstrates:

- Engineering maturity  
- Understanding of adversary behaviours  
- Ability to design multi-signal correlation hunts  
- Capability to express detection logic clearly  
- SOC-ready analysis guidance for IR teams  

This “hybrid” document is designed for analysts, engineers, and hiring managers to quickly understand **how** and **why** these hunts detect high-fidelity modern attacks.
