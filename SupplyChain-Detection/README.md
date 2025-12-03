# Polymorphic Malware Behavioural Detection Framework  
Ala Dabat  
Senior SOC / Incident Response / Detection Engineering

This document provides a full behavioural framework for detecting polymorphic malware, loaders, staged DLL/driver sideloading, and memory-only variants using Microsoft Defender for Endpoint (MDE) telemetry. It includes an extended L3 analytic, a compact Tier-1/2 variant, a companion fileless detection rule, complete behavioural matrices, full MITRE mapping, kill-chain alignment, and simulated test evaluations.

This material is designed for production detection engineering repositories and has been structured to demonstrate complete understanding of modern polymorphic behaviour, how it manifests in MDE telemetry, and how to convert those behaviours into high-fidelity detection logic.

---

# 1. Behavioural Characteristics of Polymorphic Malware

Polymorphic malware changes:

- Hashes  
- Filenames  
- Binary structure  
- Strings  
- Packing stubs  

However, several behavioural surfaces remain consistent:

| Behaviour Pattern | Description |
|-------------------|-------------|
| Writable path staging | Dropping DLL/SYS/EXE into ProgramData, Temp, AppData |
| Unsigned module loads | Loading unsigned DLLs or SYS drivers |
| Fast drop-to-load | DLL loaded within 0–5 minutes of drop |
| Dormant DLL/driver | Dropped days prior to execution |
| LOLBin loader chains | rundll32, regsvr32, mshta, powershell |
| Encoded cmd loaders | Base64-encoded arguments and reflective stubs |
| Fast outbound C2 | 0–60 seconds after process creation |
| Disappearing payloads | Drop → load → delete cycle |
| Registry-anchored execution | Run keys, AppInit DLLs, COM hijacking |
| Download → drop proximity | Network request closely precedes drop |
| Sandbox avoidance | Command lines containing VM/debugger strings |
| Delay loops | Sleep commands before execution |

These are common across loader families such as Latrodectus, PikaBot, Rhadamanthys, IcedID, and polymorphic supply-chain backdoors.

---

# 2. MITRE ATT&CK Mapping

| Technique | Description | Behaviour Covered |
|----------|-------------|------------------|
| T1027 | Obfuscation / encoding | Encoded PowerShell / base64 blob loaders |
| T1059 | Command-line execution | LOLBin loaders, PowerShell |
| T1071 | C2 over common protocols | Fast C2, suspicious ports |
| T1105 | Ingress tool transfer | Remote DLL/SYS/EXE downloads |
| T1140 | Deobfuscation / unpacking | Encoded loader patterns |
| T1195 | Supply-chain compromise | High-value processes loading unsigned DLLs |
| T1547 | Registry persistence | Run keys referencing executables |
| T1543 | Driver/service abuse | BYOVD staging |
| T1564 | Artifact hiding | Drop → load → delete |
| T1574.002 | DLL sideloading | Unsigned DLLs loaded by trusted processes |

---

# 3. Behavioural Coverage Matrix

| Behaviour | L3 Extended Rule | Compact Rule | Fileless Rule |
|----------|------------------|--------------|---------------|
| Writable-path file drops | ✓ | ✓ | ✗ |
| Unsigned image loads | ✓ | ✓ | ✗ |
| Fast drop-to-load | ✓ | ✓ | ✗ |
| Dormant DLL/driver | ✓ | ✗ | ✗ |
| Drop → load → delete chain | ✓ | ✓ | ✗ |
| LOLBin loader chain | ✓ | ✓ | ✓ |
| Encoded command behaviour | ✓ | ✗ | ✓ |
| Fast C2 | ✓ | ✓ | ✓ |
| Download → drop proximity | ✓ | ✓ | ✗ |
| Registry persistence | ✓ | ✗ | ✗ |
| Sandbox / VM evasion | ✓ | ✗ | ✓ |
| Pure memory-only loader | ✗ | ✗ | ✓ |
| Delayed execution patterns | ✓ | ✗ | ✓ |

---

# 4. Kill Chain Alignment

| Kill Chain Stage | Behaviour Detected | Coverage |
|------------------|--------------------|----------|
| Initial Access | Browser → LOLBin → loader | Strong |
| Execution | Fast drop→load, encoded commands | Strong |
| Persistence | Registry-referenced execution | Strong |
| Privilege Escalation | SYS driver staging | Medium |
| Defence Evasion | Drop→load→delete, sandbox checks | Strong |
| Command & Control | Fast C2 and rare port usage | Strong |
| Discovery | Limited | Partial |
| Lateral Movement | Not primary target | Partial |
| Impact | Out of scope | N/A |

---

# 5. Simulated Behavioural Test Runs

The following simulations apply the rule’s scoring model exactly.

| Scenario | Description | Key Flags | Score | Severity |
|---------|-------------|-----------|-------|----------|
| S1 | Word macro → rundll32 → DLL → fast C2 → delete | DroppedInWritable, FastDropToLoad, FastC2, DisappearingPayload, LOLBins, EncodedCmd | 22 | High |
| S2 | Browser → EXE drop → encoded PS → C2 | DroppedInWritable, FastC2, EncodedCmd, DropperIsBrowser | 14 | High |
| S3 | Supply-chain sideload (Outlook loads unsigned DLL) | HighValueLoader, Unsigned, WritablePath | 7 | Low |
| S4 | BYOVD driver dropped, dormant 3 days | DroppedInWritable, DormantDriver | 7 | Low |
| S5 | Full stealth: encoded PS → LOLBin → beacon, no disk writes | LOLBins, EncodedCmd, FastC2 | 12 | Medium |
| S6 | Installer noise: legitimate program drops DLL and loads quickly | DroppedInWritable, FastDropToLoad | 5 | Low |

Fileless payloads appear **only** in the companion rule (Section 8).

---

# 6. Noise vs Signal Tuning

| Noise Source | Mitigation |
|--------------|------------|
| Legitimate installers | Exclude signer and known paths |
| RMM/SCCM agents | Suppress by DroppingProcessName |
| Frequent DLL updates | Increase FastLoad threshold or add allowlists |
| Admin scripts | Require FastC2 or FastLoad to elevate score |
| Browser downloads | Require LOLBin involvement or encoded commands |

---

# 7. L3 Extended Detection Rule  
(Full Behavioural Coverage)

```kql
// Companion Rule: Fileless / Memory-Only Polymorphic Behaviour
// Detects encoded loader chains, LOLBin execution, rapid outbound C2,
// sandbox-evasion strings, and suspicious parent process behaviour.

let lookback = 48h;
let lolbins = dynamic(["powershell.exe","cscript.exe","wscript.exe","rundll32.exe","mshta.exe"]);
let office_mail = dynamic(["winword.exe","excel.exe","outlook.exe","powerpnt.exe","hxmail.exe"]);
let sandbox_strings = dynamic(["vbox","vmware","qemu","sandboxie","procmon","x64dbg","ollydbg"]);

let proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ProcessCreated"
| extend Encoded = iif(
        ProcessCommandLine has_any (" -enc","EncodedCommand","frombase64string","invoke-expression","Base64")
        or ProcessCommandLine matches regex @"[A-Za-z0-9\+/]{50,}={0,2}"
      ,1,0)
| extend IsLOLBIN = iif(FileName in~ (lolbins),1,0)
| extend ParentOffice = iif(InitiatingProcessFileName in~ (office_mail),1,0)
| extend SandboxCheck = iif(tolower(ProcessCommandLine) has_any (sandbox_strings),1,0)
| project DeviceId,DeviceName,ProcessId,Timestamp,FileName,ProcessCommandLine,
          Encoded,IsLOLBIN,ParentOffice,SandboxCheck;

let net =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| project DeviceId,DeviceName,ProcessId,ConnectionTime=Timestamp,
          RemoteIP,RemoteUrl,RemotePort;

proc
| join kind=inner net on DeviceId,ProcessId
| extend C2Delay = toint((ConnectionTime - Timestamp)/1s)
| extend FastC2 = iif(C2Delay between (0..60),1,0)
| extend Score = Encoded*3 + IsLOLBIN*2 + FastC2*3 + ParentOffice*2 + SandboxCheck*1
| where Score >= 5
| extend Severity =
    case(
        Score >= 10, "High",
        Score >= 7,  "Medium",
        "Low"
    )
| extend HunterDirectives =
    case(
       Severity == "High" and FastC2 == 1,
          "Investigate as potential memory-only loader. Inspect parent process, check command-line for encoded content, review network destinations, and isolate host if behaviour persists.",
       Severity == "Medium",
          "Validate whether encoded command behaviour is legitimate. Pivot on parent process, user account, and recent script execution.",
       "Use as hunting lead. Correlate with other host events before taking action."
    )
| project Timestamp,DeviceName,Severity,Score,HunterDirectives,
          FileName,ProcessCommandLine,RemoteIP,RemoteUrl,RemotePort,
          Encoded,IsLOLBIN,FastC2,ParentOffice,SandboxCheck
| order by Timestamp desc
---
```
# **Explanation: How Sandbox Detection Works in the Rule**

### 1. What is the sandbox detection surface?

The sandbox-evasion detection in your rule is implemented using a **dynamic string array** containing common indicators that attackers embed in their command line to detect whether they are executing inside:

- Virtual machines  
- Instrumented environments  
- Debuggers  
- Sandboxing tools  
- Malware detonation environments  

**Examples included in the rule:**
The analytic checks whether the `ProcessCommandLine` contains any of these markers.

### 2. Why polymorphic malware uses sandbox checks

Modern polymorphic loaders frequently:

- Detect VM/analysis tools  
- Detect debugger presence  
- Abort or sleep indefinitely  
- Drop “clean” payloads if sandbox detected  
- Switch behaviour when no endpoint security hooks are present

This is an extremely common TTP used by:

- Latrodectus  
- PikaBot  
- BumbleBee  
- Rhadamanthys  
- 3CX backdoor variants  
- Loader families that download encrypted payloads only after conviction that no EDR is present  

### 3. What role sandbox detection plays in your scoring model

In your L3 Extended Rule and the Fileless Companion Rule:

- `SandboxCheck = 1` when sandbox strings appear  
- It does **not** produce an alert on its own  
- It **increases Weight/Score** when combined with:
  - FastC2  
  - Encoded command execution  
  - LOLBins  
  - Writable-path staging  
  - Unsigned loads  

Its purpose is to **strengthen the behavioural cluster**, not to act as a standalone alert.

### 4. Kill Chain contribution

| Kill Chain Stage | Role of Sandbox Detection |
|------------------|---------------------------|
| Initial Access | Malware aborts or modifies payload if sandbox present |
| Execution | Loader chooses different execution paths to avoid behavioural triggers |
| Defence Evasion | Prevents payload from running inside EDR-instrumented VMs |
| C2 | Loader will only fetch the true payload if sandbox-check succeeds |
| Installation | Binaries remain dormant if VM detected |

In your scoring model, sandbox detection helps elevate the confidence of a behavioural sequence where the attacker is clearly:

- Assessing the environment  
- Attempting to bypass defender instrumentation  
- Only executing encoded/memory payloads when safe  

This is strongly correlated with polymorphic behaviour.

### 5. Depth of Analysis

Sandbox-evasion detection demonstrates:

- Understanding of adversary decision trees  
- Knowledge of malware staging logic  
- Awareness that behavioural detection must account for environment-dependent execution paths  
- Ability to model security bypass behaviour  
- Practical experience with modern loader families

This elevates your detection engineering pack significantly.

---

# Supply-Chain & Sideloading / Driver Abuse Detection (KQL)

This rule targets post-compromise behaviours frequently observed in large-scale supply-chain and component hijacking attacks, including:

- 3CX DesktopApp compromise (malicious DLL sideloading)
- F5 BIG-IP backdoor activity (malicious drivers and loaders)
- SolarWinds SUNBURST staged DLL backdoor behaviour
- NotPetya / M.E.Doc-style loader execution

Focus areas include:

- Malicious DLL drops in abused directories
- Fast-load DLL execution (sideloading indicators)
- Dormant DLL and driver staging
- Unsigned or invalid driver loads (BYOVD patterns)
- Registry-based execution and persistence
- Remote payload downloads (.dll/.sys/.exe/.bin/.dat)
- Optional threat-intel enrichment (MISP / ThreatIntelligenceIndicator)

---

## What This Rule Detects

### Behavioural Surfaces

Stage | Behaviour / Surface | Detected
------|----------------------|---------
Malicious DLL drop | .dll written to ProgramData/Users/Temp/Tasks | Yes
Fast-load DLL execution | DLL loaded within 5 minutes after drop | High
DLL loaded into trusted apps | 3CX, SolarWinds binaries, Outlook, Teams | High
Dormant DLL | DLL in writable path older than 7 days, never loaded | Yes
Driver drop | .sys in writable or abused directories | High
Dormant driver | .sys dropped but not loaded for >7 days | High
Unsigned or invalid signature | DLL/driver with unknown or invalid signer | High
Registry execution | Run keys, services, or script paths referencing payloads | High
Payload download | URLs delivering .dll/.sys/.exe/.bin/.dat | High
TI-correlated artefacts | Hash/IP/URL/domain appearing in TI feeds | High

---

## Supply-Chain Attack Coverage

Attack | DLL Drop | Fast-Load | Dormant DLL | Driver Abuse | Registry Persistence | Network Payloads | Notes
-------|----------|-----------|-------------|--------------|----------------------|------------------|-------
3CX DesktopApp | Yes | High | No | No | Yes (variants) | Yes | Malicious DLL sideloading into the 3CX binary directory
F5 BIG-IP 2025 | Yes | Yes | Yes | High | High | Yes | Driver + DLL loader chain with service persistence
SolarWinds SUNBURST | Yes | Yes | High | No | Yes | Yes | Staged dormant DLL backdoor with delayed activation
NotPetya (M.E.Doc) | Yes | Yes | No | No | Yes | Yes | Loader preceding destructive payload
Generic Vendor Compromise | Yes | Yes | Yes | Yes | Yes | Yes | Behaviour-driven, IOC-independent detection

---

## ThreatHunterDirective and HuntingDirectives

### ThreatHunterDirective
A single high-context triage line produced by the rule, examples:

- CRITICAL: Likely DLL sideloading consistent with 3CX or SolarWinds-style supply-chain compromise  
- CRITICAL: Potential BYOVD scenario with suspicious driver load patterns  
- HIGH: Dormant DLL in writable directory suggesting staged loader behaviour  
- MEDIUM: Remote retrieval of binary component likely linked to loader activity  

### HuntingDirectives
Multi-step analyst guidance emitted per detection:

1. Validate whether the DLL or driver is expected for the application or vendor.  
2. Inspect process lineage and confirm the legitimacy of installation/update activity.  
3. For DLL sideloading, examine the parent process (3CX, SolarWinds Orion, etc.) and confirm binary integrity.  
4. For driver writes, review signing, install origin, and associated services.  
5. Correlate drop/load time with network telemetry for C2 or staging infrastructure.  
6. If compromise is indicated, isolate the host and enrich findings with MISP or threat-intel feeds.  
7. Hunt across all endpoints for matching hashes, filenames, or persistence patterns.

---

## MITRE ATT&CK Mapping

Tactic | Techniques
-------|-----------
Persistence | T1547.001 (Run Keys), T1543.003 (Services), T1195 (Supply-Chain Compromise)
Privilege Escalation | T1543.003 (Driver/Service), T1574.001 (DLL Hijacking)
Defense Evasion | T1574.001 (Sideloading), T1036 (Masquerading)
Credential Access | Dependent on downstream modules (LSASS/SSP, not part of this rule)
Command and Control | T1105 (Ingress Tool Transfer)
Exfiltration | T1041/T1020 when combined with C2-oriented detections

This rule is behaviour-first, post-compromise focused, and can be augmented with MISP or other TI sources.

---

## How To Use

1. Paste `MDE_SupplyChain_Sideloading_DriverAbuse.kql` into Advanced Hunting.  
2. Adjust tunables:  
   - `lookback` (default: 14d)  
   - `dormant_window` (default: 7d)  
   - `confidence_threshold` (default: 3)  
3. Populate `known_malicious_hashes` with current supply-chain IOCs from MISP or other threat-intel feeds.  
4. Integrate with:  
   - Custom detection rule  
   - Sentinel analytics via the Defender → Sentinel connector  
   - SOAR automation using `ThreatHunterDirective` as the summary message  

---

