# Advanced Registry Persistence Detection  
**Author:** Ala Dabat  
**Category:** Persistence / Execution Hijacking / Defence Evasion  
**Platform:** Microsoft Defender for Endpoint / Microsoft Sentinel  
**Version:** Engineering Pack – Behaviour-Driven Model  

This module documents the complete behavioural model behind the Registry Persistence Detection analytic.  
It includes MITRE ATT&CK mappings, coverage matrices, IOC examples, SOC pivots, and triage workflows.

This is a high-fidelity detection artefact designed for Tier-2, Tier-3 and Threat Hunting teams.

---

# 1. Overview

The Windows Registry remains one of the most abused persistence and execution hijack surfaces.  
Modern malware, red-team tools, loaders, and APT tradecraft routinely leverage:

- **Run / RunOnce keys**
- **IFEO (Image File Execution Options) hijacking**
- **Winlogon Shell / Userinit replacement**
- **Active Setup**
- **AppInit_DLLs**
- **COM Hijacking (InProcServer32)**
- **LSA Plugin modification**
- **Service ImagePath tampering**
- **User-writable persistence paths**
- **LOLBin-driven script execution**
- **Encoded PowerShell stagers / proxy loaders**

This analytic uses multi-signal scoring, path analysis, publisher validation, and prevalence metrics  
to identify malicious activity while suppressing benign enterprise noise.

---

# 2. MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **TA0002 – Execution** | T1059 (PowerShell), T1218 (LOLBAS), T1047 (WMI Exec) | Registry keys chaining into script or binary execution |
| **TA0003 – Persistence** | T1547.001 (Run Keys), T1547.009 (LSA), T1546.012 (IFEO), T1546.015 (COM Hijacking), T1543.003 (Service ImagePath) | Core registry persistence families |
| **TA0004 – Privilege Escalation** | T1546 (Hijacking), T1543 (Service tampering) | Elevated persistence vectors |
| **TA0005 – Defense Evasion** | T1218 (LOLBAS), unsigned binaries, encoded payloads, hidden staging paths | Obfuscation and EDR bypass |
| **TA0006 – Credential Access** | T1556 (LSA Plugins), T1003 (Credential theft via hijacks) | Registry-based credential interception |
| **TA0011 – C2 & Exfiltration** | T1105 (ingress tool transfer via registry-stored URLs/IPs) | Network-enabled persistence |

---

# 3. Threat Coverage Matrix

| Threat Category | Detected | Notes |
|-----------------|----------|-------|
| Run / RunOnce autoruns | ✔ | High-risk when pointing to rare/unsigned payloads |
| IFEO Debugger Hijack | ✔ | Detects debugger redirection → RAT/loader chains |
| Winlogon Shell / Userinit | ✔ | Critical paths, rare legitimate activity |
| Active Setup & Installed Components | ✔ | Used by Emotet, Qakbot, FIN7 |
| COM Hijacking (InProcServer32) | ✔ | DLL hijacks and tradecraft used by APT29, Turla |
| LSA Plugin Injection | ✔ | Credential harvesting / SSP modification |
| Service ImagePath / FailureCommand | ✔ | Persistence and execution hijack |
| AppInit_DLLs | ✔ | Rare in modern systems → high signal |
| URL/IP-based persistence | ✔ | Registry chains linking to C2 |
| User-writable path persistence | ✔ | AppData/Public/Temp abuse |
| Browser extension persistence | ✘ | Different surface (separate rule) |
| Startup folder entries | ✘ | Not registry-based |

---

# 4. IOC Catalogue (Examples)

| IOC Type | Example Indicators |
|----------|--------------------|
| Suspicious Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = %APPDATA%\update.exe` |
| Encoded PowerShell | `powershell.exe -EncodedCommand JAB…` |
| Network-backed persistence | Registry value referencing `hxxp://malicious[.]domain/payload.ps1` |
| IFEO Hijack | `HKLM\...\Image File Execution Options\notepad.exe\Debugger = "cmd.exe /c payload.exe"` |
| Winlogon Shell Manipulation | `Shell = explorer.exe, payload.exe` |
| COM Hijack | `HKCR\CLSID\{GUID}\InProcServer32 = C:\Users\Public\evil.dll` |
| LSA Plugin Injection | `HKLM\SYSTEM\CCS\Control\Lsa\Security Packages = evil.dll` |

---

# 5. Behavioural Detection Logic

The rule identifies malicious behaviour using:

### 5.1 Binary Legitimacy Tests
- Unsigned or unknown publisher  
- File located in AppData, ProgramData, Temp, Public  
- Prevalence ≤ 2 devices in the organisation  
- Non-Microsoft publishers where Microsoft binaries are expected  

### 5.2 Data Payload Inspection
- Executables/scripts referenced in registry values  
- URLs, IP addresses, encoded blobs  
- Suspicious extensions: `.dll`, `.js`, `.vbs`, `.ps1`, `.hta`, `.exe`  
- Base64 payloads, stagers, inline commands  

### 5.3 LOLBin Abuse Detection
Flags registry entries invoking:

- `mshta.exe`
- `rundll32.exe`
- `regsvr32.exe`
- `certutil.exe`
- `powershell.exe` (obfuscated)
- `bitsadmin.exe`
- `cmd.exe` → script loaders  

### 5.4 Privileged Key Abuse
Automatic high-severity when modifications occur in:

- Winlogon  
- LSA  
- AppInit_DLLs  
- IFEO  
- Services  

### 5.5 Scoring
Composite scoring criteria includes:

- Path risk  
- Prevalence  
- Publisher trust  
- LOLBin presence  
- Encoded commands  
- Presence of network references  
- Key sensitivity (Winlogon/IFEO/LSA etc.)

---

# 6. Analyst Triage Workflow

### Step 1 — Validate Initiating Process
- Check publisher, signer, and file reputation  
- If unsigned or rare → HIGH signal  
- If launched by a known LOLBin → likely malicious

### Step 2 — Review Registry Value Data
Look for:
- URLs  
- IP addresses  
- Base64 blobs  
- PowerShell stagers  
- Unknown executables in user-writable paths  
- DLLs in unexpected COM/LSA/IFEO keys  

### Step 3 — Evaluate Prevalence
- Is the binary seen on more than 2 devices?  
- Low prevalence strongly indicates malicious tooling.

### Step 4 — Correlate Process Execution
Pivot on:
```kql
DeviceProcessEvents
| where FileName =~ "<SuspiciousBinary>"
