# Supply-Chain & Sideloading / Driver Abuse Detection (KQL)

This detection focuses on post-compromise behaviours typical of major supply-chain and component hijacking intrusions, including:

- 3CX DesktopApp (malicious DLL sideloading)
- F5 BIG-IP backdoor activity (malicious drivers and DLL loaders)
- SolarWinds SUNBURST (staged, delayed DLL backdoor)
- NotPetya / M.E.Doc loader-style behaviour

Primary focus areas:

- Malicious DLL drops in abused directories
- Fast-load DLL execution indicating sideloading
- Dormant DLL and driver staging
- Unsigned or invalid driver loads (BYOVD patterns)
- Registry-based execution and persistence
- Remote payload downloads (.dll, .sys, .exe, .bin, .dat)
- Optional threat-intel enrichment via MISP or ThreatIntelligenceIndicator

---

## What This Rule Detects

### Behavioural Surfaces

Stage | Behaviour / Surface | Detected
------|----------------------|---------
Malicious DLL drop | .dll written to ProgramData/Users/Temp/Tasks | Yes
Fast-load DLL execution | DLL loaded within 5 minutes after drop | High
DLL loaded into trusted apps | 3CX, SolarWinds binaries, Outlook, Teams | High
Dormant DLL | DLL in writable path older than 7 days and never loaded | Yes
Driver drop | .sys file dropped into writable or abused directories | High
Dormant driver | .sys dropped but not loaded for >7 days | High
Unsigned or invalid signature | DLL/driver with invalid or untrusted signer | High
Registry execution | Run keys, services, or script paths referencing payloads | High
Payload download | URLs delivering DLL/driver/executable components | High
TI-correlated artefacts | Hash/IP/URL/domain present in TI datasets | High

---

## Supply-Chain Attack Coverage

Attack | DLL Drop | Fast-Load | Dormant DLL | Driver Abuse | Registry Persistence | Network Payloads | Notes
-------|----------|-----------|-------------|--------------|----------------------|------------------|-------
3CX DesktopApp | Yes | High | No | No | Yes (variants) | Yes | Classic DLL sideloading inside 3CX binary folder
F5 BIG-IP 2025 | Yes | Yes | Yes | High | High | Yes | Driver + loader chain with service-backed persistence
SolarWinds SUNBURST | Yes | Yes | High | No | Yes | Yes | Staged dormant DLL backdoor with delayed activation
NotPetya (M.E.Doc) | Yes | Yes | No | No | Yes | Yes | Loader behaviour preceding destructive payloads
Generic Vendor Compromise | Yes | Yes | Yes | Yes | Yes | Yes | Behaviour-first, IOC-independent coverage

---

## ThreatHunterDirective and HuntingDirectives

### ThreatHunterDirective
A single triage summary line, for example:

- CRITICAL: Likely DLL sideloading consistent with 3CX or SolarWinds supply-chain intrusion  
- CRITICAL: Potential BYOVD driver abuse aligning with F5-style compromise patterns  
- HIGH: Dormant DLL in writable directory indicating possible staged loader  
- MEDIUM: Remote retrieval of binary indicative of staging or loader activity  

### HuntingDirectives
Analyst response guidance included in each result:

1. Verify whether the DLL or driver is legitimate for the associated application or vendor.  
2. Examine process lineage and confirm whether the installer or update process is valid.  
3. For DLL sideloading events, inspect the parent process (3CX, SolarWinds Orion, Outlook, etc.) and validate its integrity.  
4. For driver drops, review digital signing, installation origin, and any linked services.  
5. Correlate drop and load timestamps with network telemetry for C2, staging, or tooling distribution.  
6. If compromise is suspected, isolate the endpoint and ingest related IOCs into MISP or other TI platforms.  
7. Hunt across the entire environment for matching hashes, filenames, load patterns, or persistence mechanisms.

---

## MITRE ATT&CK Mapping

Tactic | Techniques
-------|-----------
Persistence | T1547.001 (Run Keys), T1543.003 (Services), T1195 (Supply-Chain Compromise)
Privilege Escalation | T1543.003 (Driver/Service), T1574.001 (DLL Hijacking)
Defense Evasion | T1574.001 (Sideloading), T1036 (Masquerading)
Credential Access | Depends on subsequent modules (LSASS/SSP not covered here)
Command and Control | T1105 (Ingress Tool Transfer)
Exfiltration | T1041/T1020 (when correlated with C2 activity)

This rule emphasises behavioural, post-compromise detection and can be extended via threat-intel feeds.

---

## How To Use

1. Load `MDE_SupplyChain_Sideloading_DriverAbuse.kql` into Advanced Hunting.  
2. Modify tunables as needed:  
   - `lookback` (default 14d)  
   - `dormant_window` (default 7d)  
   - `confidence_threshold` (default 3)  
3. Populate `known_malicious_hashes` with supply-chain IOCs sourced from MISP or similar feeds.  
4. Integrate via:  
   - Custom detection rules  
   - Sentinel analytics through the Defender → Sentinel connector  
   - SOAR playbooks leveraging `ThreatHunterDirective` for alert text  

---

## Suggested Repo Layout

```text
SupplyChain-Detection/
├── MDE_SupplyChain_Sideloading_DriverAbuse.kql
└── README.md
