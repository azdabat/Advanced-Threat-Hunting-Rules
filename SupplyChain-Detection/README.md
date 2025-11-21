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

## Suggested Repo Layout

```text
SupplyChain-Detection/
├── MDE_SupplyChain_Sideloading_DriverAbuse.kql
└── README.md
