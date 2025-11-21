# Registry Persistence & Hijack Detection (MDE / Sentinel)

Author: Ala Dabat  
Detection Type: Endpoint Persistence Hunt (Registry)  
Tactics: TA0003 | TA0002 | TA0005

---

## Purpose

This detection focuses on high-risk registry persistence and hijack techniques that attackers use for long-term access and execution. It targets the specific registry paths most commonly abused in real intrusions, with attention to payload content, initiation process, signer, and prevalence.

Coverage includes:

- Run and RunOnce keys  
- Winlogon Shell and Userinit hijacks  
- AppInit_DLLs global DLL injection  
- Services-based persistence  
- IFEO (Image File Execution Options) debugger redirection  
- COM hijacking (CLSID + InprocServer32)  
- LSA/SSP credential provider persistence  
- User-writable paths and LOLBin-driven payloads  

The rule is tuned for L3 threat hunting and aims to surface actual persistence rather than routine software writes.

---

## What This Rule Detects

Category | Detected | Description
---------|----------|------------
Registry Run / RunOnce persistence | Yes | Malware or tooling set to launch at user logon
Winlogon Shell/Userinit hijacks | Yes | Alternate shells or custom executables invoked at login
AppInit_DLLs | Yes | Global DLL injection into GUI processes
Services-based persistence | Yes | New or modified service entries
IFEO injection | Yes | Debugger redirection to attacker binaries
COM hijacking | Yes | CLSID and InprocServer32 pointing to malicious DLLs
LSA/SSP hooks | Yes | Credential-stealing SSP DLLs
LOLBin-backed payloads | Yes | rundll32, regsvr32, mshta, powershell, wscript, cscript, etc.
Encoded payloads | Yes | Base64 or encoded scripts in registry values
Rare unsigned binaries | Yes | Uses prevalence and signer analysis to identify anomalies

---

## What This Rule Does Not Detect

Category | Reason
---------|--------
WMI Event Consumers | Requires WMI provider telemetry
Scheduled Task persistence | Needs TaskCache and DeviceProcessEvents
Startup folder shortcuts | File-system based, not registry
Kernel or driver persistence | Depends on ELAM/driver telemetry
GPO-based persistence | Registry.pol and SYSVOL not covered here
Fully in-memory or fileless malware | No registry footprint present

Pair this with DLL/driver sideloading and task-based persistence hunts for full coverage.

---

## MITRE ATT&CK Mapping

Tactic | Technique | Notes
-------|-----------|------
Persistence | T1547.001 | Registry Run keys
Persistence | T1547.009 | LSA/SSP credential providers
Persistence | T1543.003 | Windows service persistence
Persistence | T1546.012 | IFEO debugger hijacking
Persistence | T1546.015 | COM hijacking
Execution | T1059.001 | PowerShell via registry entries
Execution | T1218.010/011/005 | LOLBins: regsvr32, rundll32, mshta
Defense Evasion | T1105 | Payload download / external staging referenced in registry

---

## Detection Logic Summary

The rule stacks multiple independent signals to identify meaningful persistence:

- Scope limited to established persistence and hijack registry paths in HKLM and HKCU  
- Payload inspection for encoded commands, URLs, domains, IP addresses, and executable/script extensions  
- Initiator analysis for unsigned, rare, or untrusted processes modifying sensitive keys  
- Signer and publisher reputation checks  
- Prevalence weighting to elevate binaries seen on very few devices  

Results are aggregated per Device + RegistryKey + ValueName and include:

- Signal count and weighted severity  
- Initiating process metadata  
- Example command line and binary hash  
- MITRE techniques  
- Analyst hunting directives for response

---

## Analyst Hunting Directives

The rule emits a HuntingDirectives field containing guidance such as:

1. Review the exact registry location and confirm its intent.  
2. Validate the binary, signer, and company information of the initiating process.  
3. Examine payloads for encoded or LOLBin-driven execution.  
4. Pivot on ProcSHA to determine spread across devices.  
5. If malicious, remove or quarantine the registry value and the referenced binary.  
6. Correlate with recent process launches, network activity, and endpoint alerts.  
7. Map findings to MITRE techniques for incident reporting.

This is designed for L3 investigations requiring low noise and high context.

---

## Supply-Chain and Notable Attack Relevance

This persistence framework aligns with common post-compromise behaviour observed in major incidents:

- NotPetya and M.E.Doc — service persistence, run keys, staged loaders  
- 3CX — secondary DLL loaders via Run keys and COM hijacks  
- F5 and appliance transitions — registry footholds once attackers pivot into Windows estates  
- APT and red-team tradecraft — heavy use of IFEO, COM, and LSA-based backdoors  

Supply-chain attacks may begin elsewhere, but durable access often ends in these registry paths.

---

## Example Output Fields

Field | Description
------|------------
DeviceName | Host containing suspicious persistence
RegistryKey / ValueName / ValueData | Location and payload
ProcUser | User context writing the registry value
ProcSigner / ProcCompany | Publisher details of the modifying binary
ProcSHA | Hash used for wider pivots and correlation
MaxSignals | Weighted score combining behavioural, signer, and rarity signals
ThreatSeverity | CRITICAL / HIGH / MEDIUM based on signal profile
MITRE_Tactics / MITRE_Techniques | ATT&CK mapping for investigation
HuntingDirectives | SOC-ready guidance for analyst response

---

## Pairing Suggestions

For full coverage of persistence mechanisms, combine this rule with:

- DLL and driver sideloading detection  
- Scheduled task persistence hunt  
- WMI event consumer hunt  
- OAuth consent and cloud-persistence rule  

Together, these form a comprehensive endpoint and cloud persistence package suitable for advanced threat-hunting operations and portfolio presentation.
