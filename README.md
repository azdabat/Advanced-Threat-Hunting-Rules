# Threat Hunting & Detection Engineering Rules  
**Author:** Ala Dabat  
**Focus Areas:** Threat Hunting • Detection Engineering • Adversary Behaviour • MDE • Sentinel • KQL  

This repository contains my ongoing collection of threat hunting and detection logic built for modern enterprise environments.  
The goal is to maintain a structured, high-signal ruleset covering endpoint, identity, cloud, persistence, C2, and privilege-escalation patterns.

The rules combine:  
- Behaviour-driven detection (native telemetry, no dependency on third-party TI unless stated)  
- Optional enrichment where available (hash reputation, TI, device exposure context, user context)  
- Confidence scoring, kill-chain classification, and analyst-ready triage notes  
- Compact human-readable KQL, production-aligned naming and schema conventions  
- Low-noise patterns suitable for scheduled hunts  
- Clear separation between *high-fidelity detectors*, *wide-scope hunts*, and *research prototypes*

This is an active work in progress. Several rules are complete and ready; others are placeholders being refined and will be finalised progressively.

---

## Rule Categories

### 1. **Command & Control (C2) Hunts**
High-signal analytics based on timing patterns, process attribution, and endpoint behaviour.

- **HTTPS C2 Jitter Beacon Hunt**  
  Detects beacon-style outbound HTTPS with semi-regular jitter, small payloads, and non-browser executables.

- **Outbound EXE → Public IP Hunt**  
  Enumerates all outbound connections from `.exe` processes to public IPs with device context, scoring, and reputation checks.

---

### 2. **Persistence & Registry Modification**
Techniques mapping to MITRE TA0003 & TA0005.

- **Registry Persistence Hunt (High-Fidelity)**  
  Multi-signal rule detecting suspicious autoruns, IFEO hijacks, COM/LSA hijacks, AppInit_DLLs, and user-writable path persistence.  
  Includes signal scoring and kill-chain mapping.

- **MISP-Enriched Registry Persistence Detector (Adaptive)**  
  Dynamic rule that blends behaviour-based signals with threat intelligence for supply-chain style trades or registry-resident backdoors.

---

### 3. **Privilege Escalation**
Detection for modern Windows EoP tradecraft.

- **Windows Kernel EoP Hunt – 2024/2025**  
  Low→SYSTEM transitions with suspicious initiating processes, exploit-style command lines, and device exposure context.

---

### 4. **Identity & OAuth Abuse**
Rules focused on cloud identity compromise and token misuse.

- **OAuth Consent Abuse Detector (Tenant-Wide Risk Engine)**  
  Maps consent grants + token usage + Graph sign-ins + service principal activity.  
  Flags high-risk permissions, on-behalf-of-all grants, suspicious user-agents, and anomalous token usage.

- **ROPC / Legacy Protocol Abuse Detector**  
  Detects misuse of non-modern auth protocols, BAV2ROPC patterns, password-spray indicators, and credential-harvesting behaviour.

---

### 5. **Supply Chain & Developer Tooling Abuse**
Detection of code execution or persistence via build systems, hooks, and project structures.

- **Git Submodule / Hook Abuse Rule (2025 Pattern)**  
  Targets suspicious git.exe execution + .git/hooks file writes within short windows. Useful for detecting submodule-based execution or malicious hook injection.

---

### 6. **LOLBins / Driver Abuse**
High-risk loaders, vulnerable drivers, and low-noise driver hunting.

- **LOLBins – High-Confidence Execution Hunt**  
  Detects low-volume execution of high-risk binaries associated with credential theft, bypasses, or payload loading.

- **LOLDrivers – Unified Driver Load Hunt**  
  Uses driver reputation, prevalence scores, delayed-load behaviour, and hash enrichment to identify malicious or vulnerable driver loads.

---

## Structure & Standards

All rules follow a consistent structure:

1. **Compact, human-readable query**  
2. **Scoring model** (Base signals → contextual boosts → final severity)  
3. **Kill-Chain Stage** classification  
4. **MITRE mapping**  
5. **Analyst triage directives**  
6. **Optional enrichment** (DeviceInfo, prevalence, threat intel, hash reputation)  
7. **Low-noise design philosophy** (field-correct, minimal joins, lightweight summarisation)

Where appropriate, rules include:

- **Enterprise prevalence modelling**  
- **Cross-signal correlation windows**  
- **Process lineage context**  
- **Account and device exposure context**  

---

## Current Status

This repo is being actively expanded.  
- Core C2, registry, identity and EoP rules are completed and tuned.  
- LOLDrivers, OAuth, persistence, and NTDS/Golden Ticket hunts are fully structured and undergoing additional noise-reduction tuning.  
- Additional coverage will be added across full MITRE ATT&CK for endpoint, identity, network, and cloud.

Where rules are still placeholders, they are clearly marked and will be finalised in upcoming iterations.

---

## Intent of This Repository

This project is meant to demonstrate:

- Practical detection engineering capability  
- Ability to design high-signal rules for real enterprise telemetry  
- Familiarity with MDE/Sentinel schema and constraints  
- Understanding of adversary behaviour and ATT&CK mapping  
- Realistic SOC-ready triage guidance  
- Low-noise engineering choices suitable for operational environments

It also reflects how I structure, version, and refine analytic content as part of an internal detection engineering program.

---

## Contributing / Notes

This is a personal research project.  
All logic is written manually, referencing real attacker behaviour, public reports, and hands-on knowledge of endpoint and cloud telemetry.
I have dozens of hunts offline but will introduce them at a pace to ensure high fedelity/noise Vs. Signal testing.

As the repository evolves, rules will continue to be updated for:

- Noise reduction  
- Scoring improvements  
- Coverage expansion  
- Integration consistency  
- Additional unit test datasets

Feedback is welcome

---
