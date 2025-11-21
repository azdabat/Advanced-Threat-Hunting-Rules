# Browser Extension Threat Detection Suite
Author: Ala Dabat  
Version: 2025-11  
Category: Persistence / Initial Access / Supply-Chain  
Status: Production-Hardened

---

## Overview
This module provides integrated detection coverage for malicious or suspicious browser extension activity across enterprise endpoints. It combines behaviour-based detection with a curated external malicious-extension intelligence feed to expose stealth installs, forced policy deployments, manifest tampering, sideloaded extensions, and known malicious components.

The detection logic is designed for high-fidelity threat hunting and SOC triage. Behaviour surfaces remain low CPU, while feed correlation adds targeted enrichment and scoring.

---

## What This Detects
- Known malicious chrome/edge extensions  
- Malicious CRX drop events  
- Forced installs via Group Policy (policy abuse)  
- manifest.json injection and tampering  
- Extension folder sideloading  
- High-risk extension categories  
- Suspicious install paths or script-based installers  
- Zero-day extension abuse patterns  

Each detection is assigned a TotalScore and a ThreatHunterDirective designed to accelerate analyst workflows.

---

## Data Sources
- DeviceFileEvents  
- DeviceRegistryEvents  
- DeviceInfo  
- externaldata() feed for malicious extensions  

---

## Output Fields
The rule returns a single flattened record per detection, including:

- Timestamp  
- DeviceName  
- FileName / FolderPath  
- Extracted extension ID  
- Feed metadata (if matched)  
- Install method classification  
- TotalScore  
- MITRE technique mapping  
- ThreatHunterDirective  

All fields use human-readable names for clarity.

---

## Example Detections
See the included simulated results for examples of:

- Malicious feed-matched installs  
- Behaviour-only suspicious activity  
- Benign installs  
- Policy-level anomalies  

---

## Deployment Notes
- Behaviour surface: low CPU, safe for continuous hunting  
- Feed correlation: medium CPU, recommended for scheduled analytics  
- Rule is modular, allowing you to expand the feed or enrich behaviour targets  

---

## Project
https://github.com/azdabat/Threat-Hunting-Rules/BrowserExtensions
