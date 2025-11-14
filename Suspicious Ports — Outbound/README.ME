# 📘 Suspicious Port Threat Hunting Rule  
### High-Fidelity Network Port Detection Using External Intelligence + Full Process Attribution  
**Author:** Ala Dabat  
**Updated:** 2025-11-14  

---

## 🚀 Purpose

This rule identifies network connections using **suspicious or malicious ports** sourced from an external intelligence CSV feed, and correlates them with **real process telemetry**, including:

- Executable name  
- Command-line  
- SHA256  
- Parent process  
- Signer  
- User context  
- MITRE ATT&CK mapping  
- Risk scoring  
- Analyst hunting directives  

Designed for **SOC L2.5–L3**, **Threat Hunters**, and **CTI analysts**.

---

## 🧠 Detection Summary

### ✔ What This Rule Detects
- Suspicious outbound ports flagged by open-source TI  
- Malware beaconing over rare or disguised ports  
- Unsigned / malicious binaries making outbound connections  
- Supply-chain malware C2 behaviour (3CX, SolarWinds, F5)  
- Encrypted proxy tunnels (SOCKS, OpenVPN)  
- LOLBins establishing network sessions  
- Multi-stage loaders communicating through uncommon ports  

### ❌ What This Rule Does *NOT* Detect

| Not Detected | Reason |
|--------------|--------|
| Malware with no network activity | No connections = no trigger |
| C2 over ports 80/443 | Requires behavioural rules |
| QUIC-based C2 | Encrypted UDP hides ports |
| DNS-over-HTTPS C2 | Hidden behind HTTPS |
| Port knocking | Needs sequential logic |
| Localhost C2 | Intentionally excluded |

---

## 📡 Data Sources

| Table | Purpose |
|-------|---------|
| **DeviceNetworkEvents** | Outbound network connections |
| **DeviceProcessEvents** | Enriched process telemetry |
| **External CSV Feed** | Suspicious ports & metadata |

CSV feed:  
`https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_ports_list.csv`

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **TA0011** | **T1071** | Application Layer C2 |
| | **T1090** | Proxy/Tunneling |
| | **T1573** | Encrypted channel |

---

## 🕵️‍♂️ Analyst Hunting Directives

1. Identify the executable creating the suspicious connection.  
2. Investigate parent process (LOLBins often spawn C2).  
3. Inspect command-line arguments for downloads or encoded payloads.  
4. Review SHA256 and signer reputation.  
5. Check frequency of connections → beaconing patterns.  
6. Perform VirusTotal lookup on destination IP.  
7. Check user session ownership.  
8. If malicious → isolate host and collect memory.

---

## 🧪 Example Output

| DeviceName | RemotePort | Process | RiskLevel | Notes |
|------------|------------|---------|-----------|-------|
| LAPTOP-123 | 1080 | powershell.exe | CRITICAL | Proxy/tunneling behaviour |
| WS-04 | 1194 | unknown.exe | HIGH | Encrypted channel C2 |
| PC-17 | 5985 | rundll32.exe | HIGH | Abnormal WinRM traffic |

---

## 📁 Recommended Folder Structure

```
/Threat-Hunting-Rules  
   └── Suspicious-Ports/  
        ├── suspicious_port_hunt.kql  
        ├── README.md  
        ├── samples/  
        └── references/
```

---

## 🎯 Need More?

I can also generate:

- A behavioural C2 rule  
- A QUIC/DoH detection module  
- A GitHub index README  
- A full supply-chain threat hunting pack  

Just say: **“generate companion rule”**.
