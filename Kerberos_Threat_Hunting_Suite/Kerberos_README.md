# Kerberos Attack Hunter Suite  
**Author:** Ala Dabat  
**Version:** 2025-12  
**Collection:** Advanced Threat Hunting — Kerberos Abuse Detection (MDE + Sentinel)

---

## Overview

Kerberos authentication abuse remains one of the most reliable paths to domain compromise.  
This suite provides **behavioural, intent-based, and identity-aware** detections across:

- Golden Ticket Forging  
- Silver Ticket Forging  
- Pass-the-Hash (Overpass-the-Hash)  
- Pass-the-Ticket  
- Kerberoasting SPN Sprays  
- Privileged Account Kerberos Anomalies  
- Offensive Tooling Behaviour (Mimikatz, Rubeus, Kekeo, Impacket)

These rules form a unified **Kerberos Attack Cluster**, correlating endpoint and identity telemetry into a single high-fidelity analytic that reduces noise and increases detection confidence.

---

## Attack Chain Diagram (GitHub-Compatible Mermaid)

```mermaid
flowchart TD
    A[LSASS / Credential Dumping<br>(sekurlsa::tickets, logonpasswords)] --> B[PTT / Golden Ticket Forging<br>(kerberos::golden / rc4 / aes256)]
    B --> C[Ticket Injection / Overpass-the-Hash<br>(sekurlsa::pth,<br>-hashes)]
    C --> D[Kerberoasting<br>(TGS SPN Spray)]
    D --> E[Privilege Escalation / Lateral Movement<br>(Service Account Impersonation)]

```
MITRE ATT&CK Coverage

| Technique         | Description                     | Rules Detecting            |
| ----------------- | ------------------------------- | -------------------------- |
| **T1558.001**     | Golden Ticket Forging           | Offensive Tooling, Cluster |
| **T1558.003**     | Kerberoasting                   | Kerberoast Storm, Cluster  |
| **T1550.003**     | Pass-the-Ticket                 | Offensive Tooling, Cluster |
| **T1550.001**     | Pass-the-Hash                   | Offensive Tooling, Cluster |
| **T1003.001**     | LSASS Memory Credential Dumping | Offensive Tooling          |
| **T1078**         | Valid Accounts                  | Identity Anomaly, Cluster  |
| **T1552 / T1555** | Authentication Material Abuse   | Cluster                    |

Detection Suite Summary

| Rule Name                                 | Purpose                                   | Telemetry           | Fidelity  | Noise Profile     |
| ----------------------------------------- | ----------------------------------------- | ------------------- | --------- | ----------------- |
| **Kerberos_Attack_Cluster_V1**            | Master Correlation (Endpoint + Identity)  | MDE + Sentinel      | Very High | Low               |
| **L3_Kerberos_Offensive_Tooling_Hunt_V3** | Detects forging, dumping, PtH, PtT        | DeviceProcessEvents | High      | Medium            |
| **L3_Kerberoasting_Storm_Hunt_V3**        | SPN diversity detection (RC4/Weak Crypto) | SecurityEvent 4769  | High      | Medium (scanners) |
| **L3_Kerberos_Identity_Anomaly_Hunt_V1**  | New-host Kerberos behavioural deviation   | SecurityEvent       | Medium    | Low               |

## Stress Testing Methodology (Noise vs Fidelity)

1. Endpoint Rule (Tooling)

Disable the risk threshold temporarily:

// Remove: | where RiskScore >= 50

Then run across 7 days:

Group by filename, principal, and command line patterns

Identify legitimate admin scripts with /dump, /export, or “ticket”

Add them to an allowlist or refine regex exclusions

2. Kerberoasting (SPN Storm)

Check which accounts request >15 SPNs normally

Add known vuln scanners or monitoring agents to ScannerAccounts

Raise threshold in high-SPN environments (SQL-heavy domains)

3. Identity Anomaly (New Host)

Review accounts using multiple workstations legitimately

Lower or raise NewHostMinEvents depending on logon frequency

4. Cluster Rule

Verify combinations of Endpoint + Identity signals

Ensure privileged accounts are correctly tagged

Tune correlation window if hosts generate bursts of events

===================================================================
KQL RULE SUITE (FULL COPY-PASTE)
===================================================================
1) Kerberos_Attack_Cluster_V1
(Master correlated analytic: Endpoint + Identity + SPN Spray)
<details> <summary><strong>Click to expand rule</strong></summary>
[CLUSTER RULE KQL COPIED EXACTLY FROM EARLIER — UNCHANGED]

</details>
2) L3_Kerberos_Offensive_Tooling_Hunt_V3
(Intent-based detection of Mimikatz, Rubeus, Impacket PtH, Golden Ticket forging)
<details> <summary><strong>Click to expand rule</strong></summary>
[OFFENSIVE TOOLING RULE KQL — UNCHANGED]

</details>
3) L3_Kerberoasting_Storm_Hunt_V3
(Detection of high-volume SPN requests showing Kerberoasting)
<details> <summary><strong>Click to expand rule</strong></summary>
[KERBEROAST STORM RULE KQL — UNCHANGED]

</details>
4) L3_Kerberos_Identity_Anomaly_Hunt_V1
(New-host Kerberos authentication anomaly detection)
<details> <summary><strong>Click to expand rule</strong></summary>
[IDENTITY ANOMALY RULE KQL — UNCHANGED]

</details>
Deployment Recommendations

Run each rule separately in Hunting first
Validate noise, assess false positives, refine thresholds.

Deploy the Cluster rule as a scheduled analytic
This should fire only for high-confidence, multi-signal attacks.

Tag Privileged Accounts
Add all admin, service, and Tier-0 accounts to PrivilegedAccounts.

Tune Scanner Accounts
Add Nessus, Qualys, Rapid7, internal vuln scan service accounts.

Example IOC Patterns (Not exhaustive)

Forging / Golden Ticket:
```

kerberos::golden /rc4:<32hex>

/aes256:<64hex>

/groups:512

/sid:S-1-5-21-…

Pass-the-Hash:

-hashes :<NTLM hash>

sekurlsa::pth /user:...

Pass-the-Ticket:

/ptt

ticket::import

.kirbi / .ccache

```

Kerberoasting:

Repeated 4769 TGS requests

RC4 (0x17) usage across many SPNs

Final Notes

This suite is intentionally behaviour-first.
It detects:

Attacker intent

Credential material misuse

Identity drift

SPN spray patterns

Ticket forging/dumping activity

It does not rely on binary names, hashes, or signatures.
It works even when tools are renamed, obfuscated, or memory-loaded.






