# 🔐 OAuth Consent Abuse Detection Rule (Microsoft Sentinel)
**Author:** Ala Dabat  
**Version:** 2025-11  
**Detection Type:** Cloud Persistence / Initial Access  
**MITRE ATT&CK:**  
- **TA0001 – Initial Access**  
- **TA0003 – Persistence**  
- **T1550.001 – OAuth Token Abuse**

---

## 🧠 Overview
Modern attacks increasingly abuse **OAuth consent flows** instead of passwords or malware.  
Threat actors no longer need a foothold inside the network — they simply request high-risk permissions, gain consent, and operate with *Microsoft Graph API access*.

This rule provides **full-stack detection** for:

- Malicious OAuth consent  
- High-risk Graph permissions  
- Non-Microsoft publishers  
- Suspicious user-agents  
- Token re-use & refresh-token abuse  
- Service principal sign-ins  
- Tenant-wide admin consent  
- App-only (client credential) persistence  
- Offline access tokens (**infinite persistence**)  

---

## 🛡 Real-World Attack Coverage

### ✔ **SolarWinds / UNC2452**
**Tactic:** OAuth app persistence + admin consent + Graph API exfiltration  
**Coverage:**  
- Detects malicious OAuth grants  
- Detects app-only “client credential” backdoor  
- Detects post-consent Graph API token activity  
- Detects non-Microsoft publisher + unusual user agents  

### ✔ **3CX Supply Chain (APT41)**
**Tactic:** OAuth token re-use + credential manipulation  
**Coverage:**  
- Token replay (TokenUseCount > 0)  
- Suspicious UA + IP pivot  
- Offline_access persistence  

### ✔ **Midnight Blizzard (NOBELIUM) 2024–2025**
**Tactic:** Creating malicious apps, granting Mail.Read, Mail.Send, offline_access  
**Coverage:**  
✔ HighRiskPermissionCount  
✔ Suspicious Publisher  
✔ App-only authentication  
✔ Token replay from foreign IPs  

---

## 🔎 Detection Logic Summary
The rule builds detections from 4 telemetry layers:

### **1) Consent Events (AuditLogs)**
- App created  
- Permissions granted  
- Who approved  
- Publisher  
- Consent context  

### **2) Token Issuance (TokenIssuanceLogs)**
- Token replay  
- Refresh token usage  
- Token flood patterns  

### **3) Graph Sign-ins (SigninLogs)**
- Unauthorized graph calls  
- Impossible travel API access  

### **4) Service Principal Sign-ins**
- Machine-level persistence  
- App-only exfiltration  

---

## 📊 Scoring Breakdown

| Component | Weight |
|----------|--------|
| High-risk permissions | +1 each |
| Admin Consent | +2 |
| App-only (client credential) | +2 |
| Suspicious User Agent | +1 |
| Unknown App | +1 |
| Unknown Publisher | +1 |
| Token Re-Use / SP Sign-ins | +2 |

Final output: **RiskScore** sorted highest-first.

---

## 📣 Hunter Directives (Auto-Generated)

Each alert includes a fully-generated SOC response block:

```
OAuth Consent Hunt Alert: App '<AppDisplayName>' granted <N> high-risk permissions.
- Consent: <Admin/User> | Grant: <Delegate/AppOnly>
- Initiator + IP: <User> from <IP>
- TokenUse: <Count> | SPCalls: <Count>
- RiskScore: <Score>
------------------------------
Analyst Actions:
1. Confirm if user truly approved this consent
2. Investigate AppID and publisher reputation
3. Pivot on IP & UserAgent for anomalies
4. Review permissions granted
5. Check token usage & SP sign-ins
6. Revoke app access if malicious
7. Force password reset if compromise suspected
```

---

## 🧪 Lab Testing Recommendations
To validate rule performance:

- Create a dummy Azure app  
- Grant *Mail.Read* or *Files.ReadWrite.All*  
- Perform Graph API calls  
- Test with python, curl, and postman  
- Observe RiskScore growth and token replay detection  
---

## 📬 Contact
For detection engineering, threat modeling, or threat intelligence collaboration:  
**GitHub:** https://github.com/azdabat
