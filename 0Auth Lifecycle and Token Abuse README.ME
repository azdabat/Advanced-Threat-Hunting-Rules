# 🛡️ OAuth Consent Abuse Threat Hunt (Production Rule)

> **Author**: AlA Dabat  
> **Date**: November 2025  
> **Version*D: 1.0  
> **Platform**: Microsoft Sentinel / Azure Log Analytics  
> **Rule Type**: Threat Hunt / Enrichment  
> **Use Case**: Detect OAuth App Consent abuse and overpermissioning  
> **MITRE ATT&CK**:  
> - **TA0001**: Initial Access  
> - **TA0003**: Persistence  
> - **T1550.001**: OAuth Token Abuse  
> - **T1098.005**: Account Manipulation - New Permissions  

---

## 📌 Overview

This KQL threat hunt rule surfaces **all OAuth app consent events** over a 30-day period, correlates them with token usage and service principal activity, and applies confidence scoring to highlight **high-risk delegated and application permissions**.

It includes:
- ✅ Enrichment from TokenIssuanceLogs, SigninLogs, SP Sign-ins  
- ✅ Confidence scoring  
- ✅ Hunter directives per row  
- ✅ High-risk scope identification (regex + exact match)  
- ✅ User-agent anomaly detection  
- ✅ Safe app/publisher flagging (flag, not filter)

---

## 🎯 Detection Goals

- Identify **overly permissive OAuth grants** (e.g., `Application.ReadWrite.All`, `Mail.ReadWrite`, `Files.ReadWrite.All`)
- Highlight **first-time or rare consent events**
- Flag **non-browser user agents** (e.g., Python, Postman) used in scripted attacks
- Expose **silent daemon apps** abusing app-only tokens (e.g., `GrantType=client_credentials`)
- Pivot to **token usage and Graph API calls** to understand impact

---

## 🧠 Confidence Scoring (RiskScore)

The `RiskScore` column is derived using:

| Signal | Points |
|--------|--------|
| +1     | Per high-risk permission scope granted |
| +2     | Admin (tenant-wide) consent |
| +2     | App-only (client_credentials) grant |
| +1     | Suspicious User-Agent |
| +1     | Unknown Publisher or App |
| +2     | Token or SP usage seen post-consent |

> **Example**: RiskScore ≥ 5 = Medium/High Confidence

---

## 👨‍💻 Hunter Directives

The `HuntingDirectives` field provides contextual actions, for example:

