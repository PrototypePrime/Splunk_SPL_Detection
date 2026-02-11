# O365 AiTM Phishing Detection (Axios UA)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-CLOUD-002` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies potential Adversary-in-the-Middle (AiTM) phishing attempts against Office 365 by detecting the `axios` User-Agent. This library is commonly used by phishing kits (like Evilginx2) or malicious scripts to proxy authentication traffic, capturing session tokens.

**Attack Scenario:**
1.  Attacker sends a phishing link to the user.
2.  User clicks the link, which proxies traffic through an AiTM server.
3.  The AiTM server (using a script/library like Axios) connects to O365.
4.  Attacker captures the password and MFA session token.

---

## 🔍 SPL Query
```spl
index=o365 user_agent="axios*" 
| convert ctime(_time) as Time 
| stats 
    earliest(Time) as Started 
    latest(Time) as Recent 
    values(LogonError) as LogonError 
    values(Operation) as Operation 
    values(ResultStatus) as ResultStatus 
    values(UserAgent) as UserAgent 
    values(src_ip) as src_ip 
    count 
    by UserId
| table Started, Recent, UserId, src_ip, UserAgent, Operation, ResultStatus, count
```

---

## 📦 Data Schema
*   **Index:** `o365` (Azure AD / Unified Audit Log)
*   **Sourcetype:** `o365:management:activity` or `azure:aad:signin`
*   **Key Fields:** `user_agent`, `src_ip`, `UserId`

## 🧪 Validation & Tuning
**False Positives:**
*   Legitimate Dev/Ops scripts using Axios to interact with O365 APIs.
*   Custom internal applications.

**Tuning:**
*   Exclude known internal service accounts or developer IPs.
*   `| where NOT src_ip IN ("10.0.0.0/8")`

**Validation Steps:**
1.  **Simulation:** Use a tool like Postman or a simple Python script with `axios` (or similar) headers to authenticate to O365.
2.  **Verify:** Check if the alert triggers with the specific User Agent.
