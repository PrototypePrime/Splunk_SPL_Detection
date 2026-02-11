# AWS Console Login Without MFA

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-CLOUD-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies AWS Console logins that did not use Multi-Factor Authentication, which violates security best practices and increases compromise risk.

**Attack Scenario:**
1.  Attacker compromises valid AWS credentials.
2.  Attacker logs into the AWS Console without MFA challenge.
3.  Attacker gains access to cloud resources.

---

## 🔍 SPL Query
```spl
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin "additionalEventData.MFAUsed"=No
| convert ctime(_time) as Time 
| stats 
    count as login_count,
    values(sourceIPAddress) as src_ips,
    earliest(Time) as first_seen
    by userIdentity.userName, awsRegion
```

---

## 📦 Data Schema
*   **Index:** `aws`
*   **Sourcetype:** `aws:cloudtrail`
*   **Key Fields:** `eventName`, `additionalEventData`, `userIdentity.userName`

## 🧪 Validation & Tuning
**False Positives:**
*   SSO/Federated logins where MFA is handled by IdP (check documentation).
*   Break-glass accounts (should be alerted anyway).

**Tuning:**
*   Exclude emergency admin accounts if authorized.

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually login to AWS Console with a user that has MFA disabled.
2.  **Verify:** Confirm the SPL returns results showing the username and source IP.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Verify if the user is authorized to login without MFA (e.g., service account, though rare for Console).
2.  Contact the user to enable MFA immediately.
3.  Investigate actions performed during the session.
