# Suspicious Email Attachment Extension

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-MAIL-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | PrototypePrime |

## ⚠️ Description
Identifies emails delivered with suspicious attachment extensions (exe, scr, vbs) that are commonly used to deliver malware.

**Attack Scenario:**
1.  Attacker sends a phishing email with a malicious attachment (e.g., `invoice.exe`).
2.  User downloads and executes the attachment.
3.  Malware infects the endpoint.

---

## 🔍 SPL Query
```spl
index=email sourcetype=cisco:esa
| where match(attachment_name, "(?i)\.(exe|scr|vbs|js|bat|ps1)$")
| stats 
    count as email_count,
    values(attachment_name) as attachments,
    values(sender) as senders
    by recipient, subject
| eval severity="HIGH"
```

---

## 📦 Data Schema
*   **Index:** `email`
*   **Sourcetype:** `cisco:esa`
*   **Key Fields:** `attachment_name`, `sender`, `recipient`, `subject`

## 🧪 Validation & Tuning
**False Positives:**
*   Legitimate IT scripts sent via email (should be rare/discouraged).

**Tuning:**
*   Exclude Internal Support addresses (e.g., `sender IN ("it-support@internal.com")`).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually send an email to a test account with a dummy file named "test.exe".
2.  **Verify:** Confirm the SPL returns results identifying the recipient and the suspicious attachment.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Quarantine the email from the user's inbox.
2.  Analyze the attachment in a sandbox.
3.  Check if the user executed the file (correlate with Endpoint logs).
