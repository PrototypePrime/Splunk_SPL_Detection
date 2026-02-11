# User Added to Privileged Group (Domain Admins)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-001` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Severity** | CRITICAL |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies when a user is added to high-privilege groups like "Domain Admins" or "Enterprise Admins" in Active Directory.

**Attack Scenario:**
1.  Attacker gains administrative access to a Domain Controller or Admin workstation.
2.  Attacker adds a compromised user or a new backdoor user to the "Domain Admins" group.
3.  Attacker establishes persistence with domain dominance.

---

## 🔍 SPL Query
```spl
index=security sourcetype=WinEventLog:Security EventCode IN (4728, 4732, 4756)
| where match(TargetUserName, "(?i)(Domain Admins|Enterprise Admins|Administrators)")
| stats 
    count,
    values(MemberName) as added_user,
    values(SubjectUserName) as actor
    by TargetUserName, dest
```

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `WinEventLog:Security`
*   **Key Fields:** `EventCode`, `TargetUserName`, `MemberName`, `SubjectUserName`

## 🧪 Validation & Tuning
**False Positives:**
*   Legitimate administrative changes via Change Management.

**Tuning:**
*   Exclude authorized admin accounts if automated (e.g., `SubjectUserName` IN ("authorized_admin")).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually run: `net group "Domain Admins" testuser /add /domain`
2.  **Verify:** Confirm the SPL returns results showing the actor and the added user.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Identify the actor (`SubjectUserName`) who performed the addition.
2.  Verify if there is an approved Change Request.
3.  If unauthorized, remove the user from the group immediately.
4.  Reset the password of the actor account and investigate for compromise.
