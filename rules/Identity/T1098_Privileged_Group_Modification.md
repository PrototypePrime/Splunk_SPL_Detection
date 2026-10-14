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
````spl
index=security sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode IN (4728, 4732, 4756)

```-- Exclusions (uncomment, then maintain the lookup) --```
```NOT [| inputlookup authorized_group_admins.csv | fields SubjectUserName ]```

| where match(TargetUserName, "(?i)(Domain Admins|Enterprise Admins|Schema Admins|Administrators)")

```1. Stats Aggregation```
| stats
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(MemberName) as added_user
    values(SubjectUserName) as actor
    count
    by TargetUserName, Computer

```2. Format```
| convert ctime(first_seen) ctime(last_seen)
| rename Computer as dest
| table first_seen, last_seen, dest, TargetUserName, added_user, actor, count
````

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **Key Fields:** `EventCode`, `TargetUserName` (Group), `MemberName` (Added User), `SubjectUserName` (Actor), `Computer` (output as `dest`)

## 🧪 Validation & Tuning
**False Positives:**
*   Legitimate administrative changes via Change Management.

**Tuning:**
*   Add authorized automation/admin accounts to `authorized_group_admins.csv` and uncomment the Exclusions line.

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually run: `net group "Domain Admins" testuser /add /domain`
2.  **Verify:** Confirm the SPL returns results showing the actor and the added user.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Identify the actor (`SubjectUserName`) who performed the addition.
2.  Verify if there is an approved Change Request.
3.  If unauthorized, remove the user from the group immediately.
4.  Reset the password of the actor account and investigate for compromise.
