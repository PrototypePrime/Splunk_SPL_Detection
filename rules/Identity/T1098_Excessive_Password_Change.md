# Windows Excessive Password Change Activity

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-005` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies when a single user account or administrative account changes/resets the password for the same target user multiple times (>4) within a short window. This "Password Thrashing" can indicate:
*   An administrator struggling with a script/tool.
*   Someone attempting to cycle through password history requirements.
*   Malicious persistence attempts.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode IN (4723, 4724)
NOT SubjectUserName="*$"

```1. Stats Aggregation```
| stats
    earliest(_time) as started
    latest(_time) as recent
    values(EventCode) as action
    values(Keywords) as status
    values(SubjectDomainName) as src_domain
    values(TargetDomainName) as dest_domain
    count
    by SubjectUserName, TargetUserName

```2. Threshold Filter```
| where count > 4

```3. Format```
| convert ctime(started) ctime(recent)
| rename SubjectUserName as src_user, TargetUserName as user
| sort - count

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup password_reset_exclusions.csv | fields src_user ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCodes:** `4723` (User changed own password), `4724` (Admin reset password)
*   **Key Fields:** `SubjectUserName` (Actor, output as `src_user`), `TargetUserName` (Target, output as `user`), `Keywords` (Audit Success / Failure)

## 🧪 Validation
1.  **Simulation:** Manually change a test user's password 5 times in 5 minutes using `net user`.
2.  **Verify:** Confirm the alert fires.
