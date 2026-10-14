# Windows User Account Deleted

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-007` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects when a Windows User Account is deleted (Event Code 4726). While account deletion can be a normal administrative task, unexpected deletions can indicate:
*   **Adversary Cleanup:** Removing backdoor accounts to hide tracks.
*   **Malicious Insider:** Sabotaging legitimate users.

**Logic:**
*   **Specific EventCode:** Uses `EventCode=4726` (User Account Deleted) for precision.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4726
NOT SubjectUserName="*$"

```1. Stats Aggregation```
| stats
    earliest(_time) as started
    latest(_time) as recent
    values(Computer) as Host
    values(TargetDomainName) as Domain
    count
    by SubjectUserName, TargetUserName

```2. Format```
| convert ctime(started) ctime(recent)
| rename SubjectUserName as Deleted_by, TargetUserName as Deleted_account
| table started, recent, Host, Domain, Deleted_by, Deleted_account, count

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup account_deletion_exclusions.csv | fields Deleted_by ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4726`
*   **Key Fields:** `SubjectUserName` (output as `Deleted_by`), `TargetUserName` (output as `Deleted_account`), `Computer`

## 🧪 Validation
1.  **Simulation:** Use `net user TestUser /delete` on a monitored host.
2.  **Verify:** Confirm the alert triggers.
