# Windows User Account Deleted

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-007` |
| **MITRE Tactic** | Persistence / Defense Evasion |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects when a Windows User Account is deleted (Event Code 4726). While account deletion can be a normal administrative task, unexpected deletions can indicate:
*   **Adversary Cleanup:** Removing backdoor accounts to hide tracks.
*   **Malicious Insider:** Sabotaging legitimate users.

**Logic:**
*   **Specific EventCode:** Uses `EventCode=4726` (User Account Deleted) for precision.

## 🔍 SPL Query
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4726
NOT src_user IN ("*$", "ServiceAccount_Pruner")

| convert ctime(_time) as Time 
| rename src_user as Deleted_by 
| rename user as Deleted_account

| stats 
    earliest(Time) as started 
    latest(Time) as recent 
    values(ComputerName) as Host 
    values(Account_Domain) as Domain 
    count 
    by Deleted_by, Deleted_account

| table started, recent, Host, Domain, Deleted_by, Deleted_account, count
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog:Security`
*   **EventCode:** `4726`

## 🧪 Validation
1.  **Simulation:** Use `net user TestUser /delete` on a monitored host.
2.  **Verify:** Confirm the alert triggers.
