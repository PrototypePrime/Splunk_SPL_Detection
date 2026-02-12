# Failed Login - Disabled Account

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-002` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects login attempts using accounts that are intentionally disabled.
*   **External:** May indicate an attacker trying to use old/known credentials (e.g., former employee).
*   **Internal:** May indicate services improperly configured with deprecated accounts.

**Logic:**
Filters for `EventCode=4625` (Failure) where the SubStatus or Message indicates `0xC0000072` (Account Disabled).

## 🔍 SPL Query
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625 
(Sub_Status="0xc0000072" OR signature="*Account is currently disabled*")
NOT user IN ("Guest", "DefaultAccount", "*$")

| convert ctime(_time) as Time
| stats 
    earliest(Time) as first_seen
    latest(Time) as last_seen
    values(signature) as Error_Message 
    values(Account_Domain) as user_domain 
    values(Logon_Type) as logonType 
    values(Workstation_Name) as src_host 
    values(src_ip) as source 
    values(Caller_Process_Name) as process 
    count 
    by user 

| sort - count
```

## 📦 Data Schema
*   **Index:** `windows`
*   **EventCode:** `4625`
*   **SubStatus:** `0xc0000072` (STATUS_ACCOUNT_DISABLED)

## 🧪 Validation
1.  **Simulation:** Disable a test user (`net user TestUser /active:no`) and attempt to log in.
2.  **Verify:** Alert triggers.
