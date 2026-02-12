# Windows Excessive Login Failures (Domain Account)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of failed login attempts (>25) for a single user account. This typically indicates a Brute Force or Password Spray attack.
**Exclusions:** Filters out "Password Expired" errors to focus on actual authentication failures.

## 🔍 SPL Query
```spl
index=windows sourcetype=WinEventLog EventCode=4625 
signature!="User logon with expired password" 
NOT (user IN ("ServiceAccount1", "ScannerAccount")) 
NOT Caller_Process_Name = "*\\LegitApp.exe"

| stats 
    values(Workstation_Name) as Host_Name 
    values(ComputerName) as Auth_domain 
    values(signature) as Error_msg 
    values(Account_Domain) as user_Domain 
    values(src_ip) as host_ip 
    values(Logon_Type) as Logon_Type 
    values(Caller_Process_Name) as Process_involved 
    count 
    by user 

| where count > 25
| sort - count
| table user, user_Domain, Logon_Type, Host_Name, host_ip, Process_involved, Auth_domain, Error_msg, count
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog`
*   **EventCode:** `4625` (Logon Failure)

## 🧪 Validation
1.  **Simulation:** Attempt to RDP or `runas` with a wrong password 26 times.
2.  **Verify:** Alert triggers.
