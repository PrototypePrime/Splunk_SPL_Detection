# Windows Excessive Login Failures (Domain Account)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of failed login attempts (>25) for a single user account. This typically indicates a Brute Force or Password Spray attack.
**Exclusions:** Filters out "Password Expired" / "Must Change Password" failures (SubStatus `0xC0000071` / `0xC0000224`) to focus on actual authentication failures. Service and scanner accounts are excluded via the `auth_exclusions.csv` lookup.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4625
NOT SubStatus IN ("0xC0000071", "0xC0000224")

```1. Stats Aggregation```
| stats
    values(WorkstationName) as Host_Name
    values(Computer) as Auth_domain
    values(SubStatus) as Error_code
    values(TargetDomainName) as user_Domain
    values(IpAddress) as host_ip
    values(LogonType) as Logon_Type
    values(ProcessName) as Process_involved
    count
    by TargetUserName

```2. Threshold Filter```
| where count > 25

```3. Format```
| rename TargetUserName as user
| sort - count
| table user, user_Domain, Logon_Type, Host_Name, host_ip, Process_involved, Auth_domain, Error_code, count

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup auth_exclusions.csv | fields user ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4625` (Logon Failure)
*   **Key Fields:** `TargetUserName` (Account), `SubStatus` (Failure Code), `IpAddress`, `WorkstationName`, `LogonType`

## 🧪 Validation
1.  **Simulation:** Attempt to RDP or `runas` with a wrong password 26 times.
2.  **Verify:** Alert triggers.
