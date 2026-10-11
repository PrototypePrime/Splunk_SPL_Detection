# Password Spraying Attack

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-003` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects Password Spraying attacks (low and slow). Unlike traditional Brute Force (many failures, one account), Password Spraying attempts a small number of passwords (often just 1 or 2) across a large number of accounts to avoid triggering account lockouts.

**Logic:**
*   Looks for a single Source IP attempting to log in to many distinct targets (>10).
*   Groups events into fixed 30-minute buckets (`bin _time span=30m`) since spray attacks are typically slower.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4625
NOT TargetUserName="*$"

```1. Bucket Time (Longer window for slow spray attacks)```
| bin _time span=30m

```2. Stats Aggregation (Pivot on Source IP)```
| stats
    dc(TargetUserName) as distinct_users_targeted
    values(TargetUserName) as targeted_users
    values(WorkstationName) as Workstation_Name
    values(ProcessName) as Caller_Process_Name
    count as total_failed_attempts
    earliest(_time) as started
    latest(_time) as recent
    by _time, IpAddress

```3. Threshold Filter```
| where distinct_users_targeted > 10

```4. Format```
| convert ctime(started) ctime(recent)
| rename IpAddress as src_ip, distinct_users_targeted as "Distinct Accounts Targeted"
| table started, recent, src_ip, Workstation_Name, Caller_Process_Name, "Distinct Accounts Targeted", targeted_users, total_failed_attempts
| sort - total_failed_attempts
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4625`
*   **Key Fields:** `IpAddress` (Attacker IP, output as `src_ip`), `TargetUserName` (Targeted Accounts)

## 🧪 Validation
1.  **Simulation:** Use a tool or script to attempt a failed login for 15 different usernames from the same IP address within 30 minutes.
2.  **Verify:** Alert triggers with `Distinct Accounts Targeted > 10`.
