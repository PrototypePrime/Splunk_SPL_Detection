# Failed Login - Disabled Account

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-002` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects login attempts using accounts that are intentionally disabled.
*   **External:** May indicate an attacker trying to use old/known credentials (e.g., former employee).
*   **Internal:** May indicate services improperly configured with deprecated accounts.

**Logic:**
Filters for `EventCode=4625` (Failure) where the SubStatus is `0xC0000072` (Account Disabled).

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4625
SubStatus="0xC0000072"
NOT TargetUserName IN ("Guest", "DefaultAccount", "*$")

```1. Stats Aggregation```
| stats
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(SubStatus) as Error_Message
    values(TargetDomainName) as user_domain
    values(LogonType) as logonType
    values(WorkstationName) as src_host
    values(IpAddress) as source
    values(ProcessName) as process
    count
    by TargetUserName

```2. Format```
| convert ctime(first_seen) ctime(last_seen)
| rename TargetUserName as user
| sort - count
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4625`
*   **SubStatus:** `0xc0000072` (STATUS_ACCOUNT_DISABLED)

## 🧪 Validation
1.  **Simulation:** Disable a test user (`net user TestUser /active:no`) and attempt to log in.
2.  **Verify:** Alert triggers.
