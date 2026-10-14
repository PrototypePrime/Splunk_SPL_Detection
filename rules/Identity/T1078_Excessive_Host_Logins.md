# User Logged into Multiple Hosts (Lateral Movement)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-006` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects when a single user account logs into a distinct number of hosts (>3) within a short time window (5 minutes). This "Rapid Authentication" pattern often indicates:
*   **Lateral Movement:** An adversary moving through the network.
*   **Automated Scripting:** A script executing actions across multiple endpoints.

**Logic:**
*   **Time Binning:** Uses `bin _time span=5m` to strictly enforce the 5-minute detection window.
*   **Exclusions:** Filters out Machine Accounts (`*$`), built-in Windows session accounts (`DWM-*`, `UMFD-*`, `ANONYMOUS LOGON` — same name on every host), and noisy Logon Types (3=Network, 5=Service) to focus on interactive/RDP sessions. Network fan-out (psexec/SMB, LogonType 3) should be covered by a separate detection.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4624
NOT TargetUserName IN ("*$", "DWM-*", "UMFD-*", "ANONYMOUS LOGON")
NOT LogonType IN (3, 5)

```1. Bucket Time (Enforce 5-minute window)```
| bin _time span=5m

```2. Stats Aggregation```
| stats
    dc(Computer) as distinct_host_count
    values(Computer) as target_hosts
    values(LogonType) as Logon_Type
    count as event_count
    earliest(_time) as started
    latest(_time) as recent
    by _time, TargetUserName

```3. Threshold Filter```
| where distinct_host_count > 3

```4. Format```
| convert ctime(started) ctime(recent)
| rename TargetUserName as user, distinct_host_count as "Number of Hosts"
| table started, recent, user, Logon_Type, "Number of Hosts", target_hosts, event_count
| sort - event_count
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **Key Fields:** `Computer` (Dest), `TargetUserName` (output as `user`), `LogonType`

## 🧪 Validation
1.  **Simulation:** Use RDP (or an interactive logon) to log into 4 different servers within 2 minutes. Note: `psexec`/SMB logons are LogonType 3 and are intentionally excluded.
2.  **Verify:** Alert triggers with `Number of Hosts >= 4`.
