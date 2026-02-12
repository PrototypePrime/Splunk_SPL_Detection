# User Logged into Multiple Hosts (Lateral Movement)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-006` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects when a single user account logs into a distinct number of hosts (>3) within a short time window (5 minutes). This "Rapid Authentication" pattern often indicates:
*   **Lateral Movement:** An adversary moving through the network.
*   **Automated Scripting:** A script executing actions across multiple endpoints.

**Logic:**
*   **Time Binning:** Uses `bin _time span=5m` to strictly enforce the 5-minute detection window.
*   **Exclusions:** Filters out Machine Accounts (`*$`) and noisy Logon Types (3=Network, 5=Service) to focus on interactive/RDP sessions.

## 🔍 SPL Query
```spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4624, 540)
NOT user="*$" 
NOT Logon_Type IN (3, 5)

# 1. Bucket Time (Enforce 5-minute window)
| bin _time span=5m

# 2. Stats Aggregation
| stats 
    dc(ComputerName) as distinct_host_count 
    values(ComputerName) as target_hosts 
    count as event_count
    earliest(_time) as started 
    latest(_time) as recent 
    by _time, user, Logon_Type

# 3. Threshold Filter
| where distinct_host_count > 3

# 4. Format
| convert ctime(started) ctime(recent)
| rename distinct_host_count as "Number of Hosts"
| table started, recent, user, Logon_Type, "Number of Hosts", target_hosts, event_count
| sort - event_count
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog:Security`
*   **Key Fields:** `ComputerName` (Dest), `user`, `Logon_Type`

## 🧪 Validation
1.  **Simulation:** Use `psexec` or RDP to log into 4 different servers within 2 minutes.
2.  **Verify:** Alert triggers with `Number of Hosts >= 4`.
