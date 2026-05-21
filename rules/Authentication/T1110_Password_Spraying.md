# Password Spraying Attack

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-003` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects Password Spraying attacks (low and slow). Unlike traditional Brute Force (many failures, one account), Password Spraying attempts a small number of passwords (often just 1 or 2) across a large number of accounts to avoid triggering account lockouts.

**Logic:**
*   Looks for a single Source IP attempting to log in to many distinct targets (>10).
*   Enforces a 30-minute rolling window `span=30m` since spray attacks are typically slower.

## 🔍 SPL Query
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
NOT user IN ("*$")

# 1. Bucket Time (Longer window for slow spray attacks)
| bin _time span=30m

# 2. Stats Aggregation (Pivot on Source IP)
| stats 
    dc(user) as distinct_users_targeted
    values(user) as targeted_users
    count as total_failed_attempts
    earliest(_time) as started
    latest(_time) as recent
    by _time, src_ip, Caller_Process_Name, Workstation_Name

# 3. Threshold Filter
| where distinct_users_targeted > 10

# 4. Format
| convert ctime(started) ctime(recent)
| rename distinct_users_targeted as "Distinct Accounts Targeted"
| table started, recent, src_ip, Workstation_Name, Caller_Process_Name, "Distinct Accounts Targeted", targeted_users, total_failed_attempts
| sort - total_failed_attempts
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog:Security`
*   **EventCode:** `4625`
*   **Key Fields:** `src_ip` (Attacker IP), `user` (Targeted Accounts)

## 🧪 Validation
1.  **Simulation:** Use a tool or script to attempt a failed login for 15 different usernames from the same IP address within 30 minutes.
2.  **Verify:** Alert triggers with `Distinct Accounts Targeted > 10`.
