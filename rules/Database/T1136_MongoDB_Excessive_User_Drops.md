# MongoDB Excessive User Drops

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-004` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of `dropUser` events (>5) within the search window. Mass deletion of users could indicate malicious intent to disrupt access or hide previous activity.

## 🔍 SPL Query
```spl
index=MongoDB atype=dropUser 
| convert ctime(_time) as Time   
| stats  
    earliest(Time) as Started 
    latest(Time) as Recent 
    values(sourcetype) as Sourcetype 
    values(param.user) as Dest_User 
    count 
    by users{}.user 
| where count > 5
```

## 📦 Data Schema
*   **Index:** `MongoDB`
*   **Key Fields:** `atype`, `users{}.user` (Actor), `param.user` (Target)

## 🧪 Validation
1.  **Simulation:** Run a script to drop 6 dummy users in rapid succession.
2.  **Verify:** Alert triggers with `count >= 6`.
