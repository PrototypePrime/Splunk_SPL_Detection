# MongoDB Excessive Role Drops

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-003` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of `dropRole` events (>5) within the search window. Mass deletion of roles could indicate malicious intent to disrupt access controls or hide previous modifications.

## 🔍 SPL Query
```spl
index=MongoDB atype=dropRole 
| convert ctime(_time) as Time   
| stats  
    earliest(Time) as Started 
    latest(Time) as Recent 
    values(sourcetype) as Sourcetype 
    values(param.role) as Dest_Role 
    count 
    by users{}.user 
| where count > 5
```

## 📦 Data Schema
*   **Index:** `MongoDB`
*   **Key Fields:** `atype`, `users{}.user` (Actor), `param.role` (Target)

## 🧪 Validation
1.  **Simulation:** Run a script to drop 6 dummy roles in rapid succession.
2.  **Verify:** Alert triggers with `count >= 6`.
