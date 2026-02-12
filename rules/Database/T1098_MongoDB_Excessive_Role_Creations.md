# MongoDB Excessive Role Creations

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-005` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of `createRole` events (>5) within the search window. Mass creation of roles could indicate a privilege escalation attempt or backdoor creation.

## 🔍 SPL Query
```spl
index=MongoDB atype=createRole 
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
1.  **Simulation:** Run a script to create 6 dummy roles in rapid succession.
2.  **Verify:** Alert triggers with `count >= 6`.
