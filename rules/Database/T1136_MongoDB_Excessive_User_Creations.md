# MongoDB Excessive User Creations

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-006` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of `createUser` events (>5) within the search window. Mass creation of users could indicate a botnet registration or backdoor account proliferation.

## 🔍 SPL Query
```spl
index=MongoDB atype=createUser 
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
1.  **Simulation:** Run a script to create 6 dummy users in rapid succession.
2.  **Verify:** Alert triggers with `count >= 6`.
