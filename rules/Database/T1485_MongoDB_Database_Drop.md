# MongoDB Database Drop

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-001` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects when a MongoDB database is dropped (`dropDatabase`). This is a critical, high-impact event that results in data loss.

**Attack Scenario:**
An attacker gains administrative access to the MongoDB cluster and drops databases to destroy data or disrupt services.

## 🔍 SPL Query
```spl
index=MongoDB sourcetype="atlas:audit:logs:prod" atype=dropDatabase 
| convert ctime(_time) as Time 
| rename users{}.user as User
| stats 
    earliest(Time) as Started 
    latest(Time) as Recent 
    values(atype) as Operation 
    values(param.ns) as Collection_Name 
    values(remote.ip) as Client_IP 
    count 
    by User
```

## 📦 Data Schema
*   **Index:** `MongoDB`
*   **Sourcetype:** `atlas:audit:logs:prod`
*   **Key Fields:** `atype` (Action Type), `users{}.user` (Actor)

## 🧪 Validation
1.  **Simulation:** Log in to a test MongoDB Atlas instance and run `db.dropDatabase()`.
2.  **Verify:** Confirm the alert triggers.
