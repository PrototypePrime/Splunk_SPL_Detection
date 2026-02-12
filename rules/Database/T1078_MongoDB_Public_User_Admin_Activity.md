# MongoDB Role/User Modification from Public IP

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DB-002` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects administrative actions (`dropRole`, `createRole`, `createUser`, `dropUser`) performed from a Public IP address (i.e., NOT a private RFC1918 address). Administrative tasks should typically originate from internal jump hosts or VPNs.

**Logic:**
1.  Filters for high-privilege `atype` events.
2.  Excludes private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
3.  Any remaining source usage is considered "Public".

## 🔍 SPL Query
```spl
index=MongoDB atype IN (dropRole,createRole,createUser,dropUser) 
NOT (remote.ip="10.*" OR remote.ip="192.168.*" OR remote.ip="172.16.*" OR remote.ip="172.17.*" OR remote.ip="172.18.*" OR remote.ip="172.19.*" OR remote.ip="172.2*.*" OR remote.ip="172.30.*" OR remote.ip="172.31.*")
| convert ctime(_time) as Time 
| stats  
    earliest(Time) as Started 
    latest(Time) as Recent 
    values(param.user) as Dest_User 
    values(param.role) as Dest_Role 
    count 
    by users{}.user, sourcetype, atype, remote.ip
```

## 📦 Data Schema
*   **Index:** `MongoDB`
*   **Key Fields:** `atype`, `remote.ip`

## 🧪 Validation
1.  **Simulation:** Connect to MongoDB Atlas from a public internet connection (non-VPN) and create a test user.
2.  **Verify:** Confirm the source IP matches your public IP and triggers the alert.
