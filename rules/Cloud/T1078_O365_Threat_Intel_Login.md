# O365 Login from Threat Intel IP

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-CLOUD-003` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies successful or failed logins to Office 365/Azure AD from IP addresses present in the Threat Intel lookup (`ip_intel`). It calculates how long ago the IP was added to the watchlist to prioritize recent indicators.

**Logic:**
1.  Enriches `ActorIpAddress` against `ip_intel` lookup.
2.  Filters for events where a `threat_key` exists (Match Found).
3.  Calculates `IOC_Added_Before_Days` to see if the threat is fresh or old.

## 🔍 SPL Query
```spl
index=o365 sourcetype="o365:management:activity" 
| lookup ip_intel ip as ActorIpAddress OUTPUT time, threat_key, description
| search threat_key=*
| eval IOC_Added_Before_Days = round(((now()-time)/60/60/24), 0)
| convert ctime(_time) as Time
| convert ctime(time) as IOCTIME
| iplocation ActorIpAddress 
| eval userPrincipalName=lower(UserId)
| table _time, Country, DeviceProperties{}.Name, DeviceProperties{}.Value, UserId, ActorIpAddress, ResultStatus, IOCTIME, IOC_Added_Before_Days, threat_key, description
| dedup Country, DeviceProperties{}.Name, DeviceProperties{}.Value, UserId, ActorIpAddress, ResultStatus
```

## 📦 Data Schema
*   **Index:** `o365`
*   **Sourcetype:** `o365:management:activity`
*   **Lookup:** `ip_intel` (Fields: `ip`, `time`, `threat_key`, `description`)

## 🧪 Validation & Tuning
**False Positives:**
*   Old threat intel indicators that have been reassigned to legitimate users (IP churn).
*   Corporate VPNs or proxies that were briefly compromised.

**Tuning:**
*   Filter out IOCs older than 90 days: `| where IOC_Added_Before_Days < 90`

**Validation Steps:**
1.  **Simulation:** Manually create a dummy entry in `ip_intel` matching your current public IP.
2.  **Verify:** Login to O365 and confirm the alert triggers.
