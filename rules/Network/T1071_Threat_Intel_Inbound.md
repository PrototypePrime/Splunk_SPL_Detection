# Inbound Threat Intel Traffic

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-NET-004-IN` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **Inbound** network traffic where the Source IP matches a known malicious IP in the `ip_intel` lookup.
**Logic:** Uses "Stats First" methodology to aggregate by Source IP before looking up Threat Intel, significantly reducing processing load.

## 🔍 SPL Query
```spl
index=firewall action=allowed (vendor_action=allow OR vendor_action=accept)
NOT (src="10.*" OR src="192.168.*" OR src="172.16.*") 
dest="10.*" OR dest="192.168.*" OR dest="172.16.*"

# 1. Aggregate FIRST (Reduce row count)
| stats 
    earliest(_time) as Earliest 
    latest(_time) as Latest 
    count 
    values(action) as action 
    dc(dest) as Dest_count 
    by src

# 2. Filter Noisy Sources
| where count > 10

# 3. Enrich (Lightweight now)
| lookup ip_intel ip as src OUTPUT time, threat_key, description
| search threat_key=*

# 4. Calculate Freshness
| eval IOC_Added_Before_Days = round(((now()-time)/86400), 0)
| where IOC_Added_Before_Days < 10

# 5. Format
| convert ctime(Earliest) ctime(Latest) ctime(time) as IOCTIME
| table Earliest, Latest, src, Dest_count, action, threat_key, description, IOCTIME, IOC_Added_Before_Days, count
```

## 📦 Data Schema
*   **Index:** `firewall`
*   **Lookup:** `ip_intel`

## 🧪 Validation
1.  **Simulation:** Add a public IP (e.g., 8.8.8.8) to your `ip_intel.csv` temporarily.
2.  **Traffic:** Generate traffic *from* that IP (or simulate logs).
3.  **Verify:** Confirm the rule triggers.
