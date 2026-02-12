# Outbound Threat Intel Traffic

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-NET-004-OUT` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **Outbound** network traffic where the Destination IP matches a known malicious IP in the `ip_intel` lookup. This is indicative of C2 beaconing or data exfiltration.
**Logic:** Uses "Stats First" methodology to aggregate by Destination IP before enrichment.

## 🔍 SPL Query
```spl
index=firewall action=allowed (vendor_action=allow OR vendor_action=accept)
(src="10.*" OR src="192.168.*" OR src="172.16.*") 
NOT (dest="10.*" OR dest="192.168.*" OR dest="172.16.*")

# 1. Negative Filter (Whitelist)
| search NOT [| inputlookup threat_intel_whitelist_out.csv | fields dest]

# 2. Aggregate FIRST
| stats 
    earliest(_time) as Earliest 
    latest(_time) as Latest 
    count 
    values(src) as Src_Hosts 
    values(action) as action 
    by dest

# 3. Filter Low Frequency (Optimization)
| where count > 10

# 4. Enrich
| lookup ip_intel ip as dest OUTPUT time, threat_key, description
| search threat_key=*

# 5. DNS & Age Calculation
| lookup dnslookup clientip as dest OUTPUT clienthost as Dest_Resolved
| eval IOC_Added_Before_Days = round(((now()-time)/86400), 0)
| where IOC_Added_Before_Days < 10 

# 6. Format
| convert ctime(Earliest) ctime(Latest) ctime(time) as IOCTIME
| table Earliest, Latest, dest, Dest_Resolved, Src_Hosts, action, threat_key, description, IOCTIME, IOC_Added_Before_Days, count
```

## 📦 Data Schema
*   **Index:** `firewall`
*   **Lookup:** `ip_intel`, `dnslookup`

## 🧪 Validation
1.  **Simulation:** Add a public IP (e.g., 1.1.1.1) to your `ip_intel.csv`.
2.  **Traffic:** Ping that IP from an internal host.
3.  **Verify:** Confirm the rule triggers.
