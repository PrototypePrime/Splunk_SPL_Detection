# Inbound Threat Intel Traffic

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-NET-004-IN` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **Inbound** network traffic where the Source IP matches a known malicious IP in the `ip_intel` lookup.
**Logic:**
*   First, Splunk grabs the list of known-bad IPs that were added to threat intel in the **last 10 days**.
*   It then searches the firewall logs **only for traffic from those IPs** into your internal network, instead of reading all traffic and checking it afterwards. This is much faster on a busy firewall.
*   Finally, it gives one summary line per bad IP: when it was seen, how many internal machines it reached, the threat feed it came from, and how many days ago it was added.
*   Even a single allowed connection from a known-bad IP is reported.

## 🔍 SPL Query
````spl
index=firewall action=allowed (vendor_action=allow OR vendor_action=accept)
NOT (src="10.0.0.0/8" OR src="172.16.0.0/12" OR src="192.168.0.0/16")
(dest="10.0.0.0/8" OR dest="172.16.0.0/12" OR dest="192.168.0.0/16")
[| inputlookup ip_intel
 | where (now() - time) / 86400 < 10
 | rename ip as src
 | fields src ]

```1. Aggregate (only fresh threat-intel sources reach this point)```
| stats
    earliest(_time) as Earliest
    latest(_time) as Latest
    count
    values(action) as action
    dc(dest) as Dest_count
    by src

```2. Enrich with IOC details```
| lookup ip_intel ip as src OUTPUT time, threat_key, description
| eval IOC_Added_Before_Days = round(((now()-time)/86400), 0)

```3. Format```
| convert ctime(Earliest) ctime(Latest) ctime(time) as IOCTIME
| table Earliest, Latest, src, Dest_count, action, threat_key, description, IOCTIME, IOC_Added_Before_Days, count
````

## 📦 Data Schema
*   **Index:** `firewall`
*   **Lookup:** `ip_intel` (Fields: `ip`, `time` = when the IP was added, `threat_key`, `description`)
*   **Limit:** Splunk passes at most 10,000 IPs from the threat-intel list into the search and silently drops the rest. The 10-day filter keeps the list small; if your fresh list ever grows beyond ~10,000 IPs, switch to looking up threat intel after the summary step instead.

## 🧪 Validation
1.  **Simulation:** Add a public IP (e.g., 8.8.8.8) to your `ip_intel.csv` temporarily.
2.  **Traffic:** Generate traffic *from* that IP (or simulate logs).
3.  **Verify:** Confirm the rule triggers.
