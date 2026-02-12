# IIS Excessive 404 Requests (Scanning/Probing)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-WEB-002` |
| **MITRE Tactic** | Reconnaissance / Initial Access |
| **MITRE Technique** | [T1595.003 - Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a high volume of `404 Not Found` errors (>30) from a single source IP (X-Forwarded-For) within a short window. This typically indicates:
*   **Vulnerability Scanning:** Tools like Nikto or Burp Suite looking for vulnerable files (e.g., `wp-login.php`, `.env`).
*   **Directory Busting:** Brute-forcing URL paths.

**Logic:**
*   **Stats First:** Aggregates counts *before* performing DNS lookups to improve performance.
*   **Exclusions:** Filters out Internal IPs (`10.0.0.0/8`, etc.) and Scanner accounts (`Qualys`).

## 🔍 SPL Query
```spl
index=* (sourcetype="*iis*" OR sourcetype="ms:iis:auto") 
sc_status=404 
NOT (x_forwarded_for="10.*" OR x_forwarded_for="172.16.*" OR x_forwarded_for="192.168.*") 
NOT x_forwarded_for IN ("1.2.3.4", "WhiteListed_IPs") 
NOT cs_User_Agent IN ("*Qualys*", "*Nessus*")

# 1. Aggregate FIRST (Why lookup DNS for 10,000 events when you only need the top 5?)
| rename x_forwarded_for as x_fwd_ip 
| stats 
    earliest(_time) as start_time 
    latest(_time) as end_time 
    values(s_ip) as destination_ip 
    values(cs_method) as method 
    values(cs_uri_stem) as uri_stem 
    values(cs_User_Agent) as user_agent 
    count 
    by index, x_fwd_ip

# 2. Filter Threshold
| where count > 30

# 3. Enrich (Optimized: Only runs on the few suspected IPs)
| lookup dnslookup clientip as x_fwd_ip OUTPUT clienthost as XFF_hostname 

# 4. Format
| convert ctime(start_time) ctime(end_time)
| table start_time, end_time, index, x_fwd_ip, XFF_hostname, destination_ip, method, uri_stem, user_agent, count
```

## 📦 Data Schema
*   **Index:** `*` (Web/IIS)
*   **Sourcetype:** `*iis*`
*   **Key Fields:** `sc_status`, `x_forwarded_for` (Source), `cs_uri_stem` (Target)

## 🧪 Validation
1.  **Simulation:** Use `gobuster` or a simple loop `curl` script to request 35 non-existent pages (e.g., `/test1.php`, `/test2.php`) against your IIS server.
2.  **Verify:** Alert triggers with `count >= 35`.
