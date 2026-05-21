# Possible Cross-Site Scripting (XSS) Attack

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-WEB-003` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects possible Cross-Site Scripting (XSS) payloads in web requests. It looks for common XSS indicators (e.g., `<script>`, `onerror=`, `javascript:`, `alert()`) within the query string or specific URI parameters.

**Logic:**
*   Searches web access logs for regex patterns typically associated with XSS injects.
*   Uses `stats` to group occurrences by the source IP address to bubble up aggressive scanning or manual exploitation attempts.

## 🔍 SPL Query
```spl
index=* (sourcetype="*iis*" OR sourcetype="*apache*" OR sourcetype="*nginx*")
(cs_uri_query="*<script>*" OR cs_uri_query="*javascript:*" OR cs_uri_query="*onerror=*" OR cs_uri_query="*alert(*" OR cs_uri_query="*document.cookie*")

# 1. Negative Filter
NOT x_forwarded_for IN ("10.*", "192.168.*", "172.16.*")
NOT cs_User_Agent IN ("*Qualys*", "*Nessus*")

# 2. Extract specific payload if needed (Optional depending on log formatting)

# 3. Stats Aggregation
| rename x_forwarded_for as src_ip
| stats 
    earliest(_time) as first_seen
    latest(_time) as last_seen
    count as event_count
    values(cs_method) as method
    values(cs_uri_stem) as target_uri
    values(cs_uri_query) as xss_payloads
    by index, src_ip, sourcetype, cs_User_Agent

# 4. Format
| convert ctime(first_seen) ctime(last_seen)
| table first_seen, last_seen, index, src_ip, target_uri, method, xss_payloads, cs_User_Agent, event_count
| sort - event_count
```

## 📦 Data Schema
*   **Index:** `*` (Web Servers)
*   **Sourcetype:** `*iis*`, `*apache*`, `*nginx*`
*   **Key Fields:** `cs_uri_query`, `x_forwarded_for`

## 🧪 Validation
1.  **Simulation:** Append an XSS payload (e.g., `?q=<script>alert(1)</script>`) to a valid URL on your web server.
2.  **Verify:** Confirm the alert correctly flags the Web traffic.
