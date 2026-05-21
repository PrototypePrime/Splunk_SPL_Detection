# Possible Web Shell Activity

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-WEB-004` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects interactions with suspected Web Shells. Attackers install small scripts (PHP, ASP, JSP) on compromised web servers to maintain persistent remote access.
*   Detects high-frequency POST requests to unusually named scripts or newly dropped files.
*   Looks for telltale footprints of famous Web Shells (e.g., China Chopper, C99, B374k).

**Logic:**
*   Flags unexpected file extensions or hidden files in sensitive web directories being accessed.
*   Cross-references with `POST` methods, as web shells typically use POST to accept terminal commands.

## 🔍 SPL Query
```spl
index=* (sourcetype="*iis*" OR sourcetype="*apache*" OR sourcetype="*nginx*")
cs_method="POST"
(cs_uri_stem="*.php" OR cs_uri_stem="*.asp" OR cs_uri_stem="*.aspx" OR cs_uri_stem="*.jsp")

# Suspicious payload lengths/patterns or common web shell names
OR (cs_uri_stem="*cmd*" OR cs_uri_stem="*shell*" OR cs_uri_stem="*c99*" OR cs_uri_stem="*b374k*" OR cs_User_Agent="*chopper*")

NOT src_ip IN ("10.*", "192.168.*", "172.16.*")

# 1. Stats Aggregation
| stats 
    earliest(_time) as first_seen
    latest(_time) as last_seen
    count as request_count
    values(cs_User_Agent) as user_agents
    values(sc_status) as status_codes
    by index, src_ip, cs_uri_stem

# 3. Format
| convert ctime(first_seen) ctime(last_seen)
| table first_seen, last_seen, index, src_ip, cs_uri_stem, status_codes, user_agents, request_count
| sort - request_count
```

## 📦 Data Schema
*   **Index:** `*` (Web Servers)
*   **Sourcetype:** `*iis*`, `*apache*`, `*nginx*`
*   **Key Fields:** `cs_method`, `cs_uri_stem`

## 🧪 Validation
1.  **Simulation:** Upload a test file named `cmd.php` and run a `POST` request to it with dummy variables 3 times.
2.  **Verify:** Confirm the alert triggers on the POST requests to `cmd.php`.
