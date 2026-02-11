# SQL Injection Attempt Pattern

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-WEB-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies common SQL injection patterns in web server access logs (URI or POST parameters).

**Attack Scenario:**
1.  Attacker scans a web application for vulnerabilities.
2.  Attacker injects SQL commands into a form field or URL parameter.
3.  Application executes the malicious SQL, revealing data.

---

## 🔍 SPL Query
```spl
index=web sourcetype=access_combined
| where match(uri_query, "(?i)(union select|OR 1=1|--|;|xp_cmdshell)")
| stats 
    count as attempt_count,
    values(uri_query) as payloads,
    values(clientip) as attackers
    by src_ip, dest_url
```

---

## 📦 Data Schema
*   **Index:** `web`
*   **Sourcetype:** `access_combined`
*   **Key Fields:** `uri_query`, `clientip`, `host`, `uri_path`

## 🧪 Validation & Tuning
**False Positives:**
*   Web scanners (Qualys, Nessus).
*   Poorly coded applications using SQL keywords in URLs.

**Tuning:**
*   Exclude authorized scanners (e.g., `clientip IN ("192.168.1.50")`).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or run: `curl "http://target-site/search?q=union select 1,2,3"`
2.  **Verify:** Confirm the SPL returns results showing the attacker IP and the payload.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Block the attacker IP.
2.  Identify the vulnerable URL/Application.
3.  Check if the attack was successful (e.g., 200 OK with large response size).
