# High Frequency Connection to Rare Destination (Potential C2)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-NET-001` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | [T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | PrototypePrime |

## ⚠️ Description
Identifies internal hosts making frequent, periodic connections to external IPs that are rare in the environment, indicative of C2 beaconing.

**Attack Scenario:**
1.  Malware on an infected host establishes a C2 channel.
2.  Malware sends "heartbeat" signals (beacons) to the C2 server at regular intervals.
3.  Network traffic shows high frequency connection to a single external IP.

---

## 🔍 SPL Query
```spl
index=network sourcetype=firewall action=allowed
| bin _time span=5m
| stats count as conn_count by src_ip, dest_ip, dest_port
| eventstats sum(conn_count) as total_conns by src_ip
| where conn_count > 10 AND total_conns > 100
| stats 
    dc(src_ip) as unique_sources,
    values(src_ip) as infected_hosts,
    sum(conn_count) as total_beacons
    by dest_ip, dest_port
| where unique_sources < 5  # Rare destination (few hosts talking to it)
| eval severity="HIGH"
```

---

## 📦 Data Schema
*   **Index:** `network`
*   **Sourcetype:** `firewall`
*   **Key Fields:** `src_ip`, `dest_ip`, `dest_port`, `action`

## 🧪 Validation & Tuning
**False Positives:**
*   NTP servers.
*   Software update services.
*   Cloud telemetry endpoints.

**Tuning:**
*   Exclude known safe subnets (e.g., `cidrmatch("10.0.0.0/8", dest_ip)`).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or use a tool like 'caldera' or a simple python script to send HTTP requests every 5 seconds to an external IP.
2.  **Verify:** Confirm the SPL returns results identifying the source IP and the external C2 IP.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Identify the process making the connections on the source host.
2.  Block the destination IP at the firewall.
3.  Isolate the infected host.
