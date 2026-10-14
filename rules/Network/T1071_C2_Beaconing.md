# High Frequency Connection to Rare Destination (Potential C2)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-NET-001` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | [T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies internal hosts making frequent, periodic connections to external IPs that are rare in the environment, indicative of C2 beaconing.

**Attack Scenario:**
1.  Malware on an infected host establishes a C2 channel.
2.  Malware sends "heartbeat" signals (beacons) to the C2 server at regular intervals.
3.  Network traffic shows high frequency connection to a single external IP.

**Logic:**
*   Flags an internal machine that contacts an outside address **often** (more than 10 connections), **like clockwork** (the gaps between connections hardly vary, `jitter` below 0.2), and that **few other machines visit** (fewer than 5).
*   Step-by-step explanation with a worked example: [streamstats guide, Example 4](../../techniques/Guide_streamstats.md#example-4-clockwork-detection-malware-phoning-home).

---

## 🔍 SPL Query
````spl
index=network sourcetype=firewall action=allowed
(src_ip="10.0.0.0/8" OR src_ip="172.16.0.0/12" OR src_ip="192.168.0.0/16")
NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" OR dest_ip="192.168.0.0/16")

```1. Time between consecutive connections (events arrive newest first)```
| streamstats current=f last(_time) as next_time by src_ip, dest_ip, dest_port
| eval interval = next_time - _time

```2. Per-pair frequency and regularity```
| stats
    count as conn_count
    avg(interval) as avg_interval
    stdev(interval) as stdev_interval
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by src_ip, dest_ip, dest_port

```3. Rarity: how many internal hosts talk to this destination at all```
| eventstats dc(src_ip) as unique_sources by dest_ip, dest_port

```4. Beacon thresholds: frequent, regular (low jitter), rare destination```
| eval jitter = round(stdev_interval / avg_interval, 2)
| where conn_count > 10 AND jitter < 0.2 AND unique_sources < 5

```5. Format```
| eval avg_interval_sec = round(avg_interval, 0)
| convert ctime(first_seen) ctime(last_seen)
| rename src_ip as infected_host, conn_count as total_beacons
| table first_seen, last_seen, infected_host, dest_ip, dest_port, total_beacons, avg_interval_sec, jitter, unique_sources
| sort + jitter
````

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
*   Traffic between internal machines is already left out.
*   Add known update and telemetry destinations (e.g. Windows Update, antivirus cloud services) to an exclusion lookup.
*   Adjust the three thresholds to your network: more than 10 connections, timing messiness (`jitter`) below 0.2, and fewer than 5 internal machines talking to the destination.

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or use a tool like 'caldera' or a simple python script to send HTTP requests every 5 seconds to an external IP.
2.  **Verify:** Confirm the SPL returns results identifying the source IP and the external C2 IP.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Identify the process making the connections on the source host.
2.  Block the destination IP at the firewall.
3.  Isolate the infected host.
