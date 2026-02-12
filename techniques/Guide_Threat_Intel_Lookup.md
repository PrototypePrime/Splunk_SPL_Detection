# Technique: Using Threat Intel Lookups (ES & Custom)

## ⚡ The Concept
Splunk Enterprise Security (ES) comes with a built-in Threat Intelligence Framework. It aggregates feeds into standard KV Store lookups. This guide shows how to query these default collections for IPs, Files, and Domains.

---

## 🏛️ Standard ES Collections
If you have Splunk ES, these are the default lookups populated by your threat feeds:
| Type | Lookup Name | Key Fields |
| :--- | :--- | :--- |
| **IP** | `ip_intel` | `ip`, `threat_key`, `weight`, `description` |
| **File** | `file_intel` | `file_hash`, `file_name`, `threat_key` |
| **Domain/URL** | `http_intel` | `url`, `domain`, `threat_key` |

---

## 🔍 Examples by IOC Type

### 1. IP Address (Network Traffic)
**Goal:** Detect connections to known malicious IPs.
```spl
index=firewall action=allowed
| lookup ip_intel ip as dest_ip OUTPUT threat_key, description, weight
| search threat_key=*
| table _time, src_ip, dest_ip, threat_key, description
```

### 2. File Hash (Endpoint/AV)
**Goal:** Detect execution of known malware hashes (MD5, SHA1, SHA256).
```spl
index=sysmon EventCode=1 
| lookup file_intel file_hash as Hash OUTPUT threat_key, file_name, description
| search threat_key=*
| table _time, host, Image, Hash, threat_key
```

### 3. Domain Name (DNS/Web)
**Goal:** Detect queries to known C2 domains.
```spl
index=dns 
| lookup http_intel domain as query OUTPUT threat_key, weight
| search threat_key=* 
| table _time, src_ip, query, threat_key
```

---

## 🧮 Calculating IOC Age (Freshness)
To prioritize *recent* indicators, you can calculate the "Days Since Added" if your feed provides a timestamp (often `time` or `added_time`).

```spl
...
| lookup ip_intel ip as dest_ip OUTPUT time
| eval IOC_Added_Before_Days = round(((now()-time)/60/60/24), 0)
| where IOC_Added_Before_Days < 30  # Only fire on recent intel
```

---

## 🚀 Pro Tip: Custom Feeds
If you don't have ES, you can replicate this by creating simple CSV lookups (`ip_intel.csv`, `http_intel.csv`) and strictly following the [CIM Threat Intelligence](https://docs.splunk.com/Documentation/CIM/latest/User/ThreatIntelligence) naming conventions.
