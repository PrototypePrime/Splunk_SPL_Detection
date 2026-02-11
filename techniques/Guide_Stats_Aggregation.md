# Technique: Stats Aggregation

## ⚡ The Concept
**`stats`** is the powerhouse of Splunk. It transforms raw events into metrics. Mastering `stats` is the difference between a slow, noisy search and a fast, actionable alert.

---

## 📊 Core Functions

### 1. Counting & Distinct Count
Basic volume analysis.
```spl
index=firewall 
| stats count as total_packets, dc(src_ip) as unique_sources by dest_port
```

### 2. Grouping Values (The "List")
See all values associated with an entity without creating duplicate rows.
```spl
index=web 
| stats values(url) as visited_urls, values(user_agent) as agents by src_ip
```
*   **Note:** `values()` returns a sorted, unique list. Use `list()` if you want every raw instance (unsorted).

---

## 🧠 Advanced Stats Logic

### A. Conditional Counting
Count specific conditions within a grouped row.
```spl
index=win_logs 
| stats 
    count(eval(EventCode=4625)) as failures,
    count(eval(EventCode=4624)) as successes
    by user
| where failures > 10 AND successes > 0
```

### B. Statistical Thresholds
Detect outliers dynamically.
```spl
index=network 
| stats avg(bytes_out) as avg_bytes, stdev(bytes_out) as stdev_bytes by src_ip
| eval upper_limit = avg_bytes + (stdev_bytes * 3)
| where bytes_out > upper_limit
```
