# [Metric] Anomaly Detection

## 🧪 Methodology
**Type:** Statistical Baseline Deviation (Z-Score / IQR)
**Description:** Detects deviations > 3 standard deviations from the baseline.
**Baseline Period:** 30 days
**Analysis Period:** 1 hour

## 📊 Logic
### 1. Baseline Calculation
Run this query daily/weekly to update the lookup file.
```spl
index=network
| bin _time span=1h
| stats sum(bytes_out) as total_bytes by _time, src_ip
| stats avg(total_bytes) as avg_bytes stdev(total_bytes) as stdev_bytes by src_ip
| outputlookup network_baseline.csv
```

### 2. Detection Query
Run this query hourly to detect anomalies.
```spl
index=network earliest=-1h
| stats sum(bytes_out) as current_bytes by src_ip
| lookup network_baseline.csv src_ip OUTPUT avg_bytes, stdev_bytes
| where isnotnull(avg_bytes)

# Calculate Z-Score
| eval z_score = (current_bytes - avg_bytes) / stdev_bytes

# Filter for Anomalies (e.g., > 3 sigma)
| where z_score > 3
| table src_ip, current_bytes, avg_bytes, stdev_bytes, z_score
| sort - z_score
```
