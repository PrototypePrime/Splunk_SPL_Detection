# [Metric] Anomaly Detection

## 🧪 Methodology
**Type:** Statistical Baseline Deviation (Z-Score)
**Description:** Detects deviations > 3 standard deviations from the baseline.
**Baseline Period:** 30 days
**Analysis:** Every hour in the selected time range is scored against the hourly baseline (schedule hourly over the last hour; widen the range to hunt retroactively).
**Coverage Gap:** Sources with no baseline yet (new hosts) are skipped — cover them with a First-Seen rule.

## 📊 Logic
### 1. Baseline Calculation
Run this query daily/weekly over the baseline period (time range: last 30 days, set in the time picker / schedule) to update the lookup file.
```spl
index=network sourcetype=firewall
| bin _time span=1h
| stats sum(bytes_out) as total_bytes by _time, src_ip
| stats
    avg(total_bytes) as avg_bytes
    stdev(total_bytes) as stdev_bytes
    count as sample_hours
    by src_ip
| outputlookup network_baseline.csv
```

### 2. Detection Query
Run this query hourly (time range: last 1 hour, set in the schedule). Because it scores each hour separately, it also works over longer ranges for retroactive hunting.
````spl
index=network sourcetype=firewall

```1. Hourly volume per source (same unit as the baseline, works for any time range)```
| bin _time span=1h
| stats sum(bytes_out) as current_bytes by _time, src_ip

```2. Attach the baseline (require at least 24 hourly samples)```
| lookup network_baseline.csv src_ip OUTPUT avg_bytes, stdev_bytes, sample_hours
| where isnotnull(avg_bytes) AND sample_hours >= 24

```3. Z-Score (stdev floored at 10% of the average so stable hosts don't alert on tiny changes)```
| eval z_score = round((current_bytes - avg_bytes) / max(stdev_bytes, avg_bytes * 0.1, 1), 2)

```4. Filter for Anomalies (> 3 sigma)```
| where z_score > 3

```5. Format```
| eval current_mb = round(current_bytes / 1024 / 1024, 2), avg_mb = round(avg_bytes / 1024 / 1024, 2)
| convert ctime(_time) as hour
| table hour, src_ip, current_mb, avg_mb, sample_hours, z_score
| sort - z_score
````

## ⚙️ Baseline Setup (One-Time)
1.  **Create it:** Run the Baseline query once with the time picker set to *Last 30 days*. `outputlookup` creates `network_baseline.csv` in the current app's lookups.
2.  **Check it:** `| inputlookup network_baseline.csv` should return one row per `src_ip` with `avg_bytes`, `stdev_bytes`, and `sample_hours`.
3.  **Keep it fresh:** Save the Baseline query as a **scheduled report** (e.g., daily at 01:00, time range *Last 30 days*). Each run overwrites the file with an up-to-date 30-day picture.
4.  **Schedule the detection:** Save the Detection query as an **alert / correlation search** (e.g., hourly, time range *last 1 hour*). The baseline must exist before the first detection run.
5.  **Share it:** If the detection runs in a different app (e.g., Enterprise Security), set the lookup file's permissions to *Global* (Settings → Lookups → Lookup table files).
6.  **How `sample_hours` works:** The baseline counts how many hours each `src_ip` had traffic (`count as sample_hours`). The detection only scores hosts with at least 24 active hours, because an average built from a handful of hours is unreliable. Tune the minimum to your environment.
