# Technique: Using Lookups (Enrichment & Filtering)

## ⚡ The Concept
Lookups allow you to map external data (like a CSV) to your search results. They are essential for:
1.  **Enrichment**: Adding context (e.g., "This IP belongs to HR").
2.  **Filtering**: Whitelisting or Blacklisting (e.g., "Exclude these Scanners").

---

## 📂 The Sample Data
We have created a sample file `sample_lookup.csv` in this folder:
```csv
ip,hostname,department,priority
192.168.1.10,sfo-router-01,Network,High
10.0.0.5,hr-laptop-44,HR,Low
...
```

---

## 🔍 Scenario A: Enrichment (The `lookup` command)
**Goal:** Add `department` and `priority` to your logs based on `src_ip`.

```spl
index=firewall 
| lookup sample_lookup.csv ip as src_ip OUTPUT department, priority
| table _time, src_ip, department, priority, action
```
*   **`ip as src_ip`**: Maps the CSV column (`ip`) to your event field (`src_ip`).
*   **`OUTPUT`**: Specifies which fields to bring into your events.

---

## 🛡️ Scenario B: Filtering (The `inputlookup` command)
**Goal 1: Whitelist (Exclude items in the CSV)**
Exclude known safe scanners from your alert.
```spl
index=intrusion_detection 
| search NOT [ | inputlookup sample_lookup.csv | rename ip as src_ip | fields src_ip ]
```
*   **Logic:** The subsearch `[ ... ]` returns a list of IPs like `(src_ip="192.168.1.10" OR src_ip="10.0.0.5")`. The `NOT` excludes them.

**Goal 2: Hunting (Search ONLY items in the CSV)**
Find activity involving your Critical Assets.
```spl
index=network 
| search [ | inputlookup sample_lookup.csv | where priority="Critical" | rename ip as dest_ip | fields dest_ip ]
```

---

## 🚦 Best Practices
1.  **Case Sensitivity:** Splunk lookups are case-sensitive by default. Add `case_sensitive_match=f` to the `lookup` command configuration if needed (usually in `transforms.conf`, but searchable via definitions).
2.  **Min/Max:** Use `max_matches=1` if you expect only one result, or strictly rely on the CSV structure.
3.  **Automatic Lookups:** You can configure these in Settings to run automatically, but explicit `lookup` commands (like above) are better for performance troubleshooting.
