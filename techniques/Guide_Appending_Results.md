# Technique: Appending Results (append)

## ⚡ The Concept
Sometimes you need to combine results from two **completely different searches** that don't share common fields. This is where **`append`** shines.

---

## 🔗 Basic Append
New results are added as *new rows* at the bottom of the table.

**Scenario:** Compare "Today's Errors" vs "Yesterday's Errors".
```spl
# Search 1: Today
index=web status=500 earliest=@d
| stats count as Today_Errors
| eval type="Today"

# Search 2: Yesterday
| append [ 
    search index=web status=500 earliest=-1d@d latest=@d 
    | stats count as Yesterday_Errors 
    | eval type="Yesterday"
]
| table type, Today_Errors, Yesterday_Errors
```

---

## 📊 AppendCols (Side-by-Side)
New results are added as *new columns* to the existing rows. (Careful: Row alignment must match!).

**Scenario:** Add a "Baseline Average" column to your current stats.
```spl
index=network 
| stats count by dest_port

| appendcols [ 
    search index=network earliest=-30d 
    | stats avg(count) as baseline_avg by dest_port 
]
| where count > baseline_avg
```

---

## ⚠️ GOTCHAS (The "Fine Print")
1.  **Subsearch Limit:** `append` runs a subsearch, which typically creates a **50,000 row limit**. Do not use for massive datasets.
2.  **Execution Time:** Subsearches run *before* the main search, effectively doubling wait time.
3.  **Alternative:** Often, `stats` with a `timewrap` command is more efficient for time comparisons.
