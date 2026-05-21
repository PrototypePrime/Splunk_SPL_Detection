# SPL Technique: fieldsummary

## 💡 Overview
The `fieldsummary` command calculates summary statistics for all fields (or a specified list of fields) in your search results. It is incredibly useful for data exploration, understanding schema structures, and identifying data quality issues (like null values).

## 🛠️ Usage Scenario
You should use `fieldsummary` when you are exploring a new sourcetype, trying to understand which fields are populated, or need a quick profile of the data distribution.

## 🔍 Examples

### Example 1: Basic Data Profiling
Generates a summary of all fields available in the Windows Security Event Log.
```spl
index=windows sourcetype="WinEventLog:Security" | head 1000
| fieldsummary
```
*   **Result:** Outputs a table showing each field name, the total count of events containing it, the number of distinct values (`distinct_count`), whether it's numeric (`is_exact`), and a JSON array of the most common values (`values`).

### Example 2: Filtering the Summary Output
Sometimes the JSON array `values` is hard to read. You can extract the top value or format it.
```spl
index=* | head 500
| fieldsummary maxvals=5
| mvexpand values
| spath input=values
```
*   **Explanation:** `maxvals=5` limits the distinct values collected to 5. `spath` parses the JSON output so you can clearly see the `value` and its `count`.

## ⚠️ Best Practices
1.  **Use with `head` or `samplings`:** Running `fieldsummary` on millions of events can be extremely slow and memory-intensive. Always use `| head 10000` or search sampling when exploring.
2.  **Combine with `table`:** If you are building a dashboard to show data coverage, you can filter the output: `| table field, count, distinct_count`
