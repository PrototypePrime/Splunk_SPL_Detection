# 📚 SPL Techniques Library

This directory contains **educational guides and recipes** for mastering Splunk Processing Language (SPL). 
Unlike the `rules/` directory (which contains detection logic), this folder focuses on **how** to use specific commands and techniques effectively.

## 🎯 Purpose
*   **Learn:** Understand complex commands like `stats`, `ctime`, and `append`.
*   **Reference:** Copy-paste patterns for string manipulation, time formatting, and math.
*   **Optimize:** Learn best practices for search efficiency.

## 📂 Content
| Guide | Description |
| :--- | :--- |
| [Stats Aggregation](Guide_Stats_Aggregation.md) | Power usage: `count`, `values`, and conditional logic. |
| [Time Formatting](Guide_Time_Formatting.md) | Using `ctime` (easy) vs `strftime` (custom). |
| [Appending Results](Guide_Appending_Results.md) | Combining searches with `append` and `appendcols`. |
| [Monthly Trend Analysis](Guide_Append_Convert_Example.md) | **Example:** 6-month trend using `append` + `convert`. |
| [Lookup Techniques](Guide_Lookups.md) | Enrichment (`lookup`) and Filtering (`inputlookup`). |
| [Lookup Management (Add/Remove)](Guide_Lookup_Management.md) | **Automated:** Programmatically add/remove rows from lookups. |
| [Threat Intel Integration](Guide_Threat_Intel_Lookup.md) | Using IOC lists and calculating "Days Since Added". |
