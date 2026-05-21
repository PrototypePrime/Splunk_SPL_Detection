# SPL Technique: map

## 💡 Overview
The `map` command is used for correlated searches. It takes the results of the current search and runs a *new* search for each row, substituting values from the current row into the new search.

## 🛠️ Usage Scenario
Use `map` when you need to perform an iterative search where the parameters of the second search change based on the results of the first. Imagine "For each IP in Search A, go run Search B for that IP."

## 🔍 Examples

### Example 1: Finding subsequent activity after an alert
Search for a malware alert, then use `map` to search for all firewall logs related to that compromised host in the 5 minutes following the alert.
```spl
index=alerts signature="Malware Detected" 
| eval start_time = _time, end_time = _time + 300
| map search="search index=firewall src_ip=\"$src_ip$\" earliest=$start_time$ latest=$end_time$" maxsearches=10
```
*   **Explanation:** `$src_ip$` takes the `src_ip` field from the alerts index and injects it into the firewall search. `$start_time$` and `$end_time$` dynamically set the time window.

### Example 2: Correlating different indices without "join"
If you have a list of suspicious users, you can use `map` to find all their actions in O365.
```spl
| inputlookup suspicious_users.csv
| map search="search index=o365 user=\"$user$\" | stats count by action"
```

## ⚠️ Best Practices
1.  **Performance Cost:** `map` is inherently slow because it kicks off a *brand new search job* for every single row. If you have 100 rows, it runs 100 searches.
2.  **maxsearches Limit:** By default, `map` stops after 10 searches to prevent system overload. You can override it with `maxsearches=100`, but exercise extreme caution.
3.  **Alternative:** Whenever possible, use `stats`, `append`, or `join` instead of `map`. `map` should be the tool of last resort for deeply correlated time-window searches.
