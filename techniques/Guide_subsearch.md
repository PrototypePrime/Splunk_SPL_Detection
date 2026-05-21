# SPL Technique: Subsearches

## 💡 Overview
A Subsearch is a search inside another search, enclosed in square brackets `[ ]`. The subsearch runs **first**, formats its results as a logical OR/AND string, and passes that string back into the outer (main) search.

## 🛠️ Usage Scenario
Use subsearches to dynamically filter data based on the results of another dataset. For example, "Find all firewall traffic going to IPs that we saw in the threat intel index yesterday."

## 🔍 Examples

### Example 1: Dynamic Filtering (The "IN" equivalent)
Find Windows logins where the user also exists in the `terminated_employees.csv` lookup.
```spl
index=windows EventCode=4624 
    [ | inputlookup terminated_employees.csv | table user ]
```
*   **Execution:** The subsearch `[| inputlookup...]` runs first and generates a string like: `(user="bob") OR (user="alice")`. The main search is effectively: `index=windows EventCode=4624 (user="bob") OR (user="alice")`.

### Example 2: Excluding results (NOT in subsearch)
Find activity for all users EXCEPT administrators.
```spl
index=app_logs
NOT [ search index=identity role=admin | dedup user | table user ]
```

### Example 3: Passing multiple fields
You can pass multiple fields simultaneously.
```spl
index=firewall 
    [ search index=alerts | dedup src_ip, dest_ip | table src_ip, dest_ip ]
```
*   **Execution:** Results in `(src_ip="1.1.1.1" AND dest_ip="2.2.2.2") OR (src_ip="3.3.3.3" AND dest_ip="4.4.4.4")`.

## ⚠️ Best Practices
1.  **Formatting is crucial:** A subsearch *must* output fields that match the outer search. Always end your subsearch with `| table field1, field2` to ensure formatting.
2.  **Row Limits:** Subsearches have a hard limit of `10,000` rows by default (`format` command limits). If your subsearch returns more than 10k rows, it will truncate silently, leading to missed detections.
3.  **Optimization:** If evaluating millions of rows against a large list, using `stats` or an `inputlookup` in a `where` clause is significantly faster and doesn't hit the 10k limit.
