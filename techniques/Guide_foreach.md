# SPL Technique: foreach

## 💡 Overview
The `foreach` command allows you to run a template search across multiple fields or multiple values within a single field. It acts like a loop, applying an `eval` or other supported command iteratively.

## 🛠️ Usage Scenario
Use `foreach` when you have multiple fields that need the exact same transformation (e.g., converting multiple epoch time fields into human-readable strings, or nullifying empty strings across all fields).

## 🔍 Examples

### Example 1: Formatting Multiple Time Fields
Suppose your data has `start_time`, `end_time`, and `creation_time` all as epoch numbers.
```spl
index=network
| foreach *time 
    [ eval <<FIELD>> = strftime(<<FIELD>>, "%Y-%m-%d %H:%M:%S") ]
```
*   **Explanation:** `<<FIELD>>` is a dynamic placeholder representing the current field being processed (e.g., `start_time`, then `end_time`).

### Example 2: Handling Null/Empty Values Globally
Replacing the string `"null"` or empty strings with actual Splunk nulls.
```spl
index=app
| foreach * 
    [ eval <<FIELD>> = if('<<FIELD>>' == "null" OR '<<FIELD>>' == "", null(), '<<FIELD>>') ]
```

### Example 3: Masking Sensitive Data across fields
If you need to mask IP addresses in any field that ends in `_ip`.
```spl
index=firewall
| foreach *_ip 
    [ eval <<FIELD>> = replace('<<FIELD>>', "\d+\.\d+\.\d+\.\d+", "XXX.XXX.XXX.XXX") ]
```

## ⚠️ Best Practices
1.  **Quoting:** Notice the difference between `<<FIELD>>` (evaluates to the field name) and `'<<FIELD>>'` (evaluates to the *value* of the field). If your field name has spaces or characters, use single quotes around the value.
2.  **Performance:** While `foreach` is convenient for writing SPL, running it over highly varied wildcard fields (e.g., `foreach *`) on massive datasets can be CPU intensive.
