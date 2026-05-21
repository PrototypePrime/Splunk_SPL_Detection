# SPL Technique: Informational Functions

## 💡 Overview
Informational functions in Splunk (used within an `eval` or `where` command) provide metadata about the fields, evaluation types, or the state of the search. They are critical for data cleaning, type checking, and conditional logic.

## 🛠️ Usage Scenario
Use informational functions when you need to validate data types (e.g., "Is this a number or a string?"), check for null values, or determine if a field contains multiple values.

## 🔍 Key Functions & Examples

### 1. `isnull()` and `isnotnull()`
Checks if a field exists or lacks a value for a specific event.
```spl
index=web
| eval status = if(isnull(username), "Anonymous Client", "Authenticated Client")
```

### 2. `isstr()` and `isnum()`
Validates data types. Useful if a field occasionally parses as a string when you expect an integer, potentially breaking math operations.
```spl
| makeresults 
| eval test_val = "123A"
| eval validation = if(isnum(test_val), "Valid Number", "Invalid Data")
```

### 3. `typeof()`
Returns a string representing the data type of the field (`Number`, `String`, `Bool`, `Invalid`).
```spl
index=network
| eval port_type = typeof(dest_port)
```

### 4. `mvcount()`
Returns the number of values in a multi-valued field. Extremely useful for identifying arrays or grouping anomalies.
```spl
index=ad EventCode=4728 
| stats values(MemberName) as target_users by _time, GroupName
| eval targets_added = mvcount(target_users)
| where targets_added > 5
```

### 5. `cidrmatch()`
Checks if an IP address exists within a specific CIDR block.
```spl
index=firewall
| eval is_internal = if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("192.168.0.0/16", src_ip), "Yes", "No")
```
*   *(Note: While `cidrmatch` is technically a Boolean function, it is heavily used for informational validation of IP fields).*

## ⚠️ Best Practices
1.  **Handling Nulls before Math:** Always use `isnull` before applying math to a field that might be empty, as `null + 5` results in an error or drop. Use the `coalesce()` function to provide a fallback value: `eval total = coalesce(count, 0) + 5`.
2.  **Multi-value Awareness:** Use `if(mvcount(field)>1, ...)` before performing string operations on a field, as functions like `substr()` will fail on multi-value fields.
