# SPL Technique: makeresults

## 💡 Overview
The `makeresults` command creates a specified number of empty events (or events with a dummy timestamp). It is the backbone of SPL testing, dashboard dummy data generation, and triggering custom actions without needing an actual index.

## 🛠️ Usage Scenario
Use `makeresults` when you want to unit test a custom `eval` statement, build a static lookup dynamically in a search, or trigger an alert on a schedule regardless of log data.

## 🔍 Examples

### Example 1: Testing Eval Statements
Testing how `eval` parses a string without needing real logs.
```spl
| makeresults 
| eval test_string = "DOMAIN\\Administrator"
| eval parsed_user = split(test_string, "\\")
| eval domain = mvindex(parsed_user, 0), user = mvindex(parsed_user, 1)
```

### Example 2: Generating Multiple Rows
You can generate multiple rows to create a quick mock dataset.
```spl
| makeresults count=3 
| streamstats count as row_num
| eval data = case(row_num==1, "Apple", row_num==2, "Banana", row_num==3, "Orange")
```

### Example 3: Creating a Time Series for Dashboards
Often used to generate a baseline time chart when no data exists.
```spl
| makeresults count=10 
| eval _time = _time - (random() % 86400) 
| timechart count
```

## ⚠️ Best Practices
1.  **Format usage:** `makeresults` must be the **first command** in a search, unless it is inside an `append` or `join` subsearch.
2.  **Count limit:** By default `makeresults` creates 1 event. You can specify `count=N` to create N events.
