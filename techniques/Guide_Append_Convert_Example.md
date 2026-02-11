# Technique: Monthly Trend Analysis (append, convert, ctime)

## ⚡ The Concept
This guide demonstrates how to manually build a **6-month trend report** using `append` to combine separate time windows, and `convert ctime` to format timestamps into readable "Month Year" strings.

## 📝 The Scenario
You want to see the count of `Notable Alerts` for the last 6 months, broken down by month, without using `timechart` (perhaps for specific formatting or disjointed time ranges).

## 🔍 The Query
```spl
# --- Month 1 (Current Previous Month) ---
index=notable earliest=-mon@mon latest=@mon  
| convert timeformat="%B %Y" ctime(_time) as "Time" 
| stats values(Time) as Time count by search_name 

# --- Month 2 ---
| append [ 
    search index=notable earliest=-2mon@mon latest=-mon@mon 
    | convert timeformat="%B %Y" ctime(_time) as "Time" 
    | stats values(Time) as Time count by search_name 
]

# --- Month 3 ---
| append [ 
    search index=notable earliest=-3mon@mon latest=-2mon@mon 
    | convert timeformat="%B %Y" ctime(_time) as "Time" 
    | stats values(Time) as Time count by search_name 
]

# --- Month 4 ---
| append [ 
    search index=notable earliest=-4mon@mon latest=-3mon@mon 
    | convert timeformat="%B %Y" ctime(_time) as "Time" 
    | stats values(Time) as Time count by search_name 
]

# --- Month 5 ---
| append [ 
    search index=notable earliest=-5mon@mon latest=-4mon@mon 
    | convert timeformat="%B %Y" ctime(_time) as "Time" 
    | stats values(Time) as Time count by search_name 
]

# --- Month 6 ---
| append [ 
    search index=notable earliest=-6mon@mon latest=-5mon@mon 
    | convert timeformat="%B %Y" ctime(_time) as "Time" 
    | stats values(Time) as Time count by search_name 
]
```

## 🧠 Breakdown of Commands

### 1. `convert timeformat="%B %Y" ctime(_time)`
*   **Purpose:** Changes a Unix timestamp (e.g., `1695280000`) into a string like `September 2023`.
*   **`timeformat="%B %Y"`**: Specifies the output format. `%B` is full month name, `%Y` is 4-digit year.
*   **`ctime(_time)`**: The function that performs the conversion on the `_time` field.

### 2. `stats values(Time) as Time count`
*   **Purpose:** Aggregates the data.
*   **`values(Time)`**: Since we converted efficiency, `values` grabs the "September 2023" string we just made.
*   **`count`**: Counts how many events occurred in that month.

### 3. `append [...]`
*   **Purpose:** Adds the results of a subsearch to the main results.
*   **Logic:** Each `append` block runs a separate search for a specific month (e.g., `-2mon@mon` to `-mon@mon`) and adds those rows to the table.

## ⚠️ Performance Note
This approach runs **6 separate searches**. For high-volume data, consider using `timechart span=1mon` instead, which runs a single search:
```spl
index=notable earliest=-6mon@mon latest=@mon
| timechart span=1mon count by search_name
```
However, `timechart` has **limitations**:
1.  **Truncation:** By default, it only shows the Top 10 values (others become "OTHER"). You must add `limit=0` to see all.
2.  **Format:** It pivots data into **Wide Format** (Columns = Search Names), whereas the `append` method keeps **Long Format** (Rows = Month, Search Name).
    *   *If you need a row for every alert per month, `append` is better.*
