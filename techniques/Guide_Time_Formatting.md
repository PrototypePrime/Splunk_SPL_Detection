# Technique: Time Formatting (ctime & strftime)

## ⚡ The Concept
Splunk handles time as a "Unix Epoch" (seconds since 1970). To make this readable for humans (or specific systems), we use **`convert ctime`** or **`eval strftime`**.

---

## 🕒 The Easy Way (ctime)
Use `convert ctime` to quickly turn a raw timestamp into a human-readable string.

**Scenario:** You have `_time` or `indextime` and want to see it nicely.
```spl
index=web 
| convert ctime(_time) as readable_time
| table readable_time, clientip, status
```
*   **Result:** `09/21/2023 14:30:00`

---

## 🛠️ The Power Way (strftime)
Use `eval ... strftime()` when you need a *specific format* (e.g., for a filename or reporting).

**Scenario:** Extract just the "Day of Week" or "HH:MM".
```spl
index=firewall 
| eval day_of_week = strftime(_time, "%A")
| eval hour_of_day = strftime(_time, "%H")
| stats count by day_of_week, hour_of_day
```

**Common Formats:**
*   `%Y-%m-%d` -> `2023-09-21`
*   `%H:%M:%S` -> `14:30:00`
*   `%A` -> `Thursday`

---

## 📅 The Reverse (strptime)
If you have a string (e.g., from a CSV) and need to turn it *back* into a timestamp for math.
```spl
| eval epoch_time = strptime(timestamp_string, "%Y-%m-%d %H:%M:%S")
```
