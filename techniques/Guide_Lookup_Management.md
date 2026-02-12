# Technique: Automatic Lookup Management (Add/Remove)

## ⚡ The Concept
This technique demonstrates how to **programmatically update** a lookup file (e.g., a "Watchlist" or "VIP List") based on events.

---

## 🟢 1. Adding Data (Append)
**Scenario:** A user is added to a security group. We want to *add* them to `Lookup.csv`.
```spl
index=windows_AD Group_Name="Group_Name" signature="A member was added to a security-enabled * group" 
| table _time, distinguishedName
| rename distinguishedName as user
| outputlookup Lookup.csv append=true
```

---

## 🔴 2. Removing Data (Filter & Rewrite)
**Scenario:** A user is removed from a security group. We want to *remove* them from `Lookup.csv`.
```spl
| inputlookup Lookup.csv
| search NOT [ search index=wineventlog signature="A member was removed..." | fields user ]
| outputlookup Lookup.csv
```

---

## 🔄 3. Combined: Add & Remove in Single Query
**Scenario:** Execute both the "Add" and "Remove" logic in a single pipeline.

```spl
# 1. Load Current List
| inputlookup Lookup.csv

# 2. Append New Additions
| append [ 
    search index=windows_AD Group_Name="Group_Name" signature="A member was added to a security-enabled * group" 
    | table _time, distinguishedName
    | rename distinguishedName as user
]

# 3. Filter Out Removals
| search NOT [ 
    search index=wineventlog Group_Name="Group_Name" signature="A member was removed from a security-enabled * group"
    | fields user 
]

# 4. Save Final List
| table _time, user
| outputlookup Lookup.csv
```

### 🧠 Logic Flow
1.  **Load** the existing lookup (`inputlookup`).
2.  **Append** the new users found in the "Add" logs.
3.  **Filter** out any users found in the "Remove" logs (using `search NOT`).
4.  **Save** the result back to the CSV (`outputlookup`).

This linear approach is simple and effective for standard list maintenance.
