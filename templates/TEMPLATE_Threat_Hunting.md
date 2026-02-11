# [Hunt Name Title Case]

## 🎯 Hypothesis
**Hypothesis:** [e.g., "Adversaries are using rare LOLBins to evade detection."]
**Goal:** [What are we trying to find?]
**Scope:** [Timeframe, specific subnets, specific host groups]

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-HUNT-000` |
| **MITRE Tactic** | [Tactic Name] |
| **MITRE Technique** | [Txxxx - Name](https://attack.mitre.org/techniques/Txxxx/) |
| **Status** | Development |
| **Author** | Mathan Subbiah |

## 🔬 Hunt Logic
```spl
# Step 1: Broad Search
index=security sourcetype=WinEventLog:Security EventCode=4688
| where _time >= relative_time(now(), "-7d")

# Step 2: Filter Known Good (The "Noise")
| search NOT (NewProcessName IN ("*\\svchost.exe", "*\\explorer.exe"))

# Step 3: Look for Outliers / Rare Events
| stats count values(CommandLine) as cmds by NewProcessName
| where count < 5  # Rare execution frequency

# Step 4: Investigate
| sort count asc
| table NewProcessName, count, cmds
```

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `WinEventLog:Security`

## 🧪 Validation & Tuning
**Known False Positives:**
*   Rare admin tools used for maintenance.

**Validation Steps:**
1.  **Simulation:** Trigger the anomalous behavior. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate realistic logs or manually execute the technique.
2.  **Verify:** Confirm the query captures the event as an outlier.
3.  **Noise:** Ensure normal baseline activity is filtered out.
