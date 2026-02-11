# [Rule Name Title Case]

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-CAT-000` |
| **MITRE Tactic** | [Tactic Name] |
| **MITRE Technique** | [Txxxx - Name](https://attack.mitre.org/techniques/Txxxx/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detailed description of the detection logic. Explain *what* is being detected and *why* it is suspicious.

**Attack Scenario:**
1.  Attacker gains initial access.
2.  Attacker executes [Specific Tool].
3.  Detection fires on [Specific Event].

---

## 🔍 SPL Query
```spl
index=security sourcetype=WinEventLog:Security EventCode=4688
| search NewProcessName="*\\powershell.exe"
    AND CommandLine="*-enc*"
| stats 
    count 
    min(_time) as first_seen 
    max(_time) as last_seen 
    values(CommandLine) as commands 
    by user, dest, src_ipProcessName
| where count > 0
# -- False Positive Filtering --
# | search NOT [ inputlookup allowable_admins.csv ]
```

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `WinEventLog:Security`
*   **Key Fields:** `EventCode`, `CommandLine`, `ParentProcessName`

## 🧪 Validation & Tuning
**False Positives:**
*   List legitimate activities that might trigger this alert (e.g., Admin scripts).

**Tuning:**
*   Suggested exclusions or threshold adjustments.

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually execute the technique.
2.  **Verify:** Confirm the SPL returns results.
3.  **Noise:** Run against background traffic to check for FPs.


## ⏭️ Response
1.  Isolate the `dest` host.
2.  Review `commands` for malicious intent.
3.  Reset password for `user`.
