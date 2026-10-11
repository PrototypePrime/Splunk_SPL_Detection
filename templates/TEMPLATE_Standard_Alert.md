# [Rule Name Title Case]

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-CAT-000` |
| **MITRE Tactic** | [Tactic Name] |
| **MITRE Technique** | [Txxxx - Name](https://attack.mitre.org/techniques/Txxxx/) |
| **Severity** | [CRITICAL / HIGH / MEDIUM / LOW] — see [Framework §1](../docs/FRAMEWORK.md#1-detection-strategy-severity-levels) |
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
````spl
index=security sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4688
NewProcessName="*\\powershell.exe" CommandLine="*-enc*"

```1. Stats Aggregation```
| stats
    count
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(CommandLine) as commands
    values(ParentProcessName) as parent_process
    by SubjectUserName, Computer

```2. Threshold Filter (tune per baseline)```
| where count > 0

```3. Format```
| convert ctime(first_seen) ctime(last_seen)
| table first_seen, last_seen, Computer, SubjectUserName, parent_process, commands, count
| sort - count

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup allowable_admins.csv | fields SubjectUserName ]```
````

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **Key Fields:** `EventCode`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`, `Computer`

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
1.  Isolate the `Computer` host.
2.  Review `commands` for malicious intent.
3.  Reset password for `SubjectUserName`.
