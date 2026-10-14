# Suspicious PowerShell Execution - Policy Bypass

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-END-002` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects PowerShell being started in a way that switches off its script safety setting (the *execution policy*). That setting normally stops unsigned or downloaded scripts from running, so attackers switch it off to run their own scripts freely.

**Logic:**
*   Looks for the five common ways of switching the safety setting off:
    *   The `-ExecutionPolicy Bypass` / `Unrestricted` flag, including short forms such as `-ep bypass` or `-exec bypass`.
    *   Running `Set-ExecutionPolicy Bypass` inside a command.
    *   Overriding the setting with the `PSExecutionPolicyPreference` environment variable.
    *   Changing the setting in the registry (`reg add ... ExecutionPolicy`).
    *   Piping a script straight into PowerShell (`type script.ps1 | powershell -`), which skips the file check.
*   `-NoProfile` on its own does **not** switch the safety setting off (admin tools use it all the time), so it does not trigger this rule.
*   Each hit is labelled with the method used (`bypass_method`), so the analyst can see at a glance what happened.
*   PowerShell launched from another program (e.g. `cmd /c powershell -ep bypass`) is also caught.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4688
(CommandLine IN ("*powershell*", "*pwsh*") OR NewProcessName IN ("*\\powershell.exe", "*\\pwsh.exe"))

```1. Real execution-policy bypass techniques (not just -NoProfile)```
| where match(CommandLine, "(?i)([-/](ep|ex[a-z]*)\s+(bypass|unrestricted)|executionpolicy.{0,60}(bypass|unrestricted)|psexecutionpolicypreference|\s-\s*$)")

```2. Label the technique for the analyst```
| eval bypass_method = case(
    match(CommandLine, "(?i)psexecutionpolicypreference"), "Environment variable override",
    match(CommandLine, "(?i)\breg(\.exe)?\s+add\b"), "Registry policy change",
    match(CommandLine, "(?i)set-executionpolicy"), "Set-ExecutionPolicy",
    match(CommandLine, "(?i)\s-\s*$"), "Script piped to stdin",
    1=1, "-ExecutionPolicy flag")

```3. Stats Aggregation```
| stats
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(bypass_method) as bypass_method
    values(CommandLine) as commands
    count
    by Computer, SubjectUserName, ParentProcessName

```4. Format```
| convert ctime(first_seen) ctime(last_seen)
| table first_seen, last_seen, Computer, SubjectUserName, ParentProcessName, bypass_method, commands, count
| sort - count

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup powershell_bypass_exclusions.csv | fields SubjectUserName ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4688` (Process Creation)
*   **Key Fields:** `CommandLine` (the full command typed), `NewProcessName` (the program started), `ParentProcessName` (the program that started it), `SubjectUserName` (who ran it), `Computer` (which machine)
*   **Requirements:** Command line logging must be turned on, otherwise event 4688 has no `CommandLine` to check.

## 🧪 Validation
1.  **Simulation:** Run any of: `powershell.exe -ExecutionPolicy Bypass -Command "Write-Host Test"`, `powershell -ep bypass -c "Write-Host Test"`, or `type test.ps1 | powershell -`.
2.  **Verify:** The alert triggers and `bypass_method` names the technique used.
3.  **Negative test:** `powershell -NoProfile -Command "Write-Host Test"` should **not** trigger.
