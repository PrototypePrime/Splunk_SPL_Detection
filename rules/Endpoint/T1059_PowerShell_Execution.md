# Suspicious PowerShell Execution (Encoded/Download)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-END-001` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies PowerShell processes running with encoded commands or attempting to download content from the internet, which are common malware behaviors.

**Attack Scenario:**
1.  Attacker executes a malicious payload via PowerShell.
2.  Attacker uses `-enc` to obfuscate the command or `downloadstring` to fetch the payload from the web.
3.  Malicious code executes on the endpoint.

---

## 🔍 SPL Query
````spl
index=security sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4688
NewProcessName IN ("*\\powershell.exe", "*\\pwsh.exe")

```1. Encoded command or download/execute cradle```
| where match(CommandLine, "(?i)(\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer|\biex\b|invoke-expression)")

```2. Stats Aggregation```
| stats
    count as execution_count
    values(CommandLine) as commands
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by SubjectUserName, Computer, ParentProcessName

```3. Format```
| convert ctime(first_seen) ctime(last_seen)
| rename SubjectUserName as user, Computer as dest, ParentProcessName as parent_process_name
| sort - execution_count
````

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **Key Fields:** `NewProcessName` (the program started), `CommandLine` (the full command typed), `ParentProcessName` (the program that started it), `SubjectUserName` (output as `user`), `Computer` (output as `dest`)

## 🧪 Validation & Tuning
**False Positives:**
*   Admin scripts using encoded commands (rare but possible).
*   SCCM/Intune management scripts.

**Tuning:**
*   Exclude known management tools (e.g., `parent_process_name` matches `ccmexec.exe`).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually run: `powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJwBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBUAGUAcwB0ACIAJwA=`
2.  **Verify:** Confirm the SPL returns the host (`dest`), the user and the full command line in `commands`.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Isolate the host immediately.
2.  Decode the base64 command to understand the payload.
3.  Check the parent process to identify the source of execution.
