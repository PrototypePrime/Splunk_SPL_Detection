# Suspicious PowerShell Execution (Encoded/Download)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-END-001` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | PrototypePrime |

## ⚠️ Description
Identifies PowerShell processes running with encoded commands or attempting to download content from the internet, which are common malware behaviors.

**Attack Scenario:**
1.  Attacker executes a malicious payload via PowerShell.
2.  Attacker uses `-enc` to obfuscate the command or `downloadstring` to fetch the payload from the web.
3.  Malicious code executes on the endpoint.

---

## 🔍 SPL Query
```spl
index=security sourcetype="WinEventLog:Security" EventCode=4688
| where process_name="powershell.exe" OR process_name="pwsh.exe"
| where match(process_command_line, "(?i)(-enc|-encodedcommand|downloadstring|iex|invoke-expression)")
| stats 
    count as execution_count,
    values(process_command_line) as commands,
    earliest(_time) as first_seen
    by user, dest, parent_process_name
| eval severity="HIGH"
```

---

## 📦 Data Schema
*   **Index:** `security`
*   **Sourcetype:** `WinEventLog:Security`
*   **Key Fields:** `EventCode`, `process_name`, `process_command_line`

## 🧪 Validation & Tuning
**False Positives:**
*   Admin scripts using encoded commands (rare but possible).
*   SCCM/Intune management scripts.

**Tuning:**
*   Exclude known management tools (e.g., `parent_process_name` matches `ccmexec.exe`).

**Validation Steps:**
1.  **Simulation:** Trigger the event. You can use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) for automated simulation or manually run: `powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJwBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBUAGUAcwB0ACIAJwA=`
2.  **Verify:** Confirm the SPL returns results with "HIGH" severity.
3.  **Noise:** Run against background traffic to check for FPs.

## ⏭️ Response
1.  Isolate the host immediately.
2.  Decode the base64 command to understand the payload.
3.  Check the parent process to identify the source of execution.
