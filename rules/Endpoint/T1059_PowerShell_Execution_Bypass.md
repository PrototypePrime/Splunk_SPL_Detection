# Suspicious PowerShell Execution - Policy Bypass

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-END-002` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies PowerShell processes started with flags attempting to bypass execution policies (`-executionpolicy bypass`, `-noprofile`, `-nop`). Malware often uses these flags to run unsigned scripts or avoid profile-based restrictions.

## 🔍 SPL Query
```spl
index=windows sourcetype=WinEventLog EventCode=4688 
(Process_Command_Line="*powershell*" OR New_Process_Name="*powershell.exe")
(Process_Command_Line="*executionpolicy*" OR Process_Command_Line="*bypass*" OR Process_Command_Line="*-noprofile*" OR Process_Command_Line="*-nop*")
NOT Account_Name IN ("Admin1", "System") 
NOT Process_Command_Line="*\\ApprovedScript.ps1*"

| fields _time, host, Account_Name, Process_Name, Process_ID, Process_Command_Line, New_Process_Name, New_Process_ID, Creator_Process_ID, Message 
| eval Short_Message = mvindex(split(Message, "."), 0)
| table _time, host, Account_Name, Process_Name, Process_ID, Process_Command_Line, New_Process_Name, New_Process_ID, Creator_Process_ID, Short_Message
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog`
*   **EventCode:** `4688` (Process Creation)
*   **Requirements:** Command Line Logging must be enabled (Event ID 4688 with `Process_Command_Line`).

## 🧪 Validation
1.  **Simulation:** Run `powershell.exe -ExecutionPolicy Bypass -Nop -Command "Write-Host Test"`
2.  **Verify:** Alert triggers.
