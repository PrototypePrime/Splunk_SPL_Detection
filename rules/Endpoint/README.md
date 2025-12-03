# Endpoint Detections

Detection rules focusing on host-based threats, malware execution, and persistence mechanisms.

## 🎯 What Goes Here
- Malware execution (Ransomware, Trojans)
- Suspicious process behavior (PowerShell, CMD)
- Persistence mechanisms (Registry, Scheduled Tasks)
- Privilege escalation on endpoints
- Anti-virus/EDR tampering

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1059** | Command and Scripting Interpreter | PowerShell, CMD, Python abuse |
| **T1055** | Process Injection | Code injection into legitimate processes |
| **T1053** | Scheduled Task/Job | Persistence via scheduled tasks |
| **T1547** | Boot or Logon Autostart Execution | Registry run keys, startup folders |

## 🚀 Sample Detection
See `Sample_T1059_PowerShell_Execution.spl` for a production-ready example of detecting suspicious PowerShell activity.
