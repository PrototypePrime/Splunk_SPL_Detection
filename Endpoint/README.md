# Endpoint Detections

Detection rules for host-based threats and suspicious endpoint activity.

## What Goes Here

- Suspicious process execution
- Malware behavior
- Persistence mechanisms
- Privilege escalation
- Defense evasion techniques
- Fileless attacks

## Common Techniques (MITRE)

- **T1059** - Command and Scripting Interpreter
- **T1053** - Scheduled Task/Job
- **T1547** - Boot or Logon Autostart Execution
- **T1055** - Process Injection
- **T1562** - Impair Defenses

## Quick Examples

```
# Valid detection names:
T1059_PowerShell_Encoded_Command.xql
T1053_Suspicious_Scheduled_Task.spl
T1055_Process_Injection.kql
```
