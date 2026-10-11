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

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-END-001` | [Suspicious PowerShell Execution (Encoded/Download)](T1059_PowerShell_Execution.md) | T1059.001 | HIGH |
| `SPL-END-002` | [Suspicious PowerShell Execution - Policy Bypass](T1059_PowerShell_Execution_Bypass.md) | T1059.001 | MEDIUM |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
