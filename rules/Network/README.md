# Network Detections

Detection rules focusing on network traffic anomalies, C2 communication, and lateral movement.

## 🎯 What Goes Here
- Command and Control (C2) beaconing
- Lateral movement (SMB, RDP, SSH)
- Data exfiltration over network
- Port scanning and reconnaissance
- Suspicious DNS queries (Tunneling, DGA)

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1071** | Application Layer Protocol | C2 over HTTP/S, DNS |
| **T1021** | Remote Services | RDP, SMB, SSH abuse |
| **T1048** | Exfiltration Over Alternative Protocol | Data theft via FTP, SSH |
| **T1568** | Dynamic Resolution | DGA domains |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-NET-001` | [High Frequency Connection to Rare Destination (Potential C2)](T1071_C2_Beaconing.md) | T1071.001 | HIGH |
| `SPL-NET-004-IN` | [Inbound Threat Intel Traffic](T1071_Threat_Intel_Inbound.md) | T1071 | MEDIUM |
| `SPL-NET-004-OUT` | [Outbound Threat Intel Traffic](T1071_Threat_Intel_Outbound.md) | T1071 | HIGH |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
