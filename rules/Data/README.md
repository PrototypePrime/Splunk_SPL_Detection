# Data Detections

Detection rules for data loss prevention (DLP) and exfiltration.

## 🎯 What Goes Here
- Large file uploads
- Mass data downloads
- USB device usage
- Sensitive data access (PII/PCI)
- Cloud storage exfiltration

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1048** | Exfiltration Over Alternative Protocol | FTP, SSH exfil |
| **T1567** | Exfiltration Over Web Service | Upload to Dropbox/Drive |
| **T1020** | Automated Exfiltration | Scripts to steal data |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-DATA-001` | [Large Data Upload to External IP (>500MB)](T1048_Large_Data_Upload.md) | T1048 | MEDIUM |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
