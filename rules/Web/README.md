# Web Detections

Detection rules for web application attacks and exploitation.

## 🎯 What Goes Here
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Web Shells
- Directory Traversal
- Remote Code Execution (RCE)

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1190** | Exploit Public-Facing Application | SQLi, RCE on web servers |
| **T1505** | Server Software Component | Web Shells |
| **T1133** | External Remote Services | Web portal abuse |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-WEB-001` | [SQL Injection Attempt Pattern](T1190_SQL_Injection.md) | T1190 | HIGH |
| `SPL-WEB-002` | [IIS Excessive 404 Requests (Scanning/Probing)](T1595_IIS_Excessive_404.md) | T1595.003 | MEDIUM |
| `SPL-WEB-003` | [Possible Cross-Site Scripting (XSS) Attack](T1190_Cross_Site_Scripting.md) | T1190 | MEDIUM |
| `SPL-WEB-004` | [Possible Web Shell Activity](T1505_Web_Shell_Activity.md) | T1505.003 | HIGH |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
