# Cloud Detections

Detection rules for cloud platforms (AWS, Azure, GCP) focusing on misconfigurations and abuse.

## 🎯 What Goes Here
- Cloud account compromise
- Suspicious API calls
- Storage bucket exposure (S3, Blobs)
- Security group modifications
- Instance/VM hijacking

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1078.004** | Valid Accounts: Cloud Accounts | Compromised cloud creds |
| **T1530** | Data from Cloud Storage | S3/Blob theft |
| **T1098** | Account Manipulation | IAM role changes |
| **T1496** | Resource Hijacking | Crypto mining |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-CLOUD-001` | [AWS Console Login Without MFA](T1078_AWS_Console_Login_Without_MFA.md) | T1078.004 | MEDIUM |
| `SPL-CLOUD-002` | [O365 AiTM Phishing Detection (Axios UA)](T1557_O365_AiTM_Phishing.md) | T1557 | HIGH |
| `SPL-CLOUD-003` | [O365 Login from Threat Intel IP](T1078_O365_Threat_Intel_Login.md) | T1078.004 | HIGH |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
