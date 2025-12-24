# Identity Detections

Detection rules for identity and access management (IAM) abuse.

## 🎯 What Goes Here
- Privilege escalation
- New account creation
- Group membership changes
- Token theft/manipulation
- Service account abuse

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1098** | Account Manipulation | Adding user to Domain Admins |
| **T1078** | Valid Accounts | Abuse of existing creds |
| **T1136** | Create Account | Persistence via new user |

## 🚀 Sample Detection
See `Sample_T1098_Privileged_Group_Modification.spl` for a production-ready example.

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
