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

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-ID-001` | [User Added to Privileged Group (Domain Admins)](T1098_Privileged_Group_Modification.md) | T1098 | CRITICAL |
| `SPL-ID-005` | [Windows Excessive Password Change Activity](T1098_Excessive_Password_Change.md) | T1098 | MEDIUM |
| `SPL-ID-006` | [User Logged into Multiple Hosts (Lateral Movement)](T1078_Excessive_Host_Logins.md) | T1078 | MEDIUM |
| `SPL-ID-007` | [Windows User Account Deleted](T1531_Windows_Account_Deletion.md) | T1531 | MEDIUM |
| `SPL-ID-008` | [New User Account Added to an Admin Group Within 1 Hour](T1136_New_User_Added_To_Admin_Group.md) | T1136.002 | HIGH |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
