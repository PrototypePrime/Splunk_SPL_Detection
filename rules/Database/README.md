# Database Detections

Detection rules for database platforms (MongoDB Atlas, MSSQL, Oracle) focusing on privileged changes and destructive actions.

## 🎯 What Goes Here
- Database / collection drops
- User and role creation or deletion
- Privileged actions from untrusted networks
- Mass data reads or modifications
- Audit configuration tampering

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1485** | Data Destruction | Dropping databases or collections |
| **T1136** | Create Account | Backdoor database users |
| **T1098** | Account Manipulation | Role and privilege changes |
| **T1531** | Account Access Removal | Mass user or role drops |
| **T1078** | Valid Accounts | Admin actions with stolen credentials |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-DB-001` | [MongoDB Database Drop](T1485_MongoDB_Database_Drop.md) | T1485 | CRITICAL |
| `SPL-DB-002` | [MongoDB Role/User Modification from Public IP](T1078_MongoDB_Public_User_Admin_Activity.md) | T1078 | HIGH |
| `SPL-DB-003` | [MongoDB Excessive Role Drops](T1098_MongoDB_Excessive_Role_Drops.md) | T1098 | MEDIUM |
| `SPL-DB-004` | [MongoDB Excessive User Drops](T1531_MongoDB_Excessive_User_Drops.md) | T1531 | MEDIUM |
| `SPL-DB-005` | [MongoDB Excessive Role Creations](T1098_MongoDB_Excessive_Role_Creations.md) | T1098 | MEDIUM |
| `SPL-DB-006` | [MongoDB Excessive User Creations](T1136_MongoDB_Excessive_User_Creations.md) | T1136 | MEDIUM |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
