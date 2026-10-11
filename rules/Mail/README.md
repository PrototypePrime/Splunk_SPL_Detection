# Mail Detections

Detection rules for email-based threats, phishing, and business email compromise (BEC).

## 🎯 What Goes Here
- Phishing attempts
- Malicious attachments
- Suspicious forwarding rules
- BEC / CEO Fraud
- Mass email sending

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1566** | Phishing | Spearphishing attachments/links |
| **T1114** | Email Collection | Accessing user inboxes |
| **T1087** | Account Discovery | Email address harvesting |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-MAIL-001` | [Suspicious Email Attachment Extension](T1566_Phishing_Attachment.md) | T1566.001 | HIGH |
| `SPL-MAIL-002` | [Possible Phishing Mail - Cyrillic Characters](T1566_Cyrillic_Phishing_Subject.md) | T1566.002 | MEDIUM |
| `SPL-MAIL-003` | [O365 Sender with Mixed Delivery Status (Quarantined & Delivered)](T1566_O365_Mixed_Delivery_Status.md) | T1566 | MEDIUM |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
