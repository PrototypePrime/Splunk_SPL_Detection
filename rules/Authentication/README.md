# Authentication Detections

Detection rules for authentication and access-related attacks.

## 🎯 What Goes Here
- Brute force login attempts
- Password spray attacks
- Credential stuffing
- MFA bypass attempts
- Impossible travel
- Suspicious sign-ins
- Account takeover patterns

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1110** | Brute Force | Password guessing, spraying, stuffing |
| **T1078** | Valid Accounts | Logins with compromised or disabled accounts |
| **T1556** | Modify Authentication Process | Tampering with authentication providers |
| **T1621** | Multi-Factor Authentication Request Generation | MFA fatigue / push spam |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-AUTH-001` | [Windows Excessive Login Failures (Domain Account)](T1110_Excessive_Login_Failures.md) | T1110 | MEDIUM |
| `SPL-AUTH-002` | [Failed Login - Disabled Account](T1078_Disabled_Account_Login.md) | T1078 | MEDIUM |
| `SPL-AUTH-003` | [Password Spraying Attack](T1110_Password_Spraying.md) | T1110.003 | HIGH |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
