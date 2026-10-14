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
| **T1558** | Steal or Forge Kerberos Tickets | Kerberoasting, AS-REP roasting |

## 📂 Detections
| ID | Detection | MITRE | Severity |
|----|-----------|-------|----------|
| `SPL-AUTH-001` | [Windows Excessive Login Failures (Domain Account)](T1110_Excessive_Login_Failures.md) | T1110 | MEDIUM |
| `SPL-AUTH-002` | [Failed Login - Disabled Account](T1078_Disabled_Account_Login.md) | T1078 | MEDIUM |
| `SPL-AUTH-003` | [Password Spraying Attack](T1110_Password_Spraying.md) | T1110.003 | HIGH |
| `SPL-AUTH-004` | [Brute Force Followed by Successful Logon](T1110_Brute_Force_Followed_By_Success.md) | T1110 | HIGH |
| `SPL-AUTH-005` | [Account Lockout Spike from a Single Source](T1110_Account_Lockout_Spike.md) | T1110 | MEDIUM |
| `SPL-AUTH-006` | [Kerberoasting (Weak Service Ticket Requests)](T1558_Kerberoasting.md) | T1558.003 | HIGH |
| `SPL-AUTH-007` | [AS-REP Roasting (Logon Ticket Without Pre-Authentication)](T1558_AS_REP_Roasting.md) | T1558.004 | HIGH |
| `SPL-AUTH-008` | [Impossible Travel Between Sign-ins (Entra ID)](T1078_Impossible_Travel.md) | T1078.004 | MEDIUM |
| `SPL-AUTH-009` | [MFA Fatigue (Push Notification Spam)](T1621_MFA_Fatigue.md) | T1621 | HIGH |
| `SPL-AUTH-010` | [SSH Brute Force Against Linux Servers](T1110_SSH_Brute_Force.md) | T1110.001 | MEDIUM |

File naming: `Txxxx_Descriptive_Name.md` — see the [Framework](../../docs/FRAMEWORK.md#2-naming-convention).

<!--
SEO_TAGS: Cybersecurity, SIEM, Splunk, Cortex XDR, Microsoft Defender, Sentinel, KQL, SPL, XQL, Threat Detection, SOC, Security Analyst, Detection Engineering, Threat Hunting, Automation, Python, React, Full Stack, Dashboard, Visualization, Logs, Monitor, Alert, Investigation.
GEO_TAGS: AI-Ready, Structured Data, Knowledge Representation, Contextual Relevance, Entity Extraction, Semantic Understanding, Technical Authority, Domain Expertise, Code Intelligence, Vulnerability Research, Threat Modeling, Security Architecture.
-->
