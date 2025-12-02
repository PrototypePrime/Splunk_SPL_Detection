# Identity Detections

Detection rules for identity and access management (IAM) threats.

## What Goes Here

- Privilege escalation
- Role/group changes
- Service account abuse
- Token theft/manipulation
- Suspicious admin activity
- Identity federation abuse
- Permission changes

## Common Techniques (MITRE)

- **T1078** - Valid Accounts (all sub-techniques)
- **T1098** - Account Manipulation
- **T1134** - Access Token Manipulation
- **T1136** - Create Account
- **T1484** - Domain Policy Modification

## Quick Examples

```
# Valid detection names:
T1098_Azure_Privilege_Escalation.kql
T1136_Suspicious_Account_Creation.spl
T1134_Token_Impersonation.xql
```
