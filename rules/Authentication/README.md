# Authentication Detections

Detection rules for authentication and access-related attacks.

## What Goes Here

- Brute force login attempts
- Password spray attacks
- Credential stuffing
- MFA bypass attempts
- Impossible travel
- Suspicious sign-ins
- Account takeover patterns

## Common Techniques (MITRE)

- **T1110** - Brute Force
- **T1078** - Valid Accounts
- **T1556** - Modify Authentication Process
- **T1621** - Multi-Factor Authentication Request Generation

## Quick Examples

```
# Valid detection names:
T1110_SSH_Brute_Force.spl
T1078_Impossible_Travel.kql
T1110_Password_Spray_Detection.xql
```
