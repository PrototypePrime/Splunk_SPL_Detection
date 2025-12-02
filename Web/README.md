# Web Detections

Detection rules for web application attacks and web-based threats.

## What Goes Here

- SQL injection attempts
- Cross-site scripting (XSS)
- Web shells
- Directory traversal
- Command injection
- Proxy abuse
- Suspicious user agents

## Common Techniques (MITRE)

- **T1190** - Exploit Public-Facing Application
- **T1505** - Server Software Component (Web Shell)
- **T1210** - Exploitation of Remote Services
- **T1595** - Active Scanning
- **T1133** - External Remote Services

## Quick Examples

```
# Valid detection names:
T1190_SQL_Injection_Attempt.spl
T1505_Web_Shell_Detection.xql
T1190_Directory_Traversal.kql
```
