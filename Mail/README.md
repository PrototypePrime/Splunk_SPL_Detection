# Mail/Email Detections

Detection rules for email-based threats and phishing attacks.

## What Goes Here

- Phishing campaigns
- Business Email Compromise (BEC)
- Malicious attachments
- Email forwarding rules (auto-forward abuse)
- Spoofed sender detection
- Suspicious email links
- Large volume email sends

## Common Techniques (MITRE)

- **T1566** - Phishing (all sub-techniques)
- **T1534** - Internal Spearphishing
- **T1114** - Email Collection
- **T1087** - Email Account Discovery
- **T1598** - Phishing for Information

## Quick Examples

```
# Valid detection names:
T1566_Phishing_With_Malicious_Attachment.spl
T1114_Suspicious_Email_Forwarding_Rule.kql
T1566_CEO_Fraud_BEC.spl
```
