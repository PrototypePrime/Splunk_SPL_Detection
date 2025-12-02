# Cloud Detections

Detection rules for cloud platform security (AWS, Azure, GCP, O365).

## What Goes Here

- Cloud misconfigurations
- Privilege escalation in cloud
- Unusual API activity
- Resource abuse
- Data access anomalies
- Cloud-specific persistence

## Common Techniques (MITRE)

- **T1078.004** - Cloud Accounts
- **T1580** - Cloud Infrastructure Discovery
- **T1537** - Transfer Data to Cloud Account
- **T1098** - Account Manipulation
- **T1530** - Data from Cloud Storage Object

## Quick Examples

```
# Valid detection names:
T1078_AWS_Root_Account_Usage.spl
T1098_Azure_Privilege_Escalation.kql
T1537_S3_Bucket_Exfiltration.spl
```
