# Cloud Detections

Detection rules for cloud platforms (AWS, Azure, GCP) focusing on misconfigurations and abuse.

## 🎯 What Goes Here
- Cloud account compromise
- Suspicious API calls
- Storage bucket exposure (S3, Blobs)
- Security group modifications
- Instance/VM hijacking

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1078.004** | Valid Accounts: Cloud Accounts | Compromised cloud creds |
| **T1530** | Data from Cloud Storage | S3/Blob theft |
| **T1098** | Account Manipulation | IAM role changes |
| **T1496** | Resource Hijacking | Crypto mining |

## 🚀 Sample Detection
See `Sample_T1078_AWS_Console_Login_Without_MFA.spl` for a production-ready example.
