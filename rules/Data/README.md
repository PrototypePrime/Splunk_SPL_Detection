# Data Detections

Detection rules for data loss prevention (DLP) and exfiltration.

## 🎯 What Goes Here
- Large file uploads
- Mass data downloads
- USB device usage
- Sensitive data access (PII/PCI)
- Cloud storage exfiltration

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1048** | Exfiltration Over Alternative Protocol | FTP, SSH exfil |
| **T1567** | Exfiltration Over Web Service | Upload to Dropbox/Drive |
| **T1020** | Automated Exfiltration | Scripts to steal data |

## 🚀 Sample Detection
See `Sample_T1048_Large_Data_Upload.spl` for a production-ready example.
