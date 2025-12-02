# Data Detections

Detection rules for data loss prevention (DLP) and insider threats.

## What Goes Here

- Large data transfers
- Sensitive data access
- Insider threat behaviors
- Unauthorized data downloads
- USB/removable media usage
- Cloud storage exfiltration
- Database dumps

## Common Techniques (MITRE)

- **T1020** - Automated Exfiltration
- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1567** - Exfiltration Over Web Service
- **T1074** - Data Staged

## Quick Examples

```
# Valid detection names:
T1048_Large_File_Upload_to_Cloud.spl
T1020_Mass_File_Download.kql
T1567_Dropbox_Data_Exfiltration.spl
```
