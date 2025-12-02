# Network Detections

Detection rules focusing on network traffic anomalies, C2 communication, and lateral movement.

## 🎯 What Goes Here
- Command and Control (C2) beaconing
- Lateral movement (SMB, RDP, SSH)
- Data exfiltration over network
- Port scanning and reconnaissance
- Suspicious DNS queries (Tunneling, DGA)

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1071** | Application Layer Protocol | C2 over HTTP/S, DNS |
| **T1021** | Remote Services | RDP, SMB, SSH abuse |
| **T1048** | Exfiltration Over Alternative Protocol | Data theft via FTP, SSH |
| **T1568** | Dynamic Resolution | DGA domains |

## 🚀 Sample Detection
See `Sample_T1071_C2_Beaconing.spl` for a production-ready example of detecting C2 beaconing patterns.
