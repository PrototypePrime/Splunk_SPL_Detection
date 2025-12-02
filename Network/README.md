# Network Detections

Detection rules for network-based threats and suspicious traffic patterns.

## What Goes Here

- Command & Control (C2) beaconing
- Lateral movement
- Port scanning
- DNS tunneling
- Data exfiltration over network
- Suspicious connections

## Common Techniques (MITRE)

- **T1071** - Application Layer Protocol (C2)
- **T1021** - Remote Services (Lateral Movement)
- **T1090** - Proxy
- **T1048** - Exfiltration Over Alternative Protocol
- **T1046** - Network Service Scanning

## Quick Examples

```
# Valid detection names:
T1071_C2_Beaconing_Detection.spl
T1021_RDP_Lateral_Movement.xql
T1048_DNS_Exfiltration.kql
```
