# Alerting and Detection Strategy (ADS) Framework

**Goal:** Provide a standardized framework for documenting detections, ensuring clarity, maintainability, and peer review capability.
**Based on:** Palantir's ADS Framework.

---

## 1. Goal
*What is the objective of this detection? What threat are we trying to catch?*

## 2. Categorization
* **MITRE ATT&CK Mapping:**
    * Tactic: [e.g., Execution]
    * Technique: [e.g., T1059 - Command and Scripting Interpreter]
* **Severity:** [Low/Medium/High/Critical]
* **Status:** [Development/Production/Deprecated]

## 3. Strategy Abstract
*High-level explanation of how the detection works. Avoid technical jargon if possible.*
*Example: "This rule monitors for the execution of PowerShell with encoded commands, which is a common technique used to obfuscate malicious scripts."*

## 4. Technical Context
*Detailed technical explanation. Why does this event occur? What logs are generated?*

## 5. Blind Spots and Assumptions
* **Blind Spots:** *What will this rule MISS? (e.g., "Will not detect encoded commands if they are decoded before execution logging.")*
* **Assumptions:** *What must be true for this to work? (e.g., "Assumes PowerShell Script Block Logging is enabled.")*

## 6. False Positives
*What benign activity might trigger this?*
* *Admin scripts*
* *Deployment tools*

## 7. Validation
*How was this tested?*
* **Atomic Red Team Test:** [Test ID]
* **Manual Trigger:** [Command used]

## 8. Priority and Response
* **Priority:** [High]
* **Response Playbook:**
    1. *Verify user identity.*
    2. *Decode the command string.*
    3. *Check parent process.*
