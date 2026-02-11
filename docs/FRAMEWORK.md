# Detection Engineering Framework

This document defines the standards and practices for the Splunk SPL Detection Library. It serves as a reference for creating high-fidelity, maintainable, and performant detections.

*   For a technical guide on **how** to create rules (log analysis, SPL development), see the [Detection Development Lifecycle](DETECTION_LIFECYCLE.md).

## 1. Detection Strategy (Severity Levels)

We categorize threats based on their potential impact and the urgency of response required.

| Severity | Definition | Response SLA | Example |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Confirmed malicious activity with high impact. Immediate action required. | < 1 Hour | Domain Admin account creation, Ransomware execution. |
| **HIGH** | Likely malicious activity with significant impact. Investigation required ASAP. | < 4 Hours | Brute force success, Mimikatz usage. |
| **MEDIUM** | Suspicious behavior that requires context. Batch review acceptable. | < 24 Hours | Unusual PowerShell usage, Port scanning. |
| **LOW** | Informational events or policy violations. Used for trending/hunting. | Weekly | New service installation, User added to local admin. |

## 2. Naming Convention

All detection files and rule names must follow this standard to ensure consistency and easy searching.

**File Name:** `Category/Txxxx_Name.md`
*   `Category`: The folder name (e.g., `Authentication`, `Endpoint`).
*   `Txxxx`: The primary MITRE ATT&CK Technique ID.
*   `Name`: Descriptive title (Snake Case).
*   **Format:** All files must be Markdown (`.md`) using the [Standard Alert Template](../templates/TEMPLATE_Standard_Alert.md).

**Example:** `Authentication/T1110_Brute_Force.md`



## 3. coding Standards (SPL)

To ensure performance and readability, all queries must adhere to these rules:

### 3.1 Base Search Optimization
*   **ALWAYS** specify `index` and `sourcetype` as the very first command.
*   **NEVER** use `index=*` or leave the index empty.


### 3.2 Recommended Field Naming (Best Practice)
While we do not strictly enforce the Common Information Model (CIM), using standard field names is a good practice for consistency:
*   Use `dest` for destination systems.
*   Use `src` or `src_ip` for source systems.
*   Use `user` for identities.

### 3.3 Formatting
*   Use pipes `|` on new lines for readability.

*   Comment your code using macros or inline comments if the logic is complex.

## 4. Tuning & Exclusions
Every rule must include a comment block suggesting where to add exclusions. We do not hardcode exclusions (like `dest!=host1`) in the main logic unless it is a universal standard (e.g., `user!=system`).

**Standard Exclusion Pattern:**
```spl
...
| where count > 5
# -- Exclusions --
# | search NOT [ inputlookup allowable_admins ]
# ----------------
```
