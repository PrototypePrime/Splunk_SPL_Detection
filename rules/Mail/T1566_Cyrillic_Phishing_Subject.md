# Possible Phishing Mail - Cyrillic Characters

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-MAIL-002` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies emails where the Subject line contains a mix of standard characters and Cyrillic characters (Homograph Attack). Attackers use these look-alike characters to spoof legitimate domains or subjects to trick users.

**Logic:**
1.  Filters out blocked statuses (Quarantined, Spam, etc.).
2.  Uses Regex to find subjects with mixed Cyrillic content.
3.  Excludes subjects that are *purely* Cyrillic (presumed legitimate language use).

## 🔍 SPL Query
```spl
index=o365 sourcetype=o365:reporting:messagetrace 
NOT SenderAddress IN ("internal_safe_sender@domain.com") 
Status!=Resolved Status!=FilteredAsSpam Status!=Failed Status!=Quarantined 
| regex Subject="[\[External\]]?[\W\sa-zA-Z0-9]+\p{Cyrillic}+[\W\sa-zA-Z0-9]+" 
| regex Subject!="\[External\] [\p{Cyrillic}][\p{Cyrillic}]+" 
| convert ctime(_time) as Time 
| stats 
    values(Time) as Time 
    values(Subject) as Subject
    values(RecipientAddress) as RecipientAddress 
    values(Status) as Status 
    count 
    by SenderAddress
```

## 📦 Data Schema
*   **Index:** `o365`
*   **Sourcetype:** `o365:reporting:messagetrace`
*   **Key Fields:** `Subject`, `SenderAddress`, `Status`

## 🧪 Validation & Tuning
**False Positives:**
*   Legitimate communication with regions using Cyrillic scripts.
*   Marketing emails with mixed character sets.

**Tuning:**
*   Add trusted sender domains to the `NOT SenderAddress IN (...)` list.

**Validation Steps:**
1.  **Simulation:** Send an email with a subject line containing mixed Latin and Cyrillic characters (e.g., "Paypal" where the 'a' is Cyrillic 'а').
2.  **Verify:** Confirm the SPL triggers on this email.
