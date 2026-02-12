# O365 Sender with Mixed Delivery Status (Quarantined & Delivered)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-MAIL-003` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies external senders who have emails that were **BOTH** `Delivered` and `Quarantined` within the search window.
*   **Scenario:** An attacker sends a campaign. Some emails are caught by filters (Quarantined), but slight variations or different recipients allow others to slip through (Delivered).
*   **Goal:** Capture the ones that slipped through by pivoting on the blocked ones.

## 🔍 SPL Query
```spl
index=o365 sourcetype="o365:reporting:messagetrace" 
NOT SenderAddress IN ("*@internal.domain.com", "safe_sender@partner.com") 
Status IN ("Delivered", "Quarantined")

# 1. Aggregate by Sender
| stats 
    dc(Status) as unique_statuses
    values(Status) as Statuses
    values(RecipientAddress) as Recipients
    values(Subject) as Subjects
    values(FromIP) as Sender_IPs
    count 
    by SenderAddress

# 2. Filter: Must see BOTH statuses (Count > 1 if we only have 2 options)
| where unique_statuses > 1 AND (Statuses="Delivered" AND Statuses="Quarantined")

| table SenderAddress, Statuses, Recipients, Subjects, Sender_IPs, count
```

## 📦 Data Schema
*   **Index:** `o365`
*   **Sourcetype:** `o365:reporting:messagetrace`
*   **Field:** `Status` (Values: Delivered, Quarantined, FilteredAsSpam, etc.)

## 🧪 Validation
1.  **Simulation:** Hard to simulate without sending real mail.
2.  **Verify:** Check for senders with `unique_statuses=2` in Message Trace logs.
