# Windows Excessive Password Change Activity

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-005` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Identifies when a single user account or administrative account changes/resets the password for the same target user multiple times (>4) within a short window. This "Password Thrashing" can indicate:
*   An administrator struggling with a script/tool.
*   Someone attempting to cycle through password history requirements.
*   Malicious persistence attempts.

## 🔍 SPL Query
```spl
index=windows sourcetype=WinEventLog EventCode IN (4723, 4724) 
src_user!="*$" 
NOT Account_Name IN ("ServiceAccount1", "AzureADConnect")

| convert ctime(_time) as timestamp
| stats 
    earliest(timestamp) as started 
    latest(timestamp) as recent 
    values(name) as action 
    values(status) as status 
    values(src_nt_domain) as src_domain 
    values(dest_nt_domain) as dest_domain 
    count 
    by src_user, user 

| where count > 4
```

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `WinEventLog`
*   **EventCodes:** `4723` (User changed own password), `4724` (Admin reset password)

## 🧪 Validation
1.  **Simulation:** Manually change a test user's password 5 times in 5 minutes using `net user`.
2.  **Verify:** Confirm the alert fires.
