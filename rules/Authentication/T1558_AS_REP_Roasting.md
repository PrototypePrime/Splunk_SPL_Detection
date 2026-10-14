# AS-REP Roasting (Logon Ticket Without Pre-Authentication)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-007` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **AS-REP Roasting**. Normally, before the domain controller hands out a logon ticket, the user must
first prove they know the password ("pre-authentication"). Some accounts have this check switched off
(the setting *"Do not require Kerberos preauthentication"*). For those accounts, **anyone** can ask for a ticket,
take it away and guess the password offline. This rule fires whenever a ticket is issued without that check.

**Logic:**
*   Looks for logon tickets (event 4768) that were issued (`Status 0x0`) with **no pre-authentication** (`PreAuthType 0`).
*   Very few accounts should ever have pre-authentication switched off, so every hit is worth a look.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4768
PreAuthType="0" Status="0x0"
NOT TargetUserName="*$"

```1. Stats Aggregation```
| stats
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(IpAddress) as source_ips
    values(TicketEncryptionType) as encryption_types
    count as ticket_requests
    by TargetUserName, Computer

```2. Format```
| convert ctime(first_seen) ctime(last_seen)
| rename TargetUserName as user, Computer as domain_controller
| table first_seen, last_seen, user, source_ips, encryption_types, ticket_requests, domain_controller
| sort - ticket_requests

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup asrep_exclusions.csv | fields user ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4768` (logon ticket requested, recorded on the domain controller)
*   **Key Fields:** `TargetUserName` (the account the ticket is for), `PreAuthType` (`0` = no password check before issuing), `Status` (`0x0` = ticket issued), `IpAddress` (who asked), `TicketEncryptionType` (`0x17` = weak RC4)

## 🧪 Validation & Tuning
**False Positives:**
*   Old applications or Linux/Unix systems that genuinely need pre-authentication switched off for a specific account.

**Tuning:**
*   First, find which accounts have the setting switched off (in PowerShell: `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'`) and switch it back on wherever possible.
*   Add the few accounts that truly need it to `asrep_exclusions.csv`.

**Validation Steps:**
1.  **Simulation:** Event-Horizon doesn't generate event 4768 yet. On a test domain, tick *"Do not require Kerberos preauthentication"* on a test account, then run the [Atomic Red Team T1558.004 tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.004/T1558.004.md).
2.  **Verify:** The alert shows the test account with your machine's IP in `source_ips`.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Switch pre-authentication back **on** for `user` (untick the setting in Active Directory).
2.  Reset that account's password to a long, random one, because its old password may already be cracked.
3.  Investigate who is behind `source_ips` and what else that machine did.
