# New User Account Added to an Admin Group Within 1 Hour

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-ID-008` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | [T1136.002 - Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a **brand-new user account that is put into an admin group soon after it was created**. Attackers who
gain admin rights often create their own "backdoor" admin account so they can come back later. Real new
starters rarely become admins within the hour.

**Logic:**
*   Uses two events: account created (4720) and member added to a group (4728 / 4732 / 4756).
*   Links them by the new account's unique ID (its SID), so a rename can't break the link.
*   Alerts when the account is added to Domain Admins, Enterprise Admins, Schema Admins or Administrators **within 1 hour** of being created.
*   This is a "sequence" detection: see [Detection Lifecycle, Archetype E](../../docs/DETECTION_LIFECYCLE.md#35-archetype-e-the-sequence-correlation).

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode IN (4720, 4728, 4732, 4756)

```1. Give both events the same key: the new account's SID```
| eval account_sid = if(EventCode=4720, TargetSid, MemberSid)
| eval new_user = if(EventCode=4720, TargetUserName, null())
| eval admin_group = if(EventCode!=4720, TargetUserName, null())
| where EventCode=4720 OR match(TargetUserName, "(?i)(Domain Admins|Enterprise Admins|Schema Admins|Administrators)")

```2. Per account: when it was created and when it was first added to an admin group```
| stats
    min(eval(if(EventCode=4720, _time, null()))) as created_time
    min(eval(if(EventCode!=4720, _time, null()))) as added_time
    values(new_user) as new_user
    values(admin_group) as admin_group
    values(SubjectUserName) as actor
    values(Computer) as domain_controller
    by account_sid

```3. Created first, then added to an admin group within 1 hour```
| where isnotnull(created_time) AND isnotnull(added_time) AND added_time >= created_time AND (added_time - created_time) <= 3600
| eval minutes_between = round((added_time - created_time) / 60, 0)

```4. Format```
| convert ctime(created_time) ctime(added_time)
| table created_time, added_time, minutes_between, new_user, admin_group, actor, domain_controller, account_sid
| sort + minutes_between
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCodes:** `4720` (user account created), `4728` / `4732` / `4756` (member added to a global / local / universal group)
*   **Key Fields:** `TargetSid` (the new account's ID, on 4720), `MemberSid` (the added account's ID, on 4728/4732/4756), `TargetUserName` (the new account on 4720, the group on 4728/4732/4756), `SubjectUserName` (who did it)
*   **Time range:** run over at least the last 2 hours, so both events fall inside the search.

## 🧪 Validation & Tuning
**False Positives:**
*   IT creating a new admin account through an approved request.
*   Automated provisioning tools that create and elevate accounts in one go.

**Tuning:**
*   Exclude approved provisioning tools by their `actor` account using an exclusion lookup.

**Validation Steps:**
1.  **Simulation:** Use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate 4720 and 4728 events, or on a test domain run `net user testadmin P@ssw0rd123! /add /domain` then `net group "Domain Admins" testadmin /add /domain`.
2.  **Verify:** The alert shows `testadmin` with a small `minutes_between`.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Check for an approved change request for `new_user`.
2.  If there's none, disable `new_user` and remove it from `admin_group` immediately.
3.  Investigate the `actor` account: it had admin rights to do this, and may itself be compromised.
