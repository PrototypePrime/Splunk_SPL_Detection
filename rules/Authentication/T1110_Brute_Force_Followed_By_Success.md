# Brute Force Followed by Successful Logon

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-004` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects an account that fails to log in many times and then **succeeds**. Lots of failures on their own might
just be a user who forgot their password. Lots of failures *followed by a success* often means someone kept
guessing until they got the password right.

**Logic:**
*   In each 30-minute window, counts failed logons (4625) and successful logons (4624) for every account.
*   Alerts when an account has **10 or more failures** and its **first success comes after its last failure**: the guessing stopped because it worked.
*   This is a "sequence" detection (step A, then step B): see [Detection Lifecycle, Archetype E](../../docs/DETECTION_LIFECYCLE.md#35-archetype-e-the-sequence-correlation).

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode IN (4624, 4625)
NOT TargetUserName IN ("*$", "ANONYMOUS LOGON", "-")

```1. Bucket Time (30-minute windows)```
| bin _time span=30m

```2. Count failures and successes per account, and note when they happened```
| stats
    count(eval(EventCode=4625)) as failed_attempts
    count(eval(EventCode=4624)) as successful_logons
    max(eval(if(EventCode=4625, _time, null()))) as last_failure
    min(eval(if(EventCode=4624, _time, null()))) as first_success
    values(IpAddress) as source_ips
    values(Computer) as dest_hosts
    values(LogonType) as logon_types
    by _time, TargetUserName

```3. Threshold: many failures, and the first success comes after the last failure```
| where failed_attempts >= 10 AND successful_logons >= 1 AND first_success > last_failure

```4. Format```
| convert ctime(last_failure) ctime(first_success)
| rename TargetUserName as user
| table last_failure, first_success, user, failed_attempts, successful_logons, source_ips, dest_hosts, logon_types
| sort - failed_attempts

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup auth_exclusions.csv | fields user ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCodes:** `4625` (failed logon), `4624` (successful logon)
*   **Key Fields:** `TargetUserName` (the account), `IpAddress` (where the attempt came from), `Computer` (the machine logged into), `LogonType` (how they logged in, e.g. 3 = network, 10 = RDP)

## 🧪 Validation & Tuning
**False Positives:**
*   A user who forgot their password, tried many times, then reset it and logged in.
*   Applications or mapped drives retrying with an old saved password after a password change.

**Tuning:**
*   Raise or lower the 10-failure limit to suit your environment.
*   Add service or test accounts that legitimately behave like this to `auth_exclusions.csv`.

**Validation Steps:**
1.  **Simulation:** Use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate failed and successful logons, or manually fail to log in to a test account 10 times (e.g. wrong password over RDP), then log in correctly within 30 minutes.
2.  **Verify:** The alert shows the account with `failed_attempts` ≥ 10 and a `first_success` time after `last_failure`.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Treat the `user` account as compromised: reset its password and end its active sessions.
2.  Check `source_ips`. If they're external or unexpected, block them.
3.  Review what the account did on `dest_hosts` after `first_success`.
