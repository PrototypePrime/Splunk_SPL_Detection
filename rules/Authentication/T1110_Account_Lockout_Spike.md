# Account Lockout Spike from a Single Source

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-005` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects several **different accounts getting locked out because of bad passwords coming from the same machine**.
One locked account is usually a user who forgot their password. Several accounts locked from the same machine in
a short time usually means something on that machine is guessing passwords across many accounts.

**Logic:**
*   Windows records a lockout (event 4740) on the domain controller, including the name of the machine the bad passwords came from (the *caller computer*).
*   In each 15-minute window, counts how many different accounts were locked out from each caller computer.
*   Alerts when **3 or more accounts** are locked out from the same machine.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4740
NOT TargetUserName="*$"

```1. Bucket Time (15-minute windows)```
| bin _time span=15m

```2. Group lockouts by the machine the bad passwords came from```
| stats
    dc(TargetUserName) as locked_accounts
    values(TargetUserName) as locked_users
    count as lockout_events
    earliest(_time) as started
    latest(_time) as recent
    values(Computer) as domain_controller
    by _time, TargetDomainName

```3. Threshold Filter```
| where locked_accounts >= 3

```4. Format```
| convert ctime(started) ctime(recent)
| rename TargetDomainName as caller_computer
| table started, recent, caller_computer, locked_accounts, locked_users, lockout_events, domain_controller
| sort - locked_accounts

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup lockout_source_exclusions.csv | fields caller_computer ]```
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4740` (account locked out, recorded on the domain controller)
*   **Key Fields:** `TargetUserName` (the locked account), `TargetDomainName` (despite its name, this holds the **caller computer**: the machine the bad passwords came from), `Computer` (the domain controller)

## 🧪 Validation & Tuning
**False Positives:**
*   Shared servers that sign in on behalf of many users (Exchange, ADFS, VPN, Citrix) show up as the caller computer for lots of unrelated lockouts.
*   A password policy change that locks out many users at once.

**Tuning:**
*   Add shared servers to `lockout_source_exclusions.csv`, or raise the 3-account limit for them.

**Validation Steps:**
1.  **Simulation:** Use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate lockout events, or from one test machine enter wrong passwords for 3 test accounts until each locks out.
2.  **Verify:** The alert shows that machine as `caller_computer` with `locked_accounts` ≥ 3.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Investigate `caller_computer`: what process or user is sending the bad passwords?
2.  If it's not a known shared server, isolate it and check for password-guessing tools.
3.  Unlock the `locked_users` only after the source is contained.
