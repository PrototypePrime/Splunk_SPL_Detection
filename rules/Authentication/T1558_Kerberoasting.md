# Kerberoasting (Weak Service Ticket Requests)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-006` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **Kerberoasting**: an attacker with any normal domain account asks the domain controller for "service
tickets" for many service accounts. Part of each ticket is locked with the service account's password, so the
attacker takes the tickets away and guesses the passwords offline, where nothing can stop or log the guessing.
Attackers deliberately ask for the old, weak **RC4** lock (code `0x17`) because it is much faster to crack than
modern AES.

**Logic:**
*   Looks at successful service ticket requests (event 4769) that use the weak RC4 lock.
*   Ignores computer accounts (names ending in `$`) and the built-in `krbtgt` account.
*   In each 1-hour window, alerts when **one user requests weak tickets for 3 or more different services**. Normal users rarely do that; Kerberoasting tools grab many at once.

## 🔍 SPL Query
````spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4769
TicketEncryptionType="0x17" Status="0x0"
NOT ServiceName IN ("krbtgt", "*$")
NOT TargetUserName="*$@*"

```-- Exclusions (uncomment, then maintain the lookup of legacy RC4-only services) --```
```NOT [| inputlookup kerberoast_service_exclusions.csv | fields ServiceName ]```

```1. Bucket Time (1-hour windows)```
| bin _time span=1h

```2. Count how many different services each user asked weak tickets for```
| stats
    dc(ServiceName) as services_requested
    values(ServiceName) as service_names
    values(IpAddress) as source_ips
    count as ticket_requests
    earliest(_time) as started
    latest(_time) as recent
    by _time, TargetUserName

```3. Threshold Filter```
| where services_requested >= 3

```4. Format```
| convert ctime(started) ctime(recent)
| rename TargetUserName as requesting_user
| table started, recent, requesting_user, services_requested, service_names, source_ips, ticket_requests
| sort - services_requested
````

## 📦 Data Schema
*   **Index:** `windows`
*   **Sourcetype:** `XmlWinEventLog` (Splunk Windows TA) / `XmlWinEventLog:Security` (Event-Horizon)
*   **EventCode:** `4769` (service ticket requested, recorded on the domain controller)
*   **Key Fields:** `TargetUserName` (the user asking, shown as `user@DOMAIN`), `ServiceName` (the service account the ticket is for), `TicketEncryptionType` (`0x17` = weak RC4, `0x12` = modern AES), `Status` (`0x0` = ticket issued), `IpAddress` (where the request came from, often shown as `::ffff:10.x.x.x`)

## 🧪 Validation & Tuning
**False Positives:**
*   Old applications or devices that only support RC4.
*   Service accounts that were never set up for AES, so every request for them uses RC4.

**Tuning:**
*   Best fix: enable AES on service accounts, so any RC4 request becomes genuinely unusual.
*   Add legacy RC4-only services to `kerberoast_service_exclusions.csv` and uncomment the Exclusions line.

**Validation Steps:**
1.  **Simulation:** Event-Horizon doesn't generate event 4769 yet. Use the [Atomic Red Team T1558.003 tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md) on a test domain, or from PowerShell request tickets for 3 test service accounts with RC4 enabled: `Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.contoso.com:1433"`
2.  **Verify:** The alert shows your test user with `services_requested` ≥ 3.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Find out who is behind `requesting_user` and what is running on the `source_ips` machine.
2.  Reset the passwords of every account in `service_names` to long, random passwords (25+ characters) and enable AES on them.
3.  Look for logons by those service accounts from unusual machines in the following days.
