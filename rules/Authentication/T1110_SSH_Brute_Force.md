# SSH Brute Force Against Linux Servers

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-010` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a single source address **guessing passwords over SSH** against Linux servers. Internet-facing SSH is
attacked constantly, so the rule also shows whether the same source then **logged in successfully**, which is
what turns noise into an incident.

**Logic:**
*   Reads SSH login lines from the Linux security log (`Failed password`, `Invalid user`, `Accepted …`).
*   In each 10-minute window, counts failed and successful logins for each source address.
*   Alerts at **20 or more failures** from one source. `successful_logins` above 0 means the guessing may have worked.

## 🔍 SPL Query
````spl
index=linux sourcetype=linux_secure ("Failed password" OR "Invalid user" OR "Accepted password" OR "Accepted publickey")

```1. Pull the source address, the username and the result out of each SSH line```
| rex "from (?<ssh_src>[0-9a-fA-F\.:]+) port"
| rex "(?:for (?:invalid user )?|Invalid user )(?<ssh_user>\S+) from"
| eval outcome = if(match(_raw, "Accepted (password|publickey)"), "success", "failure")

```2. Bucket Time (10-minute windows)```
| bin _time span=10m

```3. Count failures and successes per source```
| stats
    count(eval(outcome="failure")) as failed_attempts
    count(eval(outcome="success")) as successful_logins
    dc(ssh_user) as users_tried
    values(ssh_user) as usernames
    values(host) as target_servers
    earliest(_time) as started
    latest(_time) as recent
    by _time, ssh_src

```4. Threshold Filter```
| where failed_attempts >= 20

```5. Format```
| convert ctime(started) ctime(recent)
| rename ssh_src as src_ip
| table started, recent, src_ip, failed_attempts, successful_logins, users_tried, usernames, target_servers
| sort - failed_attempts

```-- Exclusions (uncomment, then maintain the lookup of scanners / jump hosts) --```
```| search NOT [| inputlookup ssh_source_exclusions.csv | fields src_ip ]```
````

## 📦 Data Schema
*   **Index:** `linux` (adjust to your environment)
*   **Sourcetype:** `linux_secure` (the Linux security / auth log)
*   **Key Fields:** pulled from each log line: `ssh_src` (where the login came from), `ssh_user` (the username tried), plus `host` (the server attacked)

## 🧪 Validation & Tuning
**False Positives:**
*   Your own vulnerability scanners or configuration tools retrying with an old password.
*   Automation (backup or deployment scripts) with an expired key or password.

**Tuning:**
*   Add scanners and jump hosts to `ssh_source_exclusions.csv`.
*   Internet-facing servers see constant background guessing; raise the 20-failure limit there, or alert only when `successful_logins` > 0.

**Validation Steps:**
1.  **Simulation:** Use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate `linux_secure` SSH events, or from a test machine try `ssh wronguser@<test-server>` with a wrong password 20 times.
2.  **Verify:** The alert shows your test machine as `src_ip` with `failed_attempts` ≥ 20.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Block `src_ip` at the firewall if it is external.
2.  If `successful_logins` > 0, treat the server as compromised: check what the logged-in user did and rotate the account's password and keys.
3.  Move SSH to key-only login (no passwords) and limit who can reach it.
