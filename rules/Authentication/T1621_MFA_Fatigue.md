# MFA Fatigue (Push Notification Spam)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-009` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1621 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/) |
| **Severity** | HIGH |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects **MFA fatigue**: an attacker who already has a user's password keeps triggering "Approve sign-in?"
prompts on the user's phone, hoping the user eventually taps *Approve* just to make them stop. A flood of prompts
or repeated "Deny" taps in a few minutes is the warning sign. If the flood ends with an **approval**, the
attacker probably got in.

**Logic:**
*   Covers both Okta (push sent / push denied / MFA approved) and Entra ID (MFA denied, error `500121`).
*   In each 10-minute window, counts prompts sent, denied and approved for each user.
*   Alerts at **5 or more prompts** or **3 or more denials**. A non-zero `prompts_approved` means the user may have given in.

## 🔍 SPL Query
````spl
(index=okta sourcetype="OktaIM2:log" eventType IN ("system.push.send_factor_verify_push", "user.mfa.okta_verify.deny_push", "user.authentication.auth_via_mfa"))
OR (index=o365 sourcetype="azure:aad:signin" status.errorCode=500121)

```1. Put Okta and Entra events into the same shape```
| eval user = lower(coalesce('actor.alternateId', userPrincipalName))
| eval src_ip = coalesce('client.ipAddress', ipAddress)
| eval mfa_event = case(
    eventType="system.push.send_factor_verify_push", "push_sent",
    eventType="user.mfa.okta_verify.deny_push" OR 'status.errorCode'=500121, "denied",
    eventType="user.authentication.auth_via_mfa" AND 'outcome.result'="SUCCESS", "approved")

```2. Bucket Time (10-minute windows)```
| bin _time span=10m

```3. Count prompts, denials and approvals per user```
| stats
    count(eval(mfa_event="push_sent")) as prompts_sent
    count(eval(mfa_event="denied")) as prompts_denied
    count(eval(mfa_event="approved")) as prompts_approved
    values(src_ip) as source_ips
    values(sourcetype) as log_source
    earliest(_time) as started
    latest(_time) as recent
    by _time, user

```4. Threshold: a flood of prompts or repeated denials```
| where prompts_sent >= 5 OR prompts_denied >= 3

```5. Format```
| convert ctime(started) ctime(recent)
| table started, recent, user, prompts_sent, prompts_denied, prompts_approved, source_ips, log_source
| sort - prompts_sent

```-- Exclusions (uncomment, then maintain the lookup) --```
```| search NOT [| inputlookup mfa_exclusions.csv | fields user ]```
````

## 📦 Data Schema
*   **Okta:** index `okta` · sourcetype `OktaIM2:log` · fields `eventType` (what happened), `actor.alternateId` (the user), `client.ipAddress` (where the sign-in attempt came from), `outcome.result` (SUCCESS / FAILURE)
*   **Entra ID:** index `o365` · sourcetype `azure:aad:signin` · fields `userPrincipalName`, `ipAddress`, `status.errorCode` (`500121` = the MFA check failed or was denied)
*   Adjust the index names to your environment.

## 🧪 Validation & Tuning
**False Positives:**
*   A user with a flaky phone or app who retries several times.
*   Background apps repeatedly asking for MFA after a password change.

**Tuning:**
*   Adjust the 5-prompt and 3-denial limits.
*   Add accounts with known-flaky MFA setups to `mfa_exclusions.csv`, temporarily.

**Validation Steps:**
1.  **Simulation:** Event-Horizon generates Okta and Entra events but not these exact push events yet. On a test account, trigger 5 sign-ins in a few minutes and deny the push prompts.
2.  **Verify:** The alert shows the test user with `prompts_sent` ≥ 5 or `prompts_denied` ≥ 3.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Contact the `user` straight away (by phone, not email): did they request these prompts?
2.  If not, reset their password, because the attacker already knows it.
3.  If `prompts_approved` is above 0, treat the account as compromised: revoke sessions and review recent activity.
4.  Consider turning on number matching for push MFA, which stops blind approvals.
