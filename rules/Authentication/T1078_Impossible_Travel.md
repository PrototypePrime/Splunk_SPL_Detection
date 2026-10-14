# Impossible Travel Between Sign-ins (Entra ID)

## 📝 Metadata
| Attribute | Value |
| :--- | :--- |
| **ID** | `SPL-AUTH-008` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Severity** | MEDIUM |
| **Status** | Production |
| **Author** | Mathan Subbiah |

## ⚠️ Description
Detects a user who signs in successfully from two places that are **too far apart for the time between them**.
For example: London at 09:00, then Sydney at 10:00. Nobody can travel that fast, so one of those sign-ins is
probably someone else using the account.

**Logic:**
*   Takes each successful sign-in and pairs it with the same user's next sign-in.
*   Works out the distance between the two locations and the time between them, then the speed the user would have needed.
*   Alerts when that speed is **faster than a passenger jet (900 km/h)** and the places are **more than 500 km apart**.
*   How "pair with the next sign-in" works: [streamstats guide, Example 2](../../techniques/Guide_streamstats.md#example-2-time-since-the-previous-event).
*   How the distance and speed are worked out, explained in plain words: [Geo Distance guide](../../techniques/Guide_Geo_Distance.md).

## 🔍 SPL Query
````spl
index=o365 sourcetype="azure:aad:signin" status.errorCode=0

```1. Pull out the location of each successful sign-in```
| eval lat = tonumber('location.geoCoordinates.latitude'),
       lon = tonumber('location.geoCoordinates.longitude'),
       location = 'location.city' . ", " . 'location.countryOrRegion'
| where isnotnull(lat) AND isnotnull(lon) AND NOT (lat=0 AND lon=0)

```2. Pair each sign-in with the same user's next sign-in```
| streamstats current=f
    last(_time) as next_time
    last(lat) as next_lat
    last(lon) as next_lon
    last(location) as next_location
    last(ipAddress) as next_ip
    by userPrincipalName
| where isnotnull(next_time) AND location!=next_location

```3. Distance between the two places (globe distance formula) and the speed needed```
| eval distance_km = round(6371 * 2 * asin(sqrt(pow(sin((next_lat - lat) * pi() / 360), 2) + cos(lat * pi() / 180) * cos(next_lat * pi() / 180) * pow(sin((next_lon - lon) * pi() / 360), 2))), 0)
| eval hours_between = round((next_time - _time) / 3600, 2)
| eval speed_kmh = round(distance_km / max(hours_between, 0.01), 0)

```4. Faster than a passenger jet, over a meaningful distance```
| where speed_kmh > 900 AND distance_km > 500

```5. Format```
| convert ctime(_time) as first_signin ctime(next_time) as second_signin
| rename userPrincipalName as user, location as from_location, next_location as to_location, ipAddress as from_ip, next_ip as to_ip
| table user, first_signin, from_location, from_ip, second_signin, to_location, to_ip, distance_km, hours_between, speed_kmh
| sort - speed_kmh

```-- Exclusions (uncomment, then maintain the lookup of VPN / proxy exit IPs) --```
```| search NOT [| inputlookup trusted_egress_ips.csv | fields to_ip ]```
````

## 📦 Data Schema
*   **Index:** `o365` (adjust to where your Entra ID sign-in logs live)
*   **Sourcetype:** `azure:aad:signin`
*   **Key Fields:** `userPrincipalName` (the user), `ipAddress`, `status.errorCode` (`0` = successful sign-in), `location.city`, `location.countryOrRegion`, `location.geoCoordinates.latitude` / `.longitude` (where the sign-in came from)

## 🧪 Validation & Tuning
**False Positives:**
*   Corporate VPNs or cloud proxies that make a user appear in another country.
*   Mobile phones that switch between Wi-Fi and a carrier network routed through another city.

**Tuning:**
*   Add VPN / proxy exit IPs to `trusted_egress_ips.csv`.
*   Raise the 500 km minimum if neighbouring-country hops are noisy.

**Validation Steps:**
1.  **Simulation:** Use [Event-Horizon](https://github.com/PrototypePrime/Event_Horizon) to generate `azure:aad:signin` events, or sign in to a test account normally, then again within an hour through a VPN exit in another continent.
2.  **Verify:** The alert shows both locations with `speed_kmh` above 900.
3.  **Noise:** Run against normal traffic to check for false positives.

## ⏭️ Response
1.  Ask the `user` whether they really signed in from both `from_location` and `to_location`.
2.  If not, reset their password, revoke their sessions and check their MFA methods for anything newly added.
3.  Review what the account did after `second_signin`.
