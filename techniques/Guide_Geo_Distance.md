# SPL Technique: Measuring Distance Between Two Locations

## 💡 Overview
**In one sentence:** this guide explains, in plain words, how a Splunk search works out **how far apart two places
are** and **how fast someone would have to travel** between them.

**Where it's used:** the [Impossible Travel](../rules/Authentication/T1078_Impossible_Travel.md) rule. It flags a
user who signs in from, say, London and then Sydney an hour later, because nobody can travel that fast.

**The idea: a piece of string on a globe.** Picture a desk globe. Stretch a piece of string tight between two
cities. The length of that string is the real distance between them. The search does exactly this, using maths
instead of string.

**Why we can't just subtract the numbers.** Every place on a map has two numbers:
*   **Latitude**: how far north or south it is.
*   **Longitude**: how far east or west it is.

On a flat street map you could simply subtract them. But the Earth is round. Near the equator, one step east is
about 111 km. Near the North Pole, the same step is only a few km, because the east–west lines squeeze together
at the pole like the segments of an orange. The distance formula takes that roundness into account.

## 🧮 You Don't Need the Maths to Use It
Treat the formula like a calculator:

| You put in | You get out |
| :--- | :--- |
| Latitude and longitude of place A | The distance between them in **kilometres** |
| Latitude and longitude of place B | |

Copy the distance line exactly as it is. The only thing you ever change is the field names, if your locations are
stored under different names.

## 🔍 Examples

### Example 1: London to Sydney in one hour
```spl
| makeresults
| eval lat = 51.5074, lon = -0.1278, next_lat = -33.8688, next_lon = 151.2093, hours_between = 1
| eval distance_km = round(6371 * 2 * asin(sqrt(pow(sin((next_lat - lat) * pi() / 360), 2) + cos(lat * pi() / 180) * cos(next_lat * pi() / 180) * pow(sin((next_lon - lon) * pi() / 360), 2))), 0)
| eval speed_kmh = round(distance_km / max(hours_between, 0.01), 0)
| table distance_km, hours_between, speed_kmh
```
*   **What it does:** puts London's and Sydney's map numbers into the calculator and pretends the two sign-ins were
    one hour apart.
*   **Result:** `distance_km = 16994`, `hours_between = 1`, `speed_kmh = 16994`. That's nearly **19 times faster
    than a passenger jet**. Impossible, so the rule would alert.

### Example 2: From distance to speed
Speed is simply **distance ÷ time**, just like driving 100 km in 2 hours means you averaged 50 km/h.

| Step in the search | In plain words |
| :--- | :--- |
| `(next_time - _time) / 3600` | Splunk counts time in seconds. There are 3,600 seconds in an hour, so this gives the **hours** between the two sign-ins. |
| `max(hours_between, 0.01)` | If both sign-ins happen in the same second, the time between them is zero, and you can't divide by zero. This treats any gap as at least 0.01 hours (36 seconds). |
| `distance_km / max(...)` | Kilometres ÷ hours = **kilometres per hour**. |

### Example 3: What gets flagged and what doesn't
| Trip | Distance | Time between sign-ins | Speed needed | Flagged? |
| :--- | :--- | :--- | :--- | :--- |
| London → Sydney | 16,994 km | 1 hour | 16,994 km/h | **Yes** |
| New York → London | 5,570 km | 2 hours | 2,785 km/h | **Yes** |
| London → Paris | 344 km | 30 minutes | 688 km/h | No (slower than a jet, and under 500 km) |

The location of a sign-in is worked out from its internet address, and that's only roughly right: often to the
city, sometimes only to the country. Short hops like London → Paris are frequently just a VPN or a mobile network
routing through a nearby city. That's why the rule needs **both**:
*   an impossible speed (faster than **900 km/h**, roughly a passenger jet), **and**
*   a real distance (more than **500 km**).

## 🔬 For the Curious: What Each Part of the Formula Does
You don't need this section to use the formula, but if you want to know what's inside the calculator:

| Part | In plain words |
| :--- | :--- |
| `* pi() / 180` | Maps measure angles in **degrees**. The maths functions (`sin`, `cos`) expect a different unit called **radians**. This converts one to the other, like converting miles into kilometres before doing a sum. |
| `* pi() / 360` | The same conversion, which also halves the gap, because the formula works with half the gap on each side. |
| `pow(sin(… latitude gap …), 2)` | Measures the **north–south** part of the gap between the two places. |
| `cos(lat) * cos(next_lat) * pow(sin(… longitude gap …), 2)` | Measures the **east–west** part of the gap, made smaller the further you are from the equator, because east–west lines squeeze together towards the poles (the orange segments again). |
| `sqrt(…)` then `2 * asin(…)` | Combines both parts into one **angle**. Imagine two laser pointers at the centre of the Earth, one aimed at each city: this is the angle between the two beams. |
| `6371 * …` | The Earth's radius is about 6,371 km. Angle × radius = the length of the curve along the surface: **the piece of string**. |
| `round(…, 0)` | Rounds the answer to whole kilometres. |

This is a long-established formula from navigation, known as the **haversine formula**.

## ⚠️ Good Habits
1.  **Check the location exists first.** Missing coordinates, or `0, 0` (a spot in the ocean off West Africa), mean
    "location unknown", not a real place. The Impossible Travel rule filters these out.
2.  **Turn the map numbers into real numbers** with `tonumber()`. Values read from logs often arrive as text, and
    the maths won't work on text.
3.  **Treat internet-address locations as approximate.** Always pair the distance with a sensible minimum, like 500 km.
4.  **Exclude known VPN and proxy exit addresses.** They make users appear to be in another country.
