# SPL Technique: streamstats

## 💡 Overview
**In one sentence:** `streamstats` adds a *running* number to every event as it works down the list.

**Think of a security guard's visitor log:**
*   `stats` is the guard's **end-of-day summary**: "Bob came in 4 times." You get one line per person, and the
    individual entries disappear.
*   `eventstats` is the guard going back and writing the **final** total next to every entry. Each of Bob's 4
    entries now says "Bob: 4 visits today".
*   `streamstats` is the guard writing a note next to each entry **as it happens**: "Bob's 1st visit", "Bob's 2nd
    visit, 15 minutes after his last one", and so on. Every entry stays, and each one knows what happened before it.

| Command | Keeps every event? | What gets added |
| :--- | :--- | :--- |
| `stats` | No, one line per group | The final totals |
| `eventstats` | Yes | The final total, copied onto every event |
| `streamstats` | Yes | The total *so far*, growing event by event |

## 🛠️ When to Use It
Use `streamstats` when **order or timing** matters:
*   Numbering events (1st, 2nd, 3rd failed login).
*   Measuring the **gap** since the previous event ("how long since this machine last contacted that address?").
*   Counting inside a **sliding** time window ("how many failures within 5 minutes of this one?").
*   Spotting **clockwork** behaviour, such as malware phoning home on a timer.

## 🔍 Examples

### Example 1: Number each failed login per user (like deli-counter tickets)
```spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4625
| sort 0 + _time
| streamstats count as failure_number by TargetUserName
| table _time, TargetUserName, failure_number
```
*   **What you get:** each failed login gets a ticket number, separately for each user. Alice gets 1, 2, 3; Bob
    gets 1, 2. The `by TargetUserName` part gives every user their own ticket roll.
*   **Why the sort?** Splunk normally lists newest first, like an inbox. `sort 0 + _time` puts the oldest first, so
    ticket 1 really is the first failure. (`0` means "sort everything, no limit".)

### Example 2: Time since the previous event
```spl
| makeresults count=5
| streamstats count as n
| eval _time = 1700000000 - (n * 60), src_ip = "10.1.5.23", dest_ip = "198.51.100.77"
| streamstats current=f last(_time) as next_time by src_ip, dest_ip
| eval interval = next_time - _time
| table _time, next_time, interval
```
*   **What it does:** builds 5 pretend connections exactly 60 seconds apart, then works out the gap for each one.
*   **Line by line:**
    *   `makeresults` ... `eval _time = ...` makes 5 fake events, newest first, 60 seconds apart.
    *   `streamstats current=f last(_time) as next_time by src_ip, dest_ip`: for each event, look at the event just
        above it in the list (for the same source and destination) and copy its time. `current=f` means "skip
        myself, give me my neighbour".
    *   `eval interval = next_time - _time` subtracts the two to get the gap.
*   **Result:** the top row has no neighbour above it, so its gap is empty. Every other row shows **60**.

### Example 3: A sliding 5-minute window
```spl
index=windows sourcetype IN ("XmlWinEventLog", "XmlWinEventLog:Security") EventCode=4625
| streamstats time_window=5m count as failures_last_5m by IpAddress
| where failures_last_5m > 20
```
*   **The idea:** for every failed login, count how many failures came from the same IP within a 5-minute span.
*   **Why not `bin _time span=5m`?** `bin` chops the clock into fixed blocks: 10:00–10:05, 10:05–10:10. An attack
    from 10:04 to 10:06 gets cut in half, and each half may stay under the limit. A sliding window moves with every
    event, so it sees the whole burst.

### Example 4: Clockwork detection (malware "phoning home")
This is the method behind the [C2 Beaconing](../rules/Network/T1071_C2_Beaconing.md) rule.

Think of malware like an **alarm clock**. Once it is on a laptop, it "phones home" to the attacker's server on a
timer (for example every 60 seconds, day and night). A person browsing the web is messy: a click, a pause, a long
read, three quick clicks. The rule looks for the alarm-clock pattern.

For every pair of *our machine → outside address*, it asks three questions:
1.  **Do they talk often?** More than 10 connections.
2.  **Like clockwork?** Are the gaps between connections almost the same every time?
3.  **Is it a rare destination?** Fewer than 5 of our machines talk to it. Popular sites (Microsoft, Google) are
    visited by everyone, while an attacker's server is usually visited only by the infected machine.

**Worked example:** laptop `10.1.5.23` connects to `198.51.100.77` five times.

| Connection time | Gap since the previous connection |
| :--- | :--- |
| 10:01:00 | (first one) |
| 10:02:00 | 60 seconds |
| 10:03:01 | 61 seconds |
| 10:04:01 | 60 seconds |
| 10:05:02 | 61 seconds |

*   **Step 1 (`streamstats`) works out the gaps.** It walks down the list one connection at a time. For each one,
    it notes the time of the neighbouring connection between the *same* laptop and the *same* address, and
    subtracts (exactly like Example 2). Splunk lists newest first, like an email inbox, so the neighbour is the
    next-later connection. The gaps come out the same.
*   **Step 2 (`stats`) summarises each pair:** 5 connections, gaps averaging about 60 seconds.
*   **Step 3 (`jitter`) gives the gaps a "messiness score":** how far the gaps typically wander from the average,
    divided by the average.
    *   This laptop: the gaps wander by about half a second out of 60, a score of **0.01**. Clockwork.
    *   A person reading the news: gaps of 3 s, 140 s, 12 s and 900 s, a score of **1.6**. Messy, human.
    *   The rule alerts when the score is **below 0.2**, meaning the gaps never wander more than about 20% from the average.
*   **Step 4** counts how many of our machines talk to that address at all (fewer than 5 means rare).

**Tuning tip:** Smarter malware adds random delays to look human. If you suspect that, raise the 0.2 limit
(e.g. to 0.4), at the cost of more alerts from legitimate software that also runs on timers (update checkers,
antivirus).

## ⚠️ Good Habits
1.  **Order matters.** `streamstats` reads the list top to bottom, like a logbook. If you re-sort the list first,
    the running numbers change.
2.  **Use `by` to keep separate tallies.** `by user` gives each user their own count. Without it, everyone's events
    go into one shared count.
3.  **`current=f` means "skip myself".** Use it when you want the previous event's value.
4.  **Narrow the search first.** `streamstats` keeps a running tally for every group, and millions of groups make it
    slow. Filter by index, sourcetype and key fields before it.
5.  **If fixed time blocks are good enough, use `bin` + `stats`.** They're simpler and faster. Use `streamstats`
    when you need order, gaps or sliding windows.
