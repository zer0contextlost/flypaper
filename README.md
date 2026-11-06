# Flypaper: open honeypot data

Everything that attacked three internet-facing honeypots on one residential IPv4 address in the
United States: SSH and Telnet sessions with every login attempt and command, malware hashes, web
exploit requests, and the attack campaigns they group into. It's rebuilt nightly from the raw logs
and released under CC-BY-4.0.

Current contents (2026-08-10 to 2026-11-05, UTC):

| | |
|---|---|
| SSH/Telnet sessions | 242,348 (192,493 honeyfleet, 49,855 Cowrie) |
| login attempts | 232,634 |
| commands typed | 371,675 |
| files dropped (hashes) | 11,508 |
| web requests | 51,752 |
| IPs that hit the Cowrie and web sensors (since 2026-08-09) | 4,221 |
| campaigns | 2,077 |
| malware samples triaged | 174 |

## Sensors

| `sensor` | what it is | data from |
|---|---|---|
| `honeyfleet` | SSH honeypot: a fork of Cowrie with a lived-in fake filesystem, rewritten common commands, and a per-session classification of the client (bot or human, typing cadence, command skeleton) | 2026-08-10 |
| `cowrie` | stock [Cowrie](https://github.com/cowrie/cowrie) on SSH and Telnet | 2026-10-17 |
| web | low-interaction HTTP catch-all with a fake WordPress login form | 2026-10-19 |

Raw Cowrie logs before 2026-10-17 and web logs before 2026-10-19 were not kept. For those weeks
`attackers.csv.gz` still has per-IP totals, usernames and passwords going back to 2026-08-09.

Every sensor accepts some logins on purpose, so `success: true` means the honeypot let the
attacker in. It doesn't mean the password is real anywhere.

## Files

```
sessions/YYYY-MM/sessions-YYYY-MM-DD.jsonl.gz   one JSON object per SSH/Telnet session, by UTC start day
web/YYYY-MM/web-YYYY-MM-DD.jsonl.gz             one JSON object per HTTP request
attackers.csv.gz                                per-IP history for the Cowrie and web sensors since 2026-08-09
campaigns/campaigns.csv                         campaigns found by grouping sessions on behaviour
campaigns/campaign_ips.csv.gz                   which IPs took part in which campaign
campaigns/campaign_daily.csv                    sessions and new IPs per campaign per day
malware/samples.csv                             static triage of captured files (hashes only)
malware/iocs.csv                                C2 addresses from those samples, confirmed by decompiling or from the dropper script
stats.json                                      the numbers above
```

Only finished UTC days are published. A day's file can still change on a later run if a late log
rotation adds sessions to it.

### Session fields

| field | |
|---|---|
| `session`, `sensor`, `protocol` | session id (unique per sensor), `cowrie`/`honeyfleet`, `ssh`/`telnet` |
| `start`, `end`, `duration_s` | ISO-8601 UTC; `end` is null if the close event was lost |
| `src_ip`, `src_port` | the attacking address |
| `asn`, `as_name`, `as_country` | from [iptoasn.com](https://iptoasn.com) at export time, not at the time of the attack |
| `known_scanner` | label (e.g. Censys, Shodan) when reverse DNS identifies a research scanner |
| `client_version`, `hassh`, `ssh_key_fingerprints`, `ja4` | client fingerprints |
| `logins[]` | `t`, `username`, `password`, `success` |
| `commands[]` | `t`, `input`, `ok` (false if the honeypot didn't implement some part of the line, true if it ran all of it, null if it logged neither) |
| `downloads[]`, `uploads[]` | `sha256` and the path or filename the attacker used |
| `failed_downloads[]` | URLs the honeypot could not fetch |
| `tunnels[]` | `direct-tcpip` forwarding requests: the host and port the attacker tried to reach through us |
| `classification` | honeyfleet only: `actor`, `actor_confidence`, `cadence`, `cadence_confidence`, `command_skeleton` |

Web records have `ts`, `src_ip`, the ASN fields, `known_scanner`, `method`, `path`, `query`,
`user_agent`, and the `username`/`password` sent to the fake login form.

## What was changed or left out

- The sensors' own public IP is replaced with `<sensor-ip>` wherever an attacker typed it (it
  turns up as a password and in client version strings). Any private IPv4 address is replaced with
  `<private-ip>`, and domain names belonging to the operator with `<own-domain>`.
- Sessions from private or local addresses (our own testing) are dropped.
- Not published: malware binaries (the hashes are on MalwareBazaar), terminal recordings, what the
  honeypots printed back, payload bytes sent through tunnels, and IDS logs.

## Using it

```python
import pandas as pd
s = pd.read_json("sessions/2026-10/sessions-2026-10-31.jsonl.gz", lines=True)
s.explode("logins").dropna(subset=["logins"])["logins"].apply(pd.Series)["password"].value_counts().head(20)
```

Most source addresses are compromised machines or rented servers, not the people behind them.
Don't treat an IP in this data as proof of who did something.

Detection rules written from this data are in
[honeypot-detections](https://github.com/zer0contextlost/honeypot-detections). Live views of the
same sensors: [watch](https://watch.zer0contextlost.net), [fleet](https://fleet.zer0contextlost.net).

## License and citation

Data: [CC-BY-4.0](LICENSE). ASN data: iptoasn.com (PDDL).

```
zer0contextlost. Flypaper: open honeypot data. https://github.com/zer0contextlost/flypaper
```

Questions and corrections: open an issue.
