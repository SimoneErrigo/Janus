# Flag IDs

Janus periodically fetches the Flag IDs of the local team, keeps a
round-aware matcher in memory, and marks packets that contain one of those
values. The match is used by Traffic, Rules, PyFilters, alerts, and the exploit
generator; it does not change the service payload.

## Configure the poller

Copy the corresponding values into `.env` before starting Janus, or change them
from **Config** at runtime.

```dotenv
FLAGID_ENABLED=true
FLAGID_API_URL=http://scoreboard.example/flagIds
OUR_TEAM_ID=1
FLAGID_FORMAT=cyberchallenge
FLAGID_POLL_INTERVAL=30

ROUND_DURATION=120
COMPETITION_START=2026-03-29T10:00:00Z
KEEP_ROUNDS=5
```

| Setting | Meaning |
| --- | --- |
| `FLAGID_ENABLED` | Enables polling in `live` traffic mode. |
| `FLAGID_API_URL` | Scoreboard endpoint returning the selected JSON shape. |
| `OUR_TEAM_ID` | Team identifier. Interpretation depends on the format. |
| `FLAGID_FORMAT` | `cyberchallenge`, `saarctf`, `faustctf`, `forcad`, or `enowars`. |
| `FLAGID_POLL_INTERVAL` | Normal fetch interval in seconds. |
| `ROUND_DURATION` | Scoreboard round length in seconds. Defaults to 120 when unset. |
| `COMPETITION_START` | Optional RFC3339 start time used to calculate the current round. |
| `KEEP_ROUNDS` | Number of latest rounds retained by the matcher. Defaults to 5. |

Use `GET /api/flagids/status` to inspect the effective configuration, current
round, latest fetch, and parse errors. `POST /api/flagids/refresh` forces a
fetch. The API route list is in [API.md](API.md).

## Behaviour by traffic mode

- In **live** mode, Janus fetches at startup and then periodically. A changed
  response rebuilds the matcher and automatically rescans only the recent
  traffic window. An unchanged response does not trigger an unnecessary
  rebuild or backfill.
- In **static** mode, periodic polling and automatic cleanup are disabled.
  Fetch Flag IDs manually and use **Apply Flag IDs** (or
  `POST /api/traffic/capture/apply-flagids`) to rescan the captured window.
- For round-aware formats, the matcher contains the latest `KEEP_ROUNDS`.
  Each Flag ID hit keeps its source round so Round Diff and Traffic can retain
  useful round information.
- Fetch/parse errors and incomplete ENOWARS responses keep the last valid
  matcher active. Repeated failures back off up to one minute and remain
  visible through `last_error` instead of flooding the runtime log.

Except for ForcAD and ENOWARS, Janus appends `?team=<OUR_TEAM_ID>` (or
`&team=...`) to the configured endpoint. Make the endpoint accept that query
parameter or return the local team's data after applying it.

## Supported formats

### CyberChallenge (`cyberchallenge`)

This is the default. The round is present in the response.

```json
{
  "service1": {
    "1": {
      "5": {
        "username": "alice",
        "record": ["r-1", "r-2"]
      }
    }
  }
}
```

Shape:

```text
service -> team -> round -> description key -> Flag ID value
```

Janus accepts strings, numbers, booleans, arrays, and nested objects at the
leaf. Arrays and objects are recursively flattened, so all usable leaf values
become match candidates. The description key is retained internally for
CyberChallenge exploit generation.

`OUR_TEAM_ID` is sent as the `team` query parameter. The endpoint should return
the data scoped to that team.

### saarCTF (`saarctf`)

Use saarCTF's `attack.json`-style response. `OUR_TEAM_ID` is the numeric team
ID; Janus resolves it to the IP address in `teams[]`, then uses that IP as the
key below `flag_ids`.

```json
{
  "teams": [
    { "id": 1, "name": "NOP", "ip": "10.32.1.2" },
    { "id": 2, "name": "saarsec", "ip": "10.32.2.2" }
  ],
  "flag_ids": {
    "service_1": {
      "10.32.1.2": {
        "15": ["alice", "account-1"],
        "16": "bob"
      }
    }
  }
}
```

Shape:

```text
flag_ids -> service -> team IP -> round -> string or array of strings
```

If `teams[]` is absent or cannot resolve the ID, Janus falls back to using
`OUR_TEAM_ID` directly as the `flag_ids` map key.

### FaustCTF (`faustctf`)

FaustCTF data has no round in the payload. Janus assigns all values to the
round calculated from `COMPETITION_START` and `ROUND_DURATION`; without usable
timing it assigns round `1`.

```json
{
  "teams": [123, 456, 789],
  "flag_ids": {
    "service1": {
      "123": ["abc123", "def456"],
      "789": ["other-team-id"]
    }
  }
}
```

Shape:

```text
flag_ids -> service -> team ID -> array of strings
```

Set `OUR_TEAM_ID` to the exact team key (`123` in the example).

### ForcAD (`forcad`)

ForcAD returns all teams in one document and does not use the `team` query
parameter. Janus selects the local team on the client side.

```json
{
  "easyblog": {
    "10.0.0.3": ["{\"username\":\"alice\",\"filename\":\"a.png\"}"],
    "10.0.0.4": ["{\"username\":\"bob\"}"]
  },
  "seaofhackerz": {
    "10.0.0.3": ["user_id: 436, ship_id: 12"]
  }
}
```

Shape:

```text
service -> team IP -> array of values
```

`OUR_TEAM_ID` can be:

1. the full key/IP (`10.0.0.3`);
2. a team number (`3`), resolved first against the last IP octet and then an
   unambiguous matching octet; or
3. a unique substring of a team key.

Values have no embedded round and are assigned to the computed current round
(or round `1` if timing is unavailable). Janus also expands JSON-in-a-string
values to their leaves, and splits `label: value` pairs into the bare value and
useful URL/JSON forms. This makes identifiers match when services send them as
request fields rather than in the scoreboard's display format.

### ENOWARS (`enowars`)

ENOWARS Attack Info responses contain all teams and retain round numbers in
the payload. Janus selects the local team client-side and does not append a
`team` query parameter.

For ENOWARS 10, configure:

```dotenv
FLAGID_API_URL=https://10.enowars.com/scoreboard/attack.json
FLAGID_FORMAT=enowars
OUR_TEAM_ID=52
```

```json
{
  "availableTeams": ["10.1.52.1"],
  "services": {
    "service_1": {
      "10.1.52.1": {
        "7": [["user73"], ["user5"]],
        "8": [["user96"], ["user314"]]
      }
    }
  }
}
```

Shape:

```text
services -> service -> team IP -> round -> nested Flag ID values
```

Set `OUR_TEAM_ID` to the full IP (`10.1.52.1`) or the team number (`52`) used
by the standard `10.1.<team>.1` address. Nested arrays and objects are flattened
to their usable leaf values, including JSON serialized inside a string, with
duplicates removed within each service and round. Five-character values such
as `user5` are accepted only on word boundaries to avoid substring matches;
shorter generic values are ignored. Partial service responses are merged with
the retained rounds, while a missing team or stale response leaves the last
valid snapshot untouched.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No values in `/api/flagids` | Confirm the URL, format, and `OUR_TEAM_ID`; inspect `last_error` in `/api/flagids/status`. |
| Values fetched but no packet is highlighted | Verify the relevant round is still within `KEEP_ROUNDS`, then check that the exact value is present in URL, headers, or body. |
| New IDs are not applied to old static traffic | Run **Apply Flag IDs** after the fetch. |
| Wrong ForcAD team selected | Set `OUR_TEAM_ID` to the full IP to remove ambiguity. |
| Round Diff shows round `0` | Set both `COMPETITION_START` and a positive `ROUND_DURATION`, using a valid RFC3339 timestamp. |

For the endpoints that expose the current values and poller health, see
[API.md](API.md). For ordinary flag-pattern detection (not scoreboard Flag
IDs), configure `FLAG_REGEX` and the related variables documented in
[README.md](README.md).
