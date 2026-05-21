# Janus — Filter Cheatsheet

Same expression language for: Traffic / Alerts page filters, drop & alert rules, QuickRulePanel.
Empty expression matches everything. Keywords case-insensitive (`AND` = `and`).

---

## Network / service

```text
service == "minecclicker"
service in ("web", "api", "auth")
proto == "tcp"
proto in ("http", "https", "h2")
src == "10.10.0.1"
src in (10.0.0.0/8)
src in (10.0.0.0/8, 192.168.0.0/16)
NOT src in (10.10.0.0/16)               # outside our subnet
dst == "127.0.0.1"
peer == "10.60.1.2"                     # direction-aware
sport == 51338
dport in (8080, 8443, 9999)
direction == "request"
direction == "response"
```

---

## URL / method / status

```text
method == "POST"
method != "GET"
method in ("PUT", "PATCH", "DELETE")
status == 200
status >= 400
status < 500
status in (401, 403, 404)
url == "/login"
url startswith "/api/admin"
url endswith ".php"
url contains "/.env"
url icontains "ADMIN"
url matches "^/api/v[0-9]+/(login|register)$"
url matches "/users/[a-f0-9-]{36}"       # UUID in path
```

---

## Headers

```text
header contains "Set-Cookie"             # any header line
header.Authorization startswith "Bearer "
header.User-Agent icontains "bot"
header.User-Agent icontains "sqlmap"
header.Content-Type contains "json"
header.X-Forwarded-For matches "^10\\.|^192\\.168\\."
header.Cookie contains "session="
header.Missing == ""                     # header absent
header.Host != "example.com"
```

---

## Body / raw bytes

```text
body contains "admin"
body icontains "PASSWORD"
body == "ok"
body matches "(?i)union\\s+select"
body matches "<script[^>]*>"
body matches ".{4000,}"                  # unusually large body
raw contains "\xDE\xAD\xBE\xEF"          # hex bytes
raw contains "\x00\x00\x00\x01ATTACK"
raw startswith "\x16\x03"                # TLS handshake
round == 12                              # packets from scoreboard round 12
round in (10, 11, 12)
```

`round` is the operator-facing round field. Janus computes it from `competition_start + round_duration`; for historical packets where timing metadata is unavailable, it falls back to the persisted flag-ID scan round.

---

## Boolean shortcuts

```text
flagged                                  # body/url/headers contain a flag
NOT flagged
contains_flagid                          # one of OUR flag IDs in this packet
NOT contains_flagid
dropped                                  # was blocked by a rule
NOT dropped
flagged AND NOT dropped                  # leaked flag, slipped through
contains_flagid AND direction == "response"
```

---

## Compound / parentheses

```text
method == "POST" AND status >= 400
status == 200 AND method == "GET"
url startswith "/admin" OR url contains "/.env"

(url startswith "/admin" OR url contains "/.git")
  AND NOT src in (10.10.0.0/16)

(body contains "flag" AND NOT header contains "internal")
  OR header contains "X-Leaked"

method == "POST" AND status >= 400 AND src in (10.0.0.0/8)

# AND binds tighter than OR:
A OR B AND C        ==   A OR (B AND C)
NOT A AND B         ==   (NOT A) AND B
```

---

## Drop / alert rule examples

```text
# SQLi-looking POSTs to /login → drop
method == "POST" AND url contains "/login"
  AND body matches "(?i)(union|select|--|or\\s+1=1)"

# Scanner user agents → alert
header.User-Agent matches "(?i)(sqlmap|nikto|nmap|nuclei|burp)"

# Path traversal on a specific service → drop
service == "files" AND (url contains "../" OR url contains "..%2f")

# Oversized bodies on auth endpoint → drop
url startswith "/api/auth/" AND body matches ".{2000,}"

# Spoofed internal X-Forwarded-For → alert
header.X-Forwarded-For matches "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"

# Non-GET to /admin from outside our /16 → drop
url startswith "/admin" AND method != "GET"
  AND NOT src in (10.10.0.0/16)

# Raw-byte payload pattern on TCP service → drop
proto == "tcp" AND raw contains "\x00\x01\x02ATTACK"

# Buffer-overflow-shaped body (long run of A's) → drop
service == "minecclicker" AND raw contains "AAAAAAAAAAAAAAAAAAAAAAAA"

# Same family — long run of \x01 (the zaza-style fuzz)
service == "minecclicker" AND raw contains "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"

# Block requests carrying ANY of OUR flag IDs (active exploitation) → drop
contains_flagid AND direction == "request"

# Always alert on flag regex (NEVER drop — checker needs the flag)
body matches "[A-Z0-9]{31}=" OR url matches "[A-Z0-9]{31}="
  OR header matches "[A-Z0-9]{31}="
```

---

## Operator quick reference

```text
strings:   contains  icontains  ==  !=  startswith  endswith  matches  in
ints:      ==  !=  >  <  >=  <=  in
ip fields: ==  !=  in            (CIDR supported on src/dst/peer)
bools:     ==  !=  | bare-name shortcut
logical:   AND  &&    OR  ||    NOT  !  ~
```

---

## Value literals

```text
"double"           'single'        # equivalent
"line1\nline2"     "\""            "\\"          # escapes
"\xDE\xAD"                                       # hex bytes (in strings & raw)
200       8080                                   # integers
true      false                                  # booleans
10.0.5.7         10.0.0.0/8                      # IP / CIDR
("GET","POST")   (401, 403, 404)                 # lists (with `in`)
```

---

## Fields at a glance

| Group | Fields |
|-------|--------|
| Content | `body`, `raw` |
| HTTP | `url`, `method`, `status`, `round`, `direction`, `header`, `header.<name>` |
| Network | `service`, `proto`, `src`, `dst`, `peer`, `sport`, `dport` |
| Flags | `flagged`, `contains_flagid`, `dropped` |

---

## Gotchas

- `contains` is **case-sensitive** — use `icontains` for ASCII-CI.
- Regex is Go **RE2** — no lookahead/lookbehind/backrefs. Anchor with `^` / `$` if needed.
- CIDR works on `src` / `dst` / `peer` only.
- Flag rule is locked to `alert`: dropping flag-bearing packets breaks the checker.
- Filters touching `body` / `raw` / `header` fall back to polling on Traffic (SSE doesn't carry those).
- AND binds tighter than OR — parenthesize when in doubt.

---

## REST endpoints

```bash
GET  /api/packets?q=<expr>&limit=50&offset=0&sort=desc
GET  /api/alerts?q=<expr>&limit=50
POST /api/filter/validate     {"expression":"..."}    → {"ok":true} or {"ok":false,"error":"...","position":12}
```
