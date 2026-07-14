# Python filters — advanced examples

Worked `match(flow)` filters, from one-liners to stateful attack detectors, for
HTTP, TCP, UDP, and WebSocket services. Most are modelled on **real A/D vulnerabilities**, and each
is written **ad-hoc so it drops the exploit without ever matching the checker's
normal traffic** — the note under each one says exactly why the checker slips
through. For the full API see [PYFILTERS.md](PYFILTERS.md).

These are deliberately service-specific recipes, not copy-and-enable defaults.
If this is your first filter, begin with the smaller examples in
[PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md), then test the adapted script
against a captured packet or a whole flow before enabling it.

Tags: **Alert** returns a reason string (works in either mode). **Inline** drops
or rewrites the current message before forwarding. Inline execution
works in both directions for TCP, UDP, and WebSocket, plus ordinary buffered
HTTP/HTTPS responses up to 1 MiB; streaming/oversized HTTP and HTTP/2 or gRPC
responses are observe-only. For body-based HTTP request decisions, require
`flow.body_complete`: chunked/unknown-length bodies are streamed without
pre-reading and bodies over 1 MiB expose only a bounded prefix inline.

Return values: `False`/`None` ignore · `"reason"` alert · `{"drop": True, "reason": …}`
drop now · assign `flow.body` / `flow.content` rewrite. `DIRECTION = "request"`/`"response"`
at module level restricts the side. Module globals persist; `flow.state` is
bounded per-connection/session state private to each filter (`flow.conn` is its
legacy alias).

The test panel accepts a manual sample, a server-loaded packet, or an ordered
request/response flow. It applies the selected mode and scope; **Repeat**
exercises counters and other stateful logic. A successful test only changes live
traffic after the script is saved, enabled, and set to Inline.

## `util.*` — payload analysis helpers

Injected into every filter as `util`. Stdlib-only, so you can inspect a payload
and drop immediately without pulling the whole thing apart by hand.

| helper | returns |
|---|---|
| `util.is_base64(s, canonical=True)` | bytes are valid (and, by default, *canonical*) base64 |
| `util.b64(s)` | decoded bytes, or `None` if not base64 |
| `util.valid_json(s)` | `s` is one complete, well-formed JSON document (no truncation / trailing bytes) |
| `util.extra_keys(obj, allowed)` | set of dict keys not in `allowed` (mass assignment) |
| `util.entropy(data)` | Shannon entropy in bits/byte (0 = uniform) |
| `util.longest_run(data)` | length of the longest run of one repeated byte |
| `util.repeated_block(data, size=16)` | an aligned block repeats (ECB-like / crafted oracle) |
| `util.printable_ratio(data)` | fraction of printable-ASCII bytes |
| `util.has_control_chars(s)` | text holds a C0 control (incl. `\r \n \t`) or DEL |
| `util.magic(data)` | sniffed file type (`png`,`jpg`,`pdf`,`zip`,`svg`,…) or `""` |
| `util.content_type_ok(ct, data)` | declared Content-Type is consistent with the bytes |
| `util.trailing_data(data)` | bytes appended after an image's logical end (polyglot) |
| `util.qr_decode(data)` | decode a QR code from a PNG/GIF/BMP image → list of strings (v1-40) |
| `util.text_layers(data, qr=False)` | every readable text layer: raw strings + decoded PNG chunks / PDF streams / ZIP entries / QR |
| `util.find_payload(data, categories=None, qr=False)` | first attack signature (SQLi/shell/php/xss/xxe/template/traversal) found in any layer, else `None` |
| `util.scan(data, patterns, qr=False)` | search every text layer with your own regex list |
| `util.inspect(data, qr=False)` | quick report: type, size, trailing, layers, first payload |
| `util.normpath(p)` | URL-decoded, `.`/`..`/`//`-folded path |
| `util.uri_scheme(s)` | scheme if `s` carries one (`telnet`, `file`, …) else `""` |
| `util.path_escapes(p)` | a (relative) path is absolute / traverses out / has a scheme or NUL |

---

## Table of contents

**Level 1 — stateless pattern**
1. [Mass assignment on registration](#1-mass-assignment-on-registration) · Inline
2. [Curl option injection / SSRF](#2-curl-option-injection--ssrf) · Inline
3. [Control chars in a username](#3-control-chars-in-a-username) · Inline
4. [Strict date format (buffer overflow)](#4-strict-date-format-buffer-overflow) · Inline
5. [Bounded numeric timestamp](#5-bounded-numeric-timestamp) · Inline

**Level 2 — body / file parsing**
6. [Reject malformed JSON (error-leak)](#6-reject-malformed-json-error-leak) · Inline
7. [A file field must be canonical base64](#7-a-file-field-must-be-canonical-base64) · Inline
8. [Content-Type must match the bytes](#8-content-type-must-match-the-bytes) · Inline
9. [Malicious content inside an uploaded image (polyglot / QR / metadata)](#9-malicious-content-inside-an-uploaded-image-polyglot--qr--metadata) · Inline
10. [Static path traversal / SSRF](#10-static-path-traversal--ssrf) · Inline
11. [Algorithm allowlist](#11-algorithm-allowlist) · Inline

**Level 3 — semantic payload**
12. [JOIN result-length overflow](#12-join-result-length-overflow) · Inline
13. [Marker that appears only after sanitization](#13-marker-that-appears-only-after-sanitization) · Inline
14. [Crypto-oracle input (uniform blocks)](#14-crypto-oracle-input-uniform-blocks) · Inline
15. [Parameter pollution + shell metacharacters](#15-parameter-pollution--shell-metacharacters) · Inline

**Level 4 — stateful flow**
16. [Login flood against one victim](#16-login-flood-against-one-victim) · Inline
17. [Repeated protocol INIT (challenge reuse)](#17-repeated-protocol-init-challenge-reuse) · Inline
18. [Byte-at-a-time compare oracle](#18-byte-at-a-time-compare-oracle) · Inline
19. [Author overwrite between open and answer](#19-author-overwrite-between-open-and-answer) · Inline
20. [IDOR: object never created in this session](#20-idor-object-never-created-in-this-session) · Inline

**Level 5 — [when a traffic filter can't be trusted](#level-5--when-a-traffic-filter-cant-be-trusted)**

---

## Level 1 — stateless pattern

### 1. Mass assignment on registration
*Duogesto — the registration object is copied into the session, so `friends`
lets you spoof a friendship.* Registration should carry only `name` + `password`;
reject sensitive extra keys.

```python
DIRECTION = "request"
ALLOWED = {"name", "password"}
SENSITIVE = {"friends", "role", "admin", "is_admin", "permissions"}

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/register"):
        extra = util.extra_keys(flow.json() or {}, ALLOWED)
        if extra & SENSITIVE:
            return {"drop": True, "reason": "mass assignment: %s" % sorted(extra & SENSITIVE)}
    return False
```
*Checker sends only `name`+`password`, so `extra` is empty. Intersecting with
`SENSITIVE` means even a future benign extra field wouldn't be dropped.*

### 2. Curl option injection / SSRF
*Duogesto — a URL/filename reach `curl`; `-K`/`--config` turn an uploaded file
into curl config (`telnet://mongo:27017`).* Allowlist the scheme, forbid values
that look like options.

```python
DIRECTION = "request"

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/download"):
        data = flow.json() or {}
        for field in ("url", "filename"):
            v = str(data.get(field, ""))
            if v.startswith("-"):
                return {"drop": True, "reason": "%s looks like a curl option: %r" % (field, v[:24])}
        if util.uri_scheme(str(data.get("url", ""))) not in ("", "http", "https"):
            return {"drop": True, "reason": "non-HTTP URL scheme"}
    return False
```
*Checker downloads `https://…` images with ordinary filenames — no leading `-`,
only `http`/`https` schemes.*

### 3. Control chars in a username
*CCalendar — a newline in the username bypasses a regex and yields `/../victim`.*
Usernames are letters/numbers only; block control chars and path metacharacters.

```python
DIRECTION = "request"
BAD = set("/\\#")

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/register"):
        user = str((flow.json() or {}).get("name", ""))
        if util.has_control_chars(user) or (set(user) & BAD):
            return {"drop": True, "reason": "illegal characters in username"}
    return False
```
*Checker usernames are short alphanumerics, so neither test fires.*

### 4. Strict date format (buffer overflow)
*CCalendar — `date` is copied into a 16-byte buffer; a valid date **followed by
extra bytes** overflows it.* Enforce the exact `YYYY-MM-DD` shape — but only the
*format*, so the checker's semantically-invalid dates still reach the app's own
error path.

```python
import re
DIRECTION = "request"
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

def match(flow):
    if flow.path.rstrip("/").endswith("/events"):
        d = str(flow.query["date"] or (flow.json() or {}).get("date", ""))
        if d and not DATE.fullmatch(d):
            return {"drop": True, "reason": "malformed date %r" % d[:32]}
    return False
```
*Checker sends `2026-07-04`; its SLA "bad date" tests (`2026-13-40`) still match
the `\d{4}-\d{2}-\d{2}` shape, so they pass through and get the app's 4xx.*

### 5. Bounded numeric timestamp
*ExCCel — a length-prefixed timestamp overruns a 32-byte buffer and rewrites the
target worksheet id.* A Unix timestamp is short and numeric.

```python
DIRECTION = "request"

def match(flow):
    if flow.path.endswith("/worksheet"):
        ts = str((flow.json() or {}).get("timestamp", ""))
        if ts and (not ts.isdigit() or len(ts) > 15):
            return {"drop": True, "reason": "oversized/non-numeric timestamp"}
    return False
```
*Checker sends a ~10-digit epoch near now; well under the 15-char cap.*

---

## Level 2 — body / file parsing

### 6. Reject malformed JSON (error-leak)
*CCForms — a truncated JSON body triggers a stack trace that leaks `JWT_SECRET`.*
Parse before forwarding; drop bodies that aren't well-formed JSON.

```python
DIRECTION = "request"

def match(flow):
    if flow.method == "POST" and "json" in flow.header("content-type").lower():
        if not util.valid_json(flow.body):
            return {"drop": True, "reason": "malformed JSON body"}
    return False
```
*Checker always sends well-formed JSON, so `valid_json` is True and nothing drops.*

### 7. A file field must be canonical base64
*CCForms — an uploaded file's `content` is concatenated into SQL; only true
base64 is safe, an SQLi rides in a non-base64 tail.* Don't hunt for `SELECT` —
require the field to *be* canonical base64.

```python
DIRECTION = "request"

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/upload"):
        content = (flow.json() or {}).get("content")
        if content is not None and not util.is_base64(content):
            return {"drop": True, "reason": "file content is not canonical base64"}
    return False
```
*Checker base64-encodes the whole file, so `is_base64` is True. The exploit's
`QQ==' || (SELECT …)` has non-alphabet bytes and fails canonicity.*

### 8. Content-Type must match the bytes
*Generic upload hardening — a file claimed as an image that is really a script or
archive.* Sniff the magic and compare to the declared type.

```python
DIRECTION = "request"

def match(flow):
    if flow.method in ("POST", "PUT") and flow.path.endswith("/avatar"):
        if not util.content_type_ok(flow.header("content-type"), flow.content):
            return {"drop": True, "reason": "body does not match its Content-Type"}
    return False
```
*Checker uploads a real PNG with `image/png`; the sniff matches. Unknown/
unenforced types return True, so non-image endpoints are never touched.*

### 9. Malicious content inside an uploaded image (polyglot / QR / metadata)
*The server decodes an uploaded image/file and acts on what's inside — a QR that
carries an SQL injection, a rev-shell appended after the image, a payload hidden
in a PNG text chunk / PDF stream.* `util.find_payload` decodes every text layer
(including a **QR code** and zlib-compressed chunks `strings` can't see) and
matches a curated signature DB; `util.trailing_data` catches raw polyglots.

```python
DIRECTION = "request"

def match(flow):
    if flow.method == "POST" and flow.path.endswith(("/upload", "/images", "/avatar")):
        data = flow.content
        hit = util.find_payload(data, qr=True)          # scans bytes, chunks, QR…
        if hit:
            return {"drop": True, "reason": "%s in upload (%s): %s" % (
                hit["category"], hit["source"], hit["label"])}
        if util.magic(data) in ("png", "jpg") and util.trailing_data(data):
            return {"drop": True, "reason": "%d bytes appended after the image"
                    % len(util.trailing_data(data))}
    return False
```
*The checker uploads a clean image / a benign QR: no signature matches in any
layer and the image ends exactly at `IEND`/EOI, so nothing drops. The signatures
are specific (`UNION SELECT`, `/dev/tcp/…`, `<?php`, …) — an ordinary photo won't
contain them. Narrow the categories (e.g. `util.find_payload(data, ("sqli",),
qr=True)`) to the one the service is actually vulnerable to.*

To inspect what a filter sees, run `util.inspect(flow.content, qr=True)` in the
Test panel — it reports the file type, appended bytes, the text layers found, and
the first signature hit.

### 10. Static path traversal / SSRF
*CCalendar — `/static//etc/passwd` and `/static/http://api/...` escape the
resource dir.* Normalize the tail and reject anything that leaves the folder.

```python
DIRECTION = "request"
PREFIX = "/static/"

def match(flow):
    p = flow.path
    if p.startswith(PREFIX) and util.path_escapes(p[len(PREFIX):]):
        return {"drop": True, "reason": "static path escapes the resource directory"}
    return False
```
*Checker fetches `/static/app.js` → tail `app.js` is a plain relative file, so
`path_escapes` is False.*

### 11. Algorithm allowlist
*ENOWARS SCEAM — the export "algorithm" is eval-like; a crafted HMAC config
exports someone else's image.* It must be a name from a fixed set, not an
expression.

```python
DIRECTION = "request"
ALGOS = {"AES256", "AES128", "NONE"}

def match(flow):
    if flow.path.endswith("/export"):
        alg = str((flow.json() or {}).get("algorithm", ""))
        if alg and alg not in ALGOS:
            return {"drop": True, "reason": "algorithm not in allowlist: %r" % alg[:40]}
    return False
```
*Checker picks one of the enumerated names; `.hmac_hash(hashes.SHA1())` isn't in
the set.*

---

## Level 3 — semantic payload

### 12. JOIN result-length overflow
*ExCCel — the size check forgets the `,` separators a `JOIN` inserts, so a JOIN
over many (even empty) cells overflows.* Bound the range span, since each element
adds a separator regardless of content.

```python
import re
DIRECTION = "request"
JOIN = re.compile(r"JOIN\(\s*[A-Z]+(\d+)\s*:\s*[A-Z]+(\d+)", re.I)

def match(flow):
    formula = str((flow.json() or {}).get("formula", ""))
    m = JOIN.search(formula)
    if m:
        span = abs(int(m.group(2)) - int(m.group(1))) + 1
        if span > 32:
            return {"drop": True, "reason": "JOIN over %d cells overflows via separators" % span}
    return False
```
*Checker uses small ranges; `=JOIN(C1:C64, A1)` spans 64 cells. (Heuristic on the
range span — tune `32` to the real buffer.)*

### 13. Marker that appears only after sanitization
*Inlook — a message is classified as an invite **before** sanitization; a leading
backtick is stripped afterwards and the invite marker becomes valid.* Classify
the *normalized* text too, and drop when normalization *creates* the marker.

```python
DIRECTION = "request"
MARKER = "=====MAILING LIST INVITE====="
STRIP = str.maketrans("", "", "`'{}\\")

def is_invite(s):
    return any(line.startswith(MARKER) for line in s.split("\n"))

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/message"):
        body = str((flow.json() or {}).get("content", ""))
        if is_invite(body.translate(STRIP)) and not is_invite(body):
            return {"drop": True, "reason": "invite marker appears only after sanitization"}
    return False
```
*The service classifies a message as an invite when a line **starts** with the
marker. A leading backtick moves the marker off the line start (so `is_invite` is
False), but sanitizing strips it and the line then starts with the marker. The
checker's unsafe-char probes don't become invites once stripped; a genuine invite
starts with the marker before and after, so `not is_invite(body)` is False.*

### 14. Crypto-oracle input (uniform blocks)
*Inlook / ArcaneLink — a structured plaintext (`0xff`×32 then repeated blocks)
turns encrypt-then-reflect into an oracle.* Real mail is high-entropy; flag long
uniform runs, repeated blocks, or very low entropy.

```python
DIRECTION = "request"

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/mail"):
        data = flow.content
        if util.longest_run(data) >= 32 or util.repeated_block(data, 16) or \
                (len(data) >= 64 and util.entropy(data) < 2.0):
            return {"drop": True, "reason": "structured low-entropy payload (crypto oracle)"}
    return False
```
*Checker mail is 100–200 random-ish chars: entropy well above 2, no 32-byte run,
no repeated 16-byte block.*

### 15. Parameter pollution + shell metacharacters
*SaarCTF Pasteable — `nonce[]` collapses the HMAC key and `modifiers` reaches a
shell.* The checker never touches this endpoint, so it can be strict.

```python
import re
DIRECTION = "request"
SHELL = re.compile(r"[;|&`$><\n]|\$\(")

def match(flow):
    if flow.path.endswith("/ntp"):
        q = flow.query
        if "nonce[]" in q or len(q.all("nonce")) > 1:
            return {"drop": True, "reason": "nonce parameter pollution"}
        if SHELL.search(str(q["modifiers"])):
            return {"drop": True, "reason": "shell metacharacters in modifiers"}
    return False
```
*The checker's flag flow (register → challenge → login → paste) never calls
`/ntp`, so this filter can't affect it at all.*

---

## Level 4 — stateful flow

These use `flow.state`, which is bounded and private to the current filter and
Janus connection/session. If an HTTP detector must span transport connections,
use a bounded module-level dictionary keyed by a **session cookie** or
credential (SNAT-safe—never only by IP).

### 16. Login flood against one victim
*CookingNonna — the exploit opens ~253 failed logins against the victim's
username to groom file descriptors before a null-byte overflow.* Count login
attempts **per username** on the connection.

```python
DIRECTION = "request"
CMDS = {b"1": ("login", ("user", "pw"))}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "login":
            k = "u:" + cmd.user.decode("latin1", "ignore")
            n = flow.state.get(k, 0) + 1
            flow.state[k] = n
            if n >= 30:
                return {"drop": True, "reason": "login flood: %d attempts on one user" % n}
    return False
```
*The checker does a single correct login, so the per-user counter never
approaches 30. Empty argument lines are preserved by `flow.commands`, so field
positions do not shift across an empty password. The long vault names the
checker uses are deliberately not what we match.*

### 17. Repeated protocol INIT (challenge reuse)
*Fonograph — the Schnorr challenge isn't regenerated; two `INIT`s before `FINISH`
break it.* Track the protocol state per connection.

```python
DIRECTION = "request"
CMDS = {b"INIT": ("init", 0), b"FINISH": ("finish", 0)}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "init":
            if flow.state.get("state") == "challenged":
                return {"drop": True, "reason": "second INIT without FINISH (challenge reuse)"}
            flow.state["state"] = "challenged"
        elif cmd.name == "finish":
            flow.state["state"] = "idle"
    return False
```
*The checker runs `INIT` → `FINISH`, so a second `INIT` never arrives while a
challenge is outstanding.*

### 18. Byte-at-a-time compare oracle
*ArcaneLink — `CHK_KEY` leaks the `memcmp` result, so the key is recovered a byte
at a time.* The checker verifies once with the right key; the attacker hammers the
same UID.

```python
DIRECTION = "request"
CMDS = {b"CHK_KEY": ("chk", ("uid", "key"))}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "chk":
            k = "n:" + cmd.uid.decode("latin1", "ignore")
            n = flow.state.get(k, 0) + 1
            flow.state[k] = n
            if n >= 16:
                return {"drop": True, "reason": "%d CHK_KEY on the same UID (compare oracle)" % n}
    return False
```
*One legitimate `CHK_KEY` per UID never reaches 16. (Refinement: also require the
successive keys to share a growing common prefix.)*

### 19. Author overwrite between open and answer
*Duogesto — listing another user's challenges overwrites the session's "author",
so answering your own question pays out the victim's reward.* A listing between
opening a question and answering it is the tell.

```python
DIRECTION = "request"

def match(flow):
    c = flow.state
    p = flow.path
    if p.endswith("/challenge/open"):
        c["open"], c["listed"] = True, False
    elif p.endswith("/challenges"):
        if c.get("open"):
            c["listed"] = True
    elif p.endswith("/challenge/answer"):
        if c.get("open") and c.get("listed"):
            return {"drop": True, "reason": "author overwritten by a listing before answering"}
    return False
```
*The checker's order is list → open → answer: the listing happens **before** the
open, so `listed` is reset to False by the open and the answer is clean.*

### 20. IDOR: object never created in this session
*CCForms — `/form/:id/answers` (and embedded forms) don't check ownership.* Learn
the ids this session created from the **responses**, then block reads of an id it
never made. Select both directions and use Inline mode for ordinary HTTP/1.1 or
HTTPS responses that fit in Janus's response buffer.

```python
import re
ANSWERS = re.compile(r"/form/([^/]+)/answers")

def match(flow):
    c = flow.state
    if flow.is_response:
        data = flow.json() or {}
        fid = data.get("id") or data.get("form_id")
        if fid and "/form" in flow.request.path:
            c.setdefault("owned", set()).add(str(fid))
        return False
    m = ANSWERS.search(flow.path)
    if m and m.group(1) not in c.get("owned", set()):
        return flow.drop("reading answers of form %s never created in this session" % m.group(1))
    return False
```
*The checker creates a form (its response teaches us the id), then reads that same
id—which is in `owned`. The exploit reads the victim's id without ever creating
it. On streaming/oversized HTTP responses, HTTP/2, or gRPC, response evaluation
is observe-only, so validate the exact service path before relying on this block.*

---

## Level 5 — when a traffic filter can't be trusted

Some bugs can't be told apart from legitimate traffic by looking at bytes,
because the attacker's decisive step happens **offline**:

- **CCForms weak JWT secret** — `$RANDOM` has 32768 values; the attacker brute
  forces the key offline and then presents a *cryptographically valid* JWT,
  byte-identical to a real one.
- **ExCCel share-token forging** / **Inlook factor-from-signature** — the forged
  token or the factoring is computed off-box; the request that uses the result
  looks exactly like the checker's.
- **ENOWARS SCEAM reversible blur** — the attacker just downloads the public
  blurred image (a normal request) and de-blurs it locally.

For these the only real defense is **fixing the service**. A filter can at best
add **token binding** — remember what the server actually issued and reject tokens
it never handed out:

```python
issued = set()   # tokens the server has really minted

def match(flow):
    if flow.is_response:
        tok = (flow.json() or {}).get("token")
        if tok:
            issued.add(str(tok))
        return False
    auth = flow.header("authorization")
    if auth.startswith("Bearer "):
        tok = auth[7:]
        if tok and tok not in issued:
            return "bearer token that was never issued by the server (possible forgery)"
    return False
```
*Start in Observe because it needs to see issuing responses and will
false-positive on tokens minted before the filter started. It can become a
Block filter on ordinary buffered HTTP/HTTPS after the state has warmed up.*

---

## Testing your filters

Use the **Test** panel on the Python Filters page: build a Request/Response
sample, or load a real captured packet (or a whole request+response **flow**)
server-side by packet ID. The selected mode and scope are enforced. Whole-flow
tests replay `match()` over the packets in order, so stateful and
`flow.commands` filters see the real sequence. Always test the **checker's**
happy path too and confirm it shows *no match* — that's what keeps a filter from
costing you SLA.
