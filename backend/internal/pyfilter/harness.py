"""Janus Python-filter harness (mitmproxy-style addons).

Runs as a long-lived worker driven by newline-delimited JSON over stdin/stdout.
User scripts each define:

    def match(flow):
        # `flow` is still a dict (flow["body"], flow.get(...) work), plus a
        # forgiving, quick-to-write API — a missing field reads as "" (never
        # crashes). Works for HTTP and TCP, in every mode.
        #
        #   flow.method / url / path / status / service / direction
        #   flow.is_request / flow.is_response
        #   flow.headers["Cookie"]          # case-insensitive, missing -> ""
        #   flow.query["id"]  flow.cookies["session"]   # forgiving dicts
        #   flow.body (str)   flow.bytes    flow.json()  # parsed body or None
        #   flow.request / flow.response    # correlated sides (never None)
        #   flow.messages[-1]               # most recent message (this service)
        #   flow.recent(3)  flow.last_request  flow.requests  flow.responses
        #
        # Payload analysis — `util` (injected into every filter), stdlib-only:
        #   util.is_base64(s)  util.valid_json(s)  util.extra_keys(obj, allowed)
        #   util.entropy(b)  util.longest_run(b)  util.repeated_block(b)
        #   util.magic(b)  util.content_type_ok(ct, b)  util.trailing_data(b)
        #   util.normpath(p)  util.uri_scheme(s)  util.path_escapes(p)
        #   # deep file/image inspection (decodes QR + hidden text layers):
        #   util.find_payload(b, qr=True)  util.qr_decode(b)  util.inspect(b)
        #   util.text_layers(b)  util.scan(b, patterns)  util.strings(b)
        #
        # TCP streams (a continuous byte flow, not one-message-per-chunk):
        #   flow.conn                       # dict persisting for the whole TCP
        #                                   #   connection — your per-conn state,
        #                                   #   private to this filter
        #   for line in flow.lines:         # complete lines, reassembled across
        #       ...                         #   chunks by Janus (bytes, exact)
        #   for cmd in flow.commands(       # parse a line-based CLI into commands
        #       {b"1": ("register",         #   trigger line -> (name, arg spec);
        #                ("user","pw"))}):  #   arg spec = a count, or field names
        #       cmd.user, cmd.pw            #   named args (or cmd.arg(0)); never
        #                                   #   unpack cmd.args — arities vary
        #
        # NOTE: match(flow) runs once per message, on BOTH directions. Use
        # flow.is_request / flow.is_response (or flow.direction) to tell them
        # apart, or set a module-level DIRECTION = "request" | "response" to have
        # Janus skip the other side for you. A Blocking filter can drop or
        # rewrite either a request or a response in real time.
        #
        # return one of:
        #   False / None            -> no match
        #   True                    -> match (no reason)
        #   "some reason string"    -> match with a reason shown in Alerts
        #   {"match": True, "reason": "...", "drop": True}   (or "block": True)
        #       -> match; drops the CURRENT message in real time (inline): a
        #          request is blocked before it reaches the backend, a response
        #          before it reaches the client (the connection is closed). Only
        #          takes effect for scripts marked "Blocking", which run
        #          synchronously on the proxy hot path. Any truthy "drop" value
        #          works, so {"drop": "some reason"} blocks too.
        #
        # Inline REWRITE (Blocking filters only): assign flow.body = "..." (HTTP)
        # or flow.content = b"..." (TCP) to rewrite the current message before
        # Janus forwards it — works on requests and responses (e.g. redact a
        # flag from a response). Applies whether or not you also return a match;
        # ignored for non-Blocking (async) filters.
        return False

Module-level state persists across calls, so a script can count things over
time (e.g. "this user logged in more than once").

Protocol (one JSON object per line):
  <- {"cmd":"load","scripts":[{"id","name","code"}...]}
  -> {"cmd":"load","ok":bool,"errors":{id:msg}}
  <- {"cmd":"eval","id":N,"packet":{...}}
  -> {"id":N,"matches":[{"script","name","reason","error"}...]}
  <- {"cmd":"test","id":N,"script":{...},"packet":{...}}
  -> {"id":N,"matches":[...]}  or  {"id":N,"error":"..."}
  <- {"cmd":"ping"} -> {"pong":true}
"""
import sys
import json
import base64
import math
import posixpath
import re
import traceback
from collections import deque, OrderedDict, Counter
from urllib.parse import urlsplit, parse_qs, unquote

# A parsed CLI command yielded by flow.commands(spec): its name, its argument
# lines (bytes), and whether a flag ID appeared anywhere within it.
#
# Access args safely — never unpack a raw list whose length can vary between
# commands:
#   cmd.args              # the list of argument lines (bytes)
#   cmd.arg(0)            # positional, "" if missing (no IndexError)
#   cmd.user, cmd.pw      # by name, when the spec declared field names, e.g.
#                         #   {b"1": ("register", ("user", "pw"))}
class Command:
    __slots__ = ("name", "args", "flagid", "_names")

    def __init__(self, name, args, flagid, names=()):
        self.name = name
        self.args = list(args)
        self.flagid = flagid
        self._names = tuple(names)

    def arg(self, i, default=b""):
        """The i-th argument line, or default if the command has fewer args."""
        return self.args[i] if -len(self.args) <= i < len(self.args) else default

    def field(self, name, default=b""):
        """The argument declared under `name` in the spec, or default."""
        try:
            return self.args[self._names.index(name)]
        except (ValueError, IndexError):
            return default

    def __getattr__(self, name):
        # cmd.<declared-name> -> that argument (b"" if the arg is absent).
        names = object.__getattribute__(self, "_names")
        if name in names:
            return self.field(name)
        raise AttributeError(name)

    def __iter__(self):
        # Back-compat: `name, args, flagid = cmd` still works.
        return iter((self.name, self.args, self.flagid))

    def __repr__(self):
        return "Command(name=%r, args=%r, flagid=%r)" % (self.name, self.args, self.flagid)

# id -> {"name": str, "fn": callable}
SCRIPTS = {}

# --- ergonomic flow object -------------------------------------------------
# match(flow) receives a Flow: still a plain dict (flow["body"], flow.get(...)
# keep working), plus forgiving attribute access + HTTP/TCP helpers so filters
# are quick to write and never crash on a missing field.

_HISTORY = {}        # service -> deque[Flow] of recently evaluated messages
_HISTORY_MAX = 32

# Per-TCP-connection scratch, persisting across every chunk of a connection
# (both directions):
#   "linebuf"  — internal line-reassembly buffer, shared (it's the raw byte
#                stream, identical for every script)
#   "state"    — flow.conn, namespaced per script id so two filters can use the
#                same key name without clobbering each other
#   "cmdstate" — internal flow.commands() pending state, per script id
_CONNS = OrderedDict()   # conn_key -> {"linebuf": {}, "state": {sid: {}}, "cmdstate": {sid: {}}}
_CONNS_MAX = 4096
_LINEBUF_MAX = 1 << 16   # cap a single unterminated line


def _conn_key(flow):
    # Direction-independent: request and response of the same connection share it.
    svc = flow.get("service") or ""
    a = (flow.get("src") or "", flow.get("sport") or 0)
    b = (flow.get("dst") or "", flow.get("dport") or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return (svc, lo, hi)


def _conn_record(flow):
    k = _conn_key(flow)
    rec = _CONNS.get(k)
    if rec is None:
        rec = {"linebuf": {}, "state": {}, "cmdstate": {}}
        _CONNS[k] = rec
        if len(_CONNS) > _CONNS_MAX:
            _CONNS.popitem(last=False)   # evict the oldest connection
    else:
        _CONNS.move_to_end(k)
    return rec


class _Headers:
    """Case-insensitive header view; a missing header reads as ""."""

    def __init__(self, d):
        self._d = d or {}
        self._l = {str(k).lower(): v for k, v in self._d.items()}

    def __getitem__(self, k):
        return self._l.get(str(k).lower(), "")

    def get(self, k, default=""):
        return self._l.get(str(k).lower(), default)

    def __contains__(self, k):
        return str(k).lower() in self._l

    def __iter__(self):
        return iter(self._d)

    def keys(self):
        return self._d.keys()

    def items(self):
        return self._d.items()

    def values(self):
        return self._d.values()

    def __bool__(self):
        return bool(self._d)

    def __repr__(self):
        return repr(self._d)


class _Bag(dict):
    """A dict whose missing keys read as "" (used for cookies)."""

    def __missing__(self, k):
        return ""

    def get(self, k, default=""):
        return dict.get(self, k, default)


class _Query:
    """Forgiving query-string view: q["id"] -> first value ("" if absent),
    q.all("id") -> every value."""

    def __init__(self, url):
        self._q = parse_qs(urlsplit(url or "").query, keep_blank_values=True)

    def __getitem__(self, k):
        v = self._q.get(k)
        return v[0] if v else ""

    def get(self, k, default=""):
        v = self._q.get(k)
        return v[0] if v else default

    def all(self, k):
        return list(self._q.get(k, []))

    def __contains__(self, k):
        return k in self._q

    def keys(self):
        return self._q.keys()

    def items(self):
        return [(k, v[0] if v else "") for k, v in self._q.items()]

    def __bool__(self):
        return bool(self._q)

    def __repr__(self):
        return repr({k: (v[0] if v else "") for k, v in self._q.items()})


def _parse_cookies(raw):
    out = _Bag()
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


class Flow(dict):
    """Ergonomic wrapper around the raw flow dict (still a dict, backward
    compatible). Adds forgiving attribute access + HTTP/TCP helpers."""

    # -- core fields (forgiving: missing -> "" / 0) --
    @property
    def method(self):
        return self.get("method", "") or ""

    @property
    def url(self):
        return self.get("url", "") or ""

    @property
    def status(self):
        return self.get("status", 0) or 0

    @property
    def service(self):
        return self.get("service", "") or ""

    @property
    def direction(self):
        return self.get("direction", "") or ""

    @property
    def src(self):
        return self.get("src", "") or ""

    @property
    def dst(self):
        return self.get("dst", "") or ""

    @property
    def sport(self):
        return self.get("sport", 0) or 0

    @property
    def dport(self):
        return self.get("dport", 0) or 0

    @property
    def flagged(self):
        return bool(self.get("flagged"))

    @property
    def contains_flagid(self):
        return bool(self.get("contains_flagid"))

    @property
    def is_request(self):
        return self.direction == "request"

    @property
    def is_response(self):
        return self.direction == "response"

    # -- body (str) / content (bytes) — settable for inline rewriting --
    @property
    def body(self):
        b = self.get("body", "")
        return b if isinstance(b, str) else (b or "")

    @body.setter
    def body(self, value):
        # Rewrite the current message's body (inline/Blocking filters only).
        if isinstance(value, (bytes, bytearray)):
            self.content = bytes(value)
        else:
            text = str(value)
            self["body"] = text
            self["__new_bytes"] = text.encode("utf-8")

    @property
    def content(self):
        # Exact bytes (mutated value if rewritten, else base64 payload for TCP,
        # else utf-8 of the text body).
        nb = self.get("__new_bytes")
        if nb is not None:
            return nb
        b64 = self.get("body_b64")
        if b64:
            try:
                return base64.b64decode(b64)
            except Exception:
                pass
        b = self.get("body", "")
        return b.encode("utf-8", "replace") if isinstance(b, str) else (b or b"")

    @content.setter
    def content(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        value = bytes(value)
        self["__new_bytes"] = value
        self["body"] = value.decode("utf-8", "replace")  # keep .body/.json usable

    bytes = content  # alias: exact bytes (mutated if rewritten)

    def json(self, default=None):
        try:
            return json.loads(self.body)
        except Exception:
            return default

    # -- headers / url parts (all forgiving) --
    @property
    def headers(self):
        return _Headers(self.get("headers") or {})

    def header(self, name, default=""):
        return self.headers.get(name, default)

    @property
    def path(self):
        return urlsplit(self.url).path

    @property
    def query(self):
        return _Query(self.url)

    params = query

    @property
    def cookies(self):
        return _parse_cookies(self.headers.get("cookie", ""))

    # -- history / recency (per service, most-recent last) --
    @property
    def messages(self):
        dq = _HISTORY.get(self.service)
        return list(dq) if dq else [self]

    def recent(self, n=3):
        msgs = self.messages
        return msgs[-n:] if n and n > 0 else msgs

    @property
    def requests(self):
        return [m for m in self.messages if m.is_request]

    @property
    def responses(self):
        return [m for m in self.messages if m.is_response]

    @property
    def last_request(self):
        for m in reversed(self.messages[:-1]):
            if m.is_request:
                return m
        return _EMPTY

    @property
    def last_response(self):
        for m in reversed(self.messages[:-1]):
            if m.is_response:
                return m
        return _EMPTY

    @property
    def request(self):
        return self if self.is_request else self.last_request

    @property
    def response(self):
        return self if self.is_response else self.last_response

    # -- TCP streams: per-connection state + line reassembly (no manual buffer) --
    def _conn_ns(self, bucket):
        # Per-(connection, script) namespace inside `bucket` of the conn record.
        # Namespacing by script id means two filters can use the same conn key
        # name without stepping on each other.
        sid = self.get("__sid") or ""
        return _conn_record(self)[bucket].setdefault(sid, {})

    @property
    def conn(self):
        """A dict that persists across every message of THIS TCP connection
        (both directions, keyed by service + endpoints). Use it for per-
        connection state instead of a global keyed by src/port. Each filter
        gets its own namespace, so your keys never collide with another
        filter's."""
        return self._conn_ns("state")

    @property
    def lines(self):
        """The complete lines newly available on this direction's stream, with
        the line terminator removed. Janus buffers the partial remainder across
        chunks, so you never manage a byte buffer yourself. Returns bytes (exact,
        binary-safe). Empty when the chunk holds no complete line yet."""
        cached = self.get("__lines")
        if cached is not None:
            return cached
        rec = _conn_record(self)
        d = self.direction or ""
        buf = rec["linebuf"].get(d, b"") + self.content
        parts = buf.split(b"\n")
        tail = parts[-1]
        if len(tail) > _LINEBUF_MAX:
            tail = tail[-_LINEBUF_MAX:]
        rec["linebuf"][d] = tail            # keep the unterminated remainder
        out = [(p[:-1] if p.endswith(b"\r") else p) for p in parts[:-1]]
        self["__lines"] = out
        return out

    def commands(self, spec):
        """Parse this connection's line stream into CLI commands, so you don't
        write the state machine yourself. `spec` maps a trigger line to either
        (name, n_args) — the trigger line followed by n_args argument lines — or
        (name, ("field", ...)) to also name those arguments. Returns the Command
        values completed by THIS chunk; cross-chunk buffering and flag-ID
        tracking are handled for you. Access args safely with cmd.arg(i) or, when
        named, cmd.<field> — never unpack cmd.args blindly (arities can differ):

            SPEC = {b"1": ("register", ("user", "pw")),
                    b"2": ("login", ("user", "pw"))}
            for cmd in flow.commands(SPEC):
                if cmd.name == "login" and cmd.flagid:
                    check(cmd.user, cmd.pw)      # by name, "" if missing
        """
        # Normalize each spec value to (name, need, field_names). The arg spec is
        # either an int (count) or a sequence of field names.
        table = {}
        for k, v in spec.items():
            key = k if isinstance(k, bytes) else str(k).encode()
            cmd_name, argspec = v[0], v[1]
            if isinstance(argspec, int):
                need, names = argspec, ()
            else:
                names = tuple(argspec)
                need = len(names)
            table[key] = (cmd_name, need, names)
        # The per-message result cache and the cross-chunk pending state are keyed
        # by (script, spec): filters never clobber each other's parse, and one
        # filter can even parse the same stream with two different tables.
        spec_key = tuple(sorted((k, nm, need) for k, (nm, need, _) in table.items()))
        cache = self.setdefault("__commands", {})
        cache_key = (self.get("__sid") or "", spec_key)
        if cache_key in cache:
            return cache[cache_key]
        pending = self._conn_ns("cmdstate")
        cur = pending.get(spec_key)
        flagid = bool(self.contains_flagid)
        out = []
        for line in self.lines:
            line = line.strip()
            if not line:
                continue
            if cur is not None:                 # collecting a pending command's args
                cur["args"].append(line)
                cur["flag"] = cur["flag"] or flagid
                if len(cur["args"]) >= cur["need"]:
                    out.append(Command(cur["name"], cur["args"], cur["flag"], cur["names"]))
                    cur = None
            else:
                hit = table.get(line)
                if hit is not None:             # a trigger line -> start a command
                    name, need, names = hit
                    if need <= 0:
                        out.append(Command(name, [], flagid, names))
                    else:
                        cur = {"name": name, "need": need, "args": [], "flag": flagid, "names": names}
        if cur is not None and flagid:          # keep the flag "sticky" across chunks
            cur["flag"] = True
        pending[spec_key] = cur
        cache[cache_key] = out
        return out

    # -- attribute fallback: flow.<key> -> flow["<key>"], missing -> "" --
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError:
            return ""


_EMPTY = Flow()


def _record(flow):
    """Append the flow to its service's bounded recent-history deque."""
    svc = flow.get("service") or ""
    dq = _HISTORY.get(svc)
    if dq is None:
        dq = deque(maxlen=_HISTORY_MAX)
        _HISTORY[svc] = dq
    dq.append(flow)


def _rewrite_of(flow):
    """If a script rewrote the flow's content, return the new bytes (base64) for
    Janus to forward; else None. Honored only on the inline path."""
    nb = flow.get("__new_bytes")
    if nb is None:
        return None
    return {"content_b64": base64.b64encode(nb).decode("ascii")}


def _norm_direction(v):
    """Normalize an optional DIRECTION constant to "request"/"response"/None."""
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    if s.startswith("req"):
        return "request"
    if s.startswith("res"):
        return "response"
    return None


# --- util: analysis helpers injected into every script namespace as `util` ----
# Stdlib-only, side-effect-free. Meant for validating/inspecting a payload right
# in a filter so it can drop immediately: base64 canonicity, entropy & repeated
# blocks (crypto oracles), file magic vs Content-Type, trailing/polyglot data,
# path normalization & traversal, URI schemes, JSON well-formedness.

_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"\x1f\x8b", "gzip"),
    (b"\x7fELF", "elf"), (b"BM", "bmp"), (b"\x00\x00\x01\x00", "ico"),
    (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
]
_CT_MAGIC = {
    "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif",
    "image/webp": "webp", "image/bmp": "bmp", "image/svg+xml": "svg",
    "image/x-icon": "ico", "image/vnd.microsoft.icon": "ico",
    "image/tiff": "tiff", "application/pdf": "pdf",
    "application/zip": "zip", "application/gzip": "gzip",
}
_DANGEROUS_SCHEMES = ("file", "gopher", "dict", "telnet", "ldap", "jar",
                      "mailto", "data", "javascript", "php", "expect", "netdoc")
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(//)?")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode("utf-8", "replace")


def _as_text(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).decode("utf-8", "replace")
    return str(x)


# --- file inspection: text layers, signatures, QR decoding --------------------
# Goal: given an uploaded file/image, decode its bytes, pull out *every* text
# layer a payload could hide in (including compressed ones that `strings` can't
# see — PNG text chunks, PDF Flate streams, ZIP entries — and a QR code's decoded
# content), then match it against a curated attack-signature database so a filter
# can drop immediately. All stdlib-only (zlib, zipfile).

import zlib
import zipfile
import io


def _strings(data, min_len=4):
    """Printable-ASCII runs of length >= min_len (like the `strings` command)."""
    d = _as_bytes(data)
    out, cur = [], bytearray()
    for b in d:
        if 0x20 <= b <= 0x7e:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def _png_chunks(d):
    """Yield (type, chunk_data) for a PNG, best-effort."""
    i = 8
    n = len(d)
    while i + 8 <= n:
        ln = int.from_bytes(d[i:i + 4], "big")
        typ = d[i + 4:i + 8]
        body = d[i + 8:i + 8 + ln]
        yield typ, body
        i += 12 + ln  # length + type + data + CRC
        if typ == b"IEND":
            break


def _png_text(d):
    """Decoded values of PNG tEXt/zTXt/iTXt chunks (payloads hide here — zTXt is
    zlib-compressed, so raw `strings` never sees it)."""
    out = []
    try:
        for typ, body in _png_chunks(d):
            if typ == b"tEXt":
                _, _, val = body.partition(b"\x00")
                out.append(val.decode("latin1", "replace"))
            elif typ == b"zTXt":
                kw, _, rest = body.partition(b"\x00")
                comp = rest[1:] if rest else b""
                try:
                    out.append(zlib.decompress(comp).decode("latin1", "replace"))
                except Exception:
                    pass
            elif typ == b"iTXt":
                parts = body.split(b"\x00", 5)
                if len(parts) >= 6:
                    flag = parts[1][:1]
                    txt = parts[5]
                    if flag == b"\x01":
                        try:
                            txt = zlib.decompress(txt)
                        except Exception:
                            pass
                    out.append(_as_text(txt))
    except Exception:
        pass
    return out


def _pdf_text(d):
    """Raw PDF plus every FlateDecode stream inflated — surfaces /JavaScript,
    /OpenAction, /Launch and text hidden inside compressed streams."""
    out = [d.decode("latin1", "replace")]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", d, re.S):
        try:
            out.append(zlib.decompress(m.group(1)).decode("latin1", "replace"))
        except Exception:
            pass
    return out


def _zip_text(d):
    """ZIP/Office entry names + inflated text entries (macros, embedded files)."""
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(d))
        out.append("\n".join(zf.namelist()))
        for name in zf.namelist():
            try:
                info = zf.getinfo(name)
                if info.file_size <= 262144:
                    raw = zf.read(name)
                    if _Util.printable_ratio(raw) > 0.7:
                        out.append(raw.decode("latin1", "replace"))
            except Exception:
                pass
    except Exception:
        pass
    return out


# Curated attack signatures. Kept specific so a benign uploaded file/image the
# checker sends won't match — matches mean an actual payload was smuggled in.
def _sig(*pairs):
    return [(re.compile(p, re.I | re.S), lbl) for p, lbl in pairs]


_SIG_DB = [
    ("sqli", _sig(
        (r"\bunion\b[\s/*]+\bselect\b", "UNION SELECT"),
        (r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "OR n=n"),
        (r"'\s*or\s+'?1'?\s*=\s*'?1", "' OR 1=1"),
        (r";\s*drop\s+table\b", "DROP TABLE"),
        (r"\b(sleep|benchmark|pg_sleep)\s*\(", "time-based SQLi"),
        (r"\binto\s+outfile\b|\bload_file\s*\(", "file SQLi"),
        (r"\binformation_schema\b", "information_schema"),
        (r"\bxp_cmdshell\b", "xp_cmdshell"),
    )),
    ("shell", _sig(
        (r"/bin/(?:ba|z|d)?sh\b", "/bin/sh"),
        (r"\b(?:ba)?sh\s+-i\b", "interactive shell"),
        (r"\bnc(?:at)?\b[^\n]*\s-e\b", "nc -e"),
        (r"/dev/tcp/\d", "/dev/tcp reverse shell"),
        (r"\b(?:os\.system|subprocess\.(?:call|Popen|run)|pty\.spawn)\s*\(", "python exec"),
        (r"\bpowershell\b[^\n]*(?:-enc|-e |downloadstring|iex)", "powershell payload"),
        (r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(", "command exec"),
    )),
    ("php", _sig(
        (r"<\?php\b|<\?=", "PHP tag"),
        (r"\beval\s*\(\s*\$", "PHP eval($var)"),
        (r"\b(?:base64_decode|assert|create_function)\s*\(", "PHP dynamic exec"),
    )),
    ("xss", _sig(
        (r"<script[\s>]", "<script>"),
        (r"\bon(?:error|load|click|mouseover)\s*=", "inline event handler"),
        (r"javascript:", "javascript: URI"),
    )),
    ("xxe", _sig(
        (r"<!ENTITY\b", "XML entity"),
        (r"<!DOCTYPE[^>]+SYSTEM\b", "external DOCTYPE"),
    )),
    ("template", _sig(
        (r"\{\{[^}]*(?:config|self|request|__|\.__)[^}]*\}\}", "SSTI {{...}}"),
        (r"\$\{[^}]*(?:T\(|Runtime|exec)[^}]*\}", "SSTI ${...}"),
    )),
    ("traversal", _sig(
        (r"(?:\.\./){2,}|(?:\.\.\\){2,}", "path traversal"),
        (r"/etc/passwd\b|/etc/shadow\b", "sensitive file"),
        (r"\bfile://", "file:// scheme"),
    )),
]


# ---- QR decoding (pure Python; PNG -> module matrix -> data) ----
# Best-effort decoder for clean, axis-aligned QR codes (as produced by upload
# tooling), all versions 1-40, numeric/alnum/byte, all masks. No error correction:
# it reads the data codewords of an undamaged symbol. Returns [] on any trouble.

# Alignment-pattern centres and EC block structure for all 40 versions (this
# table is generated from / verified against the QR spec, so any realistic
# payload — the last event had ~850-byte QR PNGs — decodes, not just small ones).
_QR_ALIGN = {1: [],
    2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
    15: [6, 26, 48, 70], 16: [6, 26, 50, 74], 17: [6, 30, 54, 78],
    18: [6, 30, 56, 82], 19: [6, 30, 58, 86], 20: [6, 34, 62, 90],
    21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98], 23: [6, 30, 54, 78, 102],
    24: [6, 28, 54, 80, 106], 25: [6, 32, 58, 84, 110], 26: [6, 30, 58, 86, 114],
    27: [6, 34, 62, 90, 118], 28: [6, 26, 50, 74, 98, 122],
    29: [6, 30, 54, 78, 102, 126], 30: [6, 26, 52, 78, 104, 130],
    31: [6, 30, 56, 82, 108, 134], 32: [6, 34, 60, 86, 112, 138],
    33: [6, 30, 58, 86, 114, 142], 34: [6, 34, 62, 90, 118, 146],
    35: [6, 30, 54, 78, 102, 126, 150], 36: [6, 24, 50, 76, 102, 128, 154],
    37: [6, 28, 54, 80, 106, 132, 158], 38: [6, 32, 58, 84, 110, 136, 162],
    39: [6, 26, 54, 82, 110, 138, 166], 40: [6, 30, 58, 86, 114, 142, 170]}
# (version, level) -> (ec_codewords_per_block, [(num_blocks, data_cw_per_block), ...])
_QR_ECB = {
    (1, "L"): (7, [(1, 19)]), (1, "M"): (10, [(1, 16)]), (1, "Q"): (13, [(1, 13)]), (1, "H"): (17, [(1, 9)]),
    (2, "L"): (10, [(1, 34)]), (2, "M"): (16, [(1, 28)]), (2, "Q"): (22, [(1, 22)]), (2, "H"): (28, [(1, 16)]),
    (3, "L"): (15, [(1, 55)]), (3, "M"): (26, [(1, 44)]), (3, "Q"): (18, [(2, 17)]), (3, "H"): (22, [(2, 13)]),
    (4, "L"): (20, [(1, 80)]), (4, "M"): (18, [(2, 32)]), (4, "Q"): (26, [(2, 24)]), (4, "H"): (16, [(4, 9)]),
    (5, "L"): (26, [(1, 108)]), (5, "M"): (24, [(2, 43)]), (5, "Q"): (18, [(2, 15), (2, 16)]), (5, "H"): (22, [(2, 11), (2, 12)]),
    (6, "L"): (18, [(2, 68)]), (6, "M"): (16, [(4, 27)]), (6, "Q"): (24, [(4, 19)]), (6, "H"): (28, [(4, 15)]),
    (7, "L"): (20, [(2, 78)]), (7, "M"): (18, [(4, 31)]), (7, "Q"): (18, [(2, 14), (4, 15)]), (7, "H"): (26, [(4, 13), (1, 14)]),
    (8, "L"): (24, [(2, 97)]), (8, "M"): (22, [(2, 38), (2, 39)]), (8, "Q"): (22, [(4, 18), (2, 19)]), (8, "H"): (26, [(4, 14), (2, 15)]),
    (9, "L"): (30, [(2, 116)]), (9, "M"): (22, [(3, 36), (2, 37)]), (9, "Q"): (20, [(4, 16), (4, 17)]), (9, "H"): (24, [(4, 12), (4, 13)]),
    (10, "L"): (18, [(2, 68), (2, 69)]), (10, "M"): (26, [(4, 43), (1, 44)]), (10, "Q"): (24, [(6, 19), (2, 20)]), (10, "H"): (28, [(6, 15), (2, 16)]),
    (11, "L"): (20, [(4, 81)]), (11, "M"): (30, [(1, 50), (4, 51)]), (11, "Q"): (28, [(4, 22), (4, 23)]), (11, "H"): (24, [(3, 12), (8, 13)]),
    (12, "L"): (24, [(2, 92), (2, 93)]), (12, "M"): (22, [(6, 36), (2, 37)]), (12, "Q"): (26, [(4, 20), (6, 21)]), (12, "H"): (28, [(7, 14), (4, 15)]),
    (13, "L"): (26, [(4, 107)]), (13, "M"): (22, [(8, 37), (1, 38)]), (13, "Q"): (24, [(8, 20), (4, 21)]), (13, "H"): (22, [(12, 11), (4, 12)]),
    (14, "L"): (30, [(3, 115), (1, 116)]), (14, "M"): (24, [(4, 40), (5, 41)]), (14, "Q"): (20, [(11, 16), (5, 17)]), (14, "H"): (24, [(11, 12), (5, 13)]),
    (15, "L"): (22, [(5, 87), (1, 88)]), (15, "M"): (24, [(5, 41), (5, 42)]), (15, "Q"): (30, [(5, 24), (7, 25)]), (15, "H"): (24, [(11, 12), (7, 13)]),
    (16, "L"): (24, [(5, 98), (1, 99)]), (16, "M"): (28, [(7, 45), (3, 46)]), (16, "Q"): (24, [(15, 19), (2, 20)]), (16, "H"): (30, [(3, 15), (13, 16)]),
    (17, "L"): (28, [(1, 107), (5, 108)]), (17, "M"): (28, [(10, 46), (1, 47)]), (17, "Q"): (28, [(1, 22), (15, 23)]), (17, "H"): (28, [(2, 14), (17, 15)]),
    (18, "L"): (30, [(5, 120), (1, 121)]), (18, "M"): (26, [(9, 43), (4, 44)]), (18, "Q"): (28, [(17, 22), (1, 23)]), (18, "H"): (28, [(2, 14), (19, 15)]),
    (19, "L"): (28, [(3, 113), (4, 114)]), (19, "M"): (26, [(3, 44), (11, 45)]), (19, "Q"): (26, [(17, 21), (4, 22)]), (19, "H"): (26, [(9, 13), (16, 14)]),
    (20, "L"): (28, [(3, 107), (5, 108)]), (20, "M"): (26, [(3, 41), (13, 42)]), (20, "Q"): (30, [(15, 24), (5, 25)]), (20, "H"): (28, [(15, 15), (10, 16)]),
    (21, "L"): (28, [(4, 116), (4, 117)]), (21, "M"): (26, [(17, 42)]), (21, "Q"): (28, [(17, 22), (6, 23)]), (21, "H"): (30, [(19, 16), (6, 17)]),
    (22, "L"): (28, [(2, 111), (7, 112)]), (22, "M"): (28, [(17, 46)]), (22, "Q"): (30, [(7, 24), (16, 25)]), (22, "H"): (24, [(34, 13)]),
    (23, "L"): (30, [(4, 121), (5, 122)]), (23, "M"): (28, [(4, 47), (14, 48)]), (23, "Q"): (30, [(11, 24), (14, 25)]), (23, "H"): (30, [(16, 15), (14, 16)]),
    (24, "L"): (30, [(6, 117), (4, 118)]), (24, "M"): (28, [(6, 45), (14, 46)]), (24, "Q"): (30, [(11, 24), (16, 25)]), (24, "H"): (30, [(30, 16), (2, 17)]),
    (25, "L"): (26, [(8, 106), (4, 107)]), (25, "M"): (28, [(8, 47), (13, 48)]), (25, "Q"): (30, [(7, 24), (22, 25)]), (25, "H"): (30, [(22, 15), (13, 16)]),
    (26, "L"): (28, [(10, 114), (2, 115)]), (26, "M"): (28, [(19, 46), (4, 47)]), (26, "Q"): (28, [(28, 22), (6, 23)]), (26, "H"): (30, [(33, 16), (4, 17)]),
    (27, "L"): (30, [(8, 122), (4, 123)]), (27, "M"): (28, [(22, 45), (3, 46)]), (27, "Q"): (30, [(8, 23), (26, 24)]), (27, "H"): (30, [(12, 15), (28, 16)]),
    (28, "L"): (30, [(3, 117), (10, 118)]), (28, "M"): (28, [(3, 45), (23, 46)]), (28, "Q"): (30, [(4, 24), (31, 25)]), (28, "H"): (30, [(11, 15), (31, 16)]),
    (29, "L"): (30, [(7, 116), (7, 117)]), (29, "M"): (28, [(21, 45), (7, 46)]), (29, "Q"): (30, [(1, 23), (37, 24)]), (29, "H"): (30, [(19, 15), (26, 16)]),
    (30, "L"): (30, [(5, 115), (10, 116)]), (30, "M"): (28, [(19, 47), (10, 48)]), (30, "Q"): (30, [(15, 24), (25, 25)]), (30, "H"): (30, [(23, 15), (25, 16)]),
    (31, "L"): (30, [(13, 115), (3, 116)]), (31, "M"): (28, [(2, 46), (29, 47)]), (31, "Q"): (30, [(42, 24), (1, 25)]), (31, "H"): (30, [(23, 15), (28, 16)]),
    (32, "L"): (30, [(17, 115)]), (32, "M"): (28, [(10, 46), (23, 47)]), (32, "Q"): (30, [(10, 24), (35, 25)]), (32, "H"): (30, [(19, 15), (35, 16)]),
    (33, "L"): (30, [(17, 115), (1, 116)]), (33, "M"): (28, [(14, 46), (21, 47)]), (33, "Q"): (30, [(29, 24), (19, 25)]), (33, "H"): (30, [(11, 15), (46, 16)]),
    (34, "L"): (30, [(13, 115), (6, 116)]), (34, "M"): (28, [(14, 46), (23, 47)]), (34, "Q"): (30, [(44, 24), (7, 25)]), (34, "H"): (30, [(59, 16), (1, 17)]),
    (35, "L"): (30, [(12, 121), (7, 122)]), (35, "M"): (28, [(12, 47), (26, 48)]), (35, "Q"): (30, [(39, 24), (14, 25)]), (35, "H"): (30, [(22, 15), (41, 16)]),
    (36, "L"): (30, [(6, 121), (14, 122)]), (36, "M"): (28, [(6, 47), (34, 48)]), (36, "Q"): (30, [(46, 24), (10, 25)]), (36, "H"): (30, [(2, 15), (64, 16)]),
    (37, "L"): (30, [(17, 122), (4, 123)]), (37, "M"): (28, [(29, 46), (14, 47)]), (37, "Q"): (30, [(49, 24), (10, 25)]), (37, "H"): (30, [(24, 15), (46, 16)]),
    (38, "L"): (30, [(4, 122), (18, 123)]), (38, "M"): (28, [(13, 46), (32, 47)]), (38, "Q"): (30, [(48, 24), (14, 25)]), (38, "H"): (30, [(42, 15), (32, 16)]),
    (39, "L"): (30, [(20, 117), (4, 118)]), (39, "M"): (28, [(40, 47), (7, 48)]), (39, "Q"): (30, [(43, 24), (22, 25)]), (39, "H"): (30, [(10, 15), (67, 16)]),
    (40, "L"): (30, [(19, 118), (6, 119)]), (40, "M"): (28, [(18, 47), (31, 48)]), (40, "Q"): (30, [(34, 24), (34, 25)]), (40, "H"): (30, [(20, 15), (61, 16)]),
}
_QR_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _png_matrix(d):
    """Decode a (non-interlaced) PNG to a 2D list of booleans (True = dark).
    Handles gray/palette/rgb(a), bit depths 1/2/4/8. None on failure."""
    if not d.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    try:
        width = height = bitd = ctype = interlace = None
        idat = bytearray()
        plte = None
        for typ, body in _png_chunks(d):
            if typ == b"IHDR":
                width, height, bitd, ctype = int.from_bytes(body[0:4], "big"), \
                    int.from_bytes(body[4:8], "big"), body[8], body[9]
                interlace = body[12]
            elif typ == b"PLTE":
                plte = body
            elif typ == b"IDAT":
                idat += body
        if not width or interlace:
            return None
        raw = zlib.decompress(bytes(idat))
        chan = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
        bpp = max(1, (bitd * chan + 7) // 8)
        stride = (width * chan * bitd + 7) // 8
        rows, prev = [], bytearray(stride)
        pos = 0
        for _ in range(height):
            ft = raw[pos]; pos += 1
            line = bytearray(raw[pos:pos + stride]); pos += stride
            for i in range(len(line)):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                if ft == 1:
                    line[i] = (line[i] + a) & 0xff
                elif ft == 2:
                    line[i] = (line[i] + b) & 0xff
                elif ft == 3:
                    line[i] = (line[i] + (a + b) // 2) & 0xff
                elif ft == 4:
                    p = a + b - c
                    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    line[i] = (line[i] + pr) & 0xff
            rows.append(bytes(line))
            prev = line
        # unpack samples -> luminance -> dark
        maxv = (1 << bitd) - 1
        out = []
        for line in rows:
            samples = []
            if bitd == 8:
                samples = list(line)
            else:
                for byte in line:
                    for s in range(8 // bitd):
                        shift = 8 - bitd * (s + 1)
                        samples.append((byte >> shift) & maxv)
            px = []
            for x in range(width):
                base = x * chan
                if ctype == 3 and plte:
                    idx = samples[x] * 3
                    r, g, b = plte[idx], plte[idx + 1], plte[idx + 2]
                    lum = 0.299 * r + 0.587 * g + 0.114 * b
                elif ctype in (0, 4):
                    lum = samples[base] * 255.0 / maxv
                else:  # rgb / rgba
                    r, g, b = samples[base], samples[base + 1], samples[base + 2]
                    lum = (0.299 * r + 0.587 * g + 0.114 * b) * 255.0 / maxv
                px.append(lum < 128)
            out.append(px)
        return out
    except Exception:
        return None


def _gif_matrix(d):
    """Decode the first frame of a GIF (LZW) to a dark-pixel matrix. None on
    failure. Handles interlaced frames and global/local colour tables."""
    if d[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    try:
        width = int.from_bytes(d[6:8], "little")
        height = int.from_bytes(d[8:10], "little")
        packed = d[10]
        pos = 13
        gct = None
        if packed & 0x80:
            n = 2 << (packed & 7)
            gct = d[pos:pos + 3 * n]
            pos += 3 * n
        while pos < len(d):
            b = d[pos]
            if b == 0x21:               # extension: skip sub-blocks
                pos += 2
                while pos < len(d) and d[pos]:
                    pos += 1 + d[pos]
                pos += 1
            elif b == 0x2c:             # image descriptor
                iw = int.from_bytes(d[pos + 5:pos + 7], "little")
                ih = int.from_bytes(d[pos + 7:pos + 9], "little")
                ipacked = d[pos + 9]
                interlaced = bool(ipacked & 0x40)
                pos += 10
                lct = gct
                if ipacked & 0x80:
                    n = 2 << (ipacked & 7)
                    lct = d[pos:pos + 3 * n]
                    pos += 3 * n
                min_code = d[pos]; pos += 1
                data = bytearray()
                while pos < len(d) and d[pos]:
                    ln = d[pos]
                    data += d[pos + 1:pos + 1 + ln]
                    pos += 1 + ln
                idx = _lzw_gif(min_code, bytes(data))
                w, h = iw or width, ih or height
                pal = lct or b""
                rows = [[False] * w for _ in range(h)]
                order = list(range(h))
                if interlaced:
                    order = (list(range(0, h, 8)) + list(range(4, h, 8)) +
                             list(range(2, h, 4)) + list(range(1, h, 2)))
                k = 0
                for ry in order:
                    for x in range(w):
                        if k < len(idx):
                            ci = idx[k] * 3
                            if ci + 2 < len(pal):
                                lum = 0.299 * pal[ci] + 0.587 * pal[ci + 1] + 0.114 * pal[ci + 2]
                                rows[ry][x] = lum < 128
                        k += 1
                return rows
            else:
                break
    except Exception:
        return None
    return None


def _lzw_gif(min_code, data):
    clear = 1 << min_code
    end = clear + 1
    size = min_code + 1
    table = [[i] for i in range(clear)] + [[], []]
    out, prev, bitpos = [], None, 0
    nbits = len(data) * 8
    while bitpos + size <= nbits:
        code = 0
        for i in range(size):
            if (data[bitpos >> 3] >> (bitpos & 7)) & 1:
                code |= 1 << i
            bitpos += 1
        if code == clear:
            table = [[i] for i in range(clear)] + [[], []]
            size = min_code + 1
            prev = None
            continue
        if code == end:
            break
        if code < len(table):
            entry = table[code]
        elif prev is not None:
            entry = prev + prev[:1]
        else:
            break
        out.extend(entry)
        if prev is not None:
            table.append(prev + entry[:1])
            if len(table) == (1 << size) and size < 12:
                size += 1
        prev = entry
    return out


def _bmp_matrix(d):
    """Decode an uncompressed BMP to a dark-pixel matrix (bpp 1/4/8/24/32)."""
    if d[:2] != b"BM":
        return None
    try:
        off = int.from_bytes(d[10:14], "little")
        hsize = int.from_bytes(d[14:18], "little")
        width = int.from_bytes(d[18:22], "little", signed=True)
        height = int.from_bytes(d[22:26], "little", signed=True)
        bpp = int.from_bytes(d[28:30], "little")
        if int.from_bytes(d[30:34], "little") != 0:   # only BI_RGB
            return None
        top_down = height < 0
        height = abs(height)
        pal = []
        if bpp <= 8:
            po = 14 + hsize
            ncol = int.from_bytes(d[46:50], "little") or (1 << bpp)
            for i in range(ncol):
                pal.append((d[po + i * 4 + 2], d[po + i * 4 + 1], d[po + i * 4]))
        row_size = ((bpp * width + 31) // 32) * 4
        out = []
        for row in range(height):
            y = row if top_down else height - 1 - row
            line = d[off + y * row_size: off + y * row_size + row_size]
            px = []
            for x in range(width):
                if bpp == 1:
                    r, g, b = pal[(line[x >> 3] >> (7 - (x & 7))) & 1]
                elif bpp == 4:
                    r, g, b = pal[(line[x >> 1] >> (4 if x % 2 == 0 else 0)) & 0xf]
                elif bpp == 8:
                    r, g, b = pal[line[x]]
                elif bpp == 24:
                    b, g, r = line[x * 3], line[x * 3 + 1], line[x * 3 + 2]
                elif bpp == 32:
                    b, g, r = line[x * 4], line[x * 4 + 1], line[x * 4 + 2]
                else:
                    return None
                px.append(0.299 * r + 0.587 * g + 0.114 * b < 128)
            out.append(px)
        return out
    except Exception:
        return None


def _image_matrix(d):
    """Dark-pixel matrix from PNG / GIF / BMP bytes (lossless formats a QR is
    shipped in), or None."""
    if d.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png_matrix(d)
    if d[:6] in (b"GIF87a", b"GIF89a"):
        return _gif_matrix(d)
    if d[:2] == b"BM":
        return _bmp_matrix(d)
    return None


def _qr_modules(px):
    """Given a dark-pixel matrix of a clean, scaled QR (with any quiet zone),
    recover the size x size module matrix. None on failure."""
    h = len(px)
    w = len(px[0]) if h else 0
    rmin = rmax = cmin = cmax = None
    for r in range(h):
        for c in range(w):
            if px[r][c]:
                if rmin is None:
                    rmin, rmax, cmin, cmax = r, r, c, c
                rmax = r
                if c < cmin:
                    cmin = c
                if c > cmax:
                    cmax = c
    if rmin is None:
        return None
    bw = cmax - cmin + 1
    # module size from the top-left finder's 7-module top edge
    run = 0
    while cmin + run <= cmax and px[rmin][cmin + run]:
        run += 1
    if run < 7:
        return None
    ms = run / 7.0
    size = int(round(bw / ms))
    if size < 21 or (size - 17) % 4 != 0:
        return None
    step = bw / size
    mods = []
    for r in range(size):
        row = []
        for c in range(size):
            y = int(rmin + (r + 0.5) * step)
            x = int(cmin + (c + 0.5) * step)
            row.append(1 if (0 <= y < h and 0 <= x < w and px[y][x]) else 0)
        mods.append(row)
    return mods


def _qr_mask(p, r, c):
    if p == 0:
        return (r + c) % 2 == 0
    if p == 1:
        return r % 2 == 0
    if p == 2:
        return c % 3 == 0
    if p == 3:
        return (r + c) % 3 == 0
    if p == 4:
        return (r // 2 + c // 3) % 2 == 0
    if p == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if p == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _bch15(data5):
    d = data5 << 10
    for i in range(4, -1, -1):
        if (d >> (10 + i)) & 1:
            d ^= 0x537 << i
    return (data5 << 10) | (d & 0x3ff)


_QR_FORMATS = {}
for _data5 in range(32):
    _QR_FORMATS[_bch15(_data5) ^ 0x5412] = _data5
_QR_ECLEVEL = {1: "L", 0: "M", 3: "Q", 2: "H"}


def _qr_reserved(size, version):
    res = [[False] * size for _ in range(size)]

    def block(r0, c0, h, w):
        for r in range(r0, r0 + h):
            for c in range(c0, c0 + w):
                if 0 <= r < size and 0 <= c < size:
                    res[r][c] = True
    block(0, 0, 9, 9)                 # TL finder + separator + format
    block(0, size - 8, 9, 8)          # TR finder + format
    block(size - 8, 0, 8, 9)          # BL finder + format
    for i in range(size):             # timing
        res[6][i] = True
        res[i][6] = True
    centers = _QR_ALIGN.get(version, [])
    for a in centers:
        for b in centers:
            if (a in (6,) and b in (6,)) or (a == 6 and b == centers[-1]) or (a == centers[-1] and b == 6):
                continue
            block(a - 2, b - 2, 5, 5)
    if version >= 7:
        block(0, size - 11, 6, 3)
        block(size - 11, 0, 3, 6)
    return res


def _qr_decode(data):
    """Decode a QR code from PNG bytes -> list of decoded strings ([] if none)."""
    try:
        px = _image_matrix(_as_bytes(data))
        if px is None:
            return []
        mods = _qr_modules(px)
        if mods is None:
            return []
        size = len(mods)
        version = (size - 17) // 4
        if version not in _QR_ALIGN:
            return []
        # format info (copy around the top-left finder); modules are [row][col]
        fb = 0
        for i in range(6):
            fb |= mods[i][8] << i
        fb |= mods[7][8] << 6
        fb |= mods[8][8] << 7
        fb |= mods[8][7] << 8
        for i in range(9, 15):
            fb |= mods[8][14 - i] << i
        best, bestd = None, 99
        for cand, d5 in _QR_FORMATS.items():
            dist = bin(cand ^ fb).count("1")
            if dist < bestd:
                bestd, best = dist, d5
        if best is None:
            return []
        mask = best & 7
        ec = _QR_ECLEVEL[(best >> 3) & 3]
        res = _qr_reserved(size, version)
        # read codewords (zigzag, right-to-left column pairs), unmasking data
        bits = []
        up = True
        col = size - 1
        while col > 0:
            if col == 6:
                col -= 1
            for i in range(size):
                r = size - 1 - i if up else i
                for c in (col, col - 1):
                    if not res[r][c]:
                        bit = mods[r][c]
                        if _qr_mask(mask, r, c):
                            bit ^= 1
                        bits.append(bit)
            up = not up
            col -= 2
        codewords = []
        for i in range(0, len(bits) - 7, 8):
            v = 0
            for b in bits[i:i + 8]:
                v = (v << 1) | b
            codewords.append(v)
        ecw, groups = _QR_ECB[(version, ec)]
        blocks = []
        for count, dcw in groups:
            blocks += [dcw] * count
        total_data = sum(blocks)
        stream = codewords[:total_data]
        maxd = max(blocks)
        per_block = [[] for _ in blocks]
        idx = 0
        for i in range(maxd):
            for b, dcw in enumerate(blocks):
                if i < dcw and idx < len(stream):
                    per_block[b].append(stream[idx])
                    idx += 1
        final = bytes(x for blk in per_block for x in blk)
        return _qr_parse(final, version)
    except Exception:
        return []


def _qr_parse(final, version):
    bits = []
    for byte in final:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    pos, total = 0, len(bits)

    def take(n):
        nonlocal pos
        if pos + n > total:
            raise IndexError
        v = 0
        for _ in range(n):
            v = (v << 1) | bits[pos]
            pos += 1
        return v
    out = []
    try:
        while pos + 4 <= total:
            mode = take(4)
            if mode == 0:
                break
            if mode == 1:      # numeric
                cnt = take(10 if version < 10 else 12 if version < 27 else 14)
                s = ""
                while cnt >= 3:
                    s += "%03d" % take(10)
                    cnt -= 3
                if cnt == 2:
                    s += "%02d" % take(7)
                elif cnt == 1:
                    s += "%d" % take(4)
                out.append(s)
            elif mode == 2:    # alphanumeric
                cnt = take(9 if version < 10 else 11 if version < 27 else 13)
                s = ""
                while cnt >= 2:
                    v = take(11)
                    s += _QR_ALNUM[v // 45] + _QR_ALNUM[v % 45]
                    cnt -= 2
                if cnt == 1:
                    s += _QR_ALNUM[take(6)]
                out.append(s)
            elif mode == 4:    # byte
                cnt = take(16 if version >= 10 else 8)
                raw = bytes(take(8) for _ in range(cnt))
                out.append(raw.decode("utf-8", "replace"))
            elif mode == 7:    # ECI: skip one assignment byte, keep decoding
                take(8)
                continue
            else:
                break
    except Exception:
        pass
    return ["".join(out)] if out else []


class _Util:
    """Analysis helpers. Available in every filter as `util`."""

    # -- base64 --
    @staticmethod
    def b64(s):
        """Decode base64 → bytes, or None if it isn't valid base64."""
        try:
            return base64.b64decode(_as_text(s).strip(), validate=True)
        except Exception:
            return None

    @staticmethod
    def is_base64(s, canonical=True):
        """True if s is base64. canonical=True also rejects non-minimal padding
        or trailing junk (i.e. re-encoding must reproduce the input exactly)."""
        t = _as_text(s).strip()
        if not t or len(t) % 4 != 0 or not _B64_RE.match(t):
            return False
        try:
            raw = base64.b64decode(t, validate=True)
        except Exception:
            return False
        if canonical:
            return base64.b64encode(raw).decode("ascii") == t
        return True

    # -- entropy / block structure (crypto-oracle payloads) --
    @staticmethod
    def entropy(data):
        """Shannon entropy in bits/byte (0..8). Low = uniform/repetitive."""
        d = _as_bytes(data)
        if not d:
            return 0.0
        n = len(d)
        return -sum((c / n) * math.log2(c / n) for c in Counter(d).values())

    @staticmethod
    def longest_run(data):
        """Length of the longest run of one repeated byte (e.g. 32×0xff)."""
        d = _as_bytes(data)
        best = cur = 0
        prev = None
        for b in d:
            cur = cur + 1 if b == prev else 1
            prev = b
            if cur > best:
                best = cur
        return best

    @staticmethod
    def repeated_block(data, size=16):
        """True if any aligned block of `size` bytes repeats (ECB-like / a
        crafted crypto-oracle input)."""
        d = _as_bytes(data)
        if size <= 0 or len(d) < size * 2:
            return False
        seen = set()
        for i in range(0, len(d) - size + 1, size):
            blk = d[i:i + size]
            if blk in seen:
                return True
            seen.add(blk)
        return False

    @staticmethod
    def printable_ratio(data):
        """Fraction of bytes that are printable ASCII (incl. \\t\\n\\r)."""
        d = _as_bytes(data)
        if not d:
            return 1.0
        p = sum(1 for b in d if 0x20 <= b < 0x7f or b in (9, 10, 13))
        return p / len(d)

    @staticmethod
    def has_control_chars(s):
        """True if the text holds any C0 control byte (incl. \\r \\n \\t) or DEL."""
        return any(ord(c) < 0x20 or ord(c) == 0x7f for c in _as_text(s))

    # -- files: magic / content-type / polyglot trailing data --
    @staticmethod
    def magic(data):
        """Sniff a file type from its leading bytes: 'png','jpg','gif','pdf',
        'zip','gzip','elf','bmp','webp','tiff','ico','svg', or '' if unknown."""
        d = _as_bytes(data)
        for sig, name in _MAGIC:
            if d.startswith(sig):
                if name == "riff":
                    return "webp" if d[8:12] == b"WEBP" else "riff"
                return name
        if d[:4] == b"RIFF" and d[8:12] == b"WEBP":
            return "webp"
        head = d[:512].lstrip().lower()
        if head[:5] == b"<?xml" or head[:4] == b"<svg" or b"<svg" in head:
            return "svg"
        return ""

    @staticmethod
    def content_type_ok(declared, data):
        """False when the declared Content-Type contradicts the sniffed magic
        (e.g. Content-Type image/png but the bytes are a ZIP). Unknown/unenforced
        types return True so you never false-positive on them."""
        ct = _as_text(declared).split(";")[0].strip().lower()
        expected = _CT_MAGIC.get(ct)
        if expected is None:
            return True
        got = _Util.magic(data)
        return got == "" or got == expected

    @staticmethod
    def trailing_data(data):
        """Bytes appended after the logical end of a recognized image container
        (polyglot / smuggled payload). b'' when there is none, or the format is
        not one we can bound precisely (PNG and JPEG only)."""
        d = _as_bytes(data)
        if d.startswith(b"\x89PNG\r\n\x1a\n"):
            end = d.find(b"IEND")
            if end != -1:
                return d[end + 8:]  # IEND + 4-byte CRC
            return b""
        if d[:3] == b"\xff\xd8\xff":
            i, n = 2, len(d)
            while i + 1 < n:
                if d[i] != 0xff:
                    return b""
                m = d[i + 1]
                if m == 0xd9:                       # EOI
                    return d[i + 2:]
                if m == 0x01 or 0xd0 <= m <= 0xd7:  # standalone markers
                    i += 2
                    continue
                if m == 0xda:                       # SOS: scan entropy-coded data
                    i += 2
                    while i + 1 < n:
                        if d[i] == 0xff and d[i + 1] == 0xd9:
                            return d[i + 2:]
                        if d[i] == 0xff and d[i + 1] != 0x00 and not (0xd0 <= d[i + 1] <= 0xd7):
                            break
                        i += 1
                    return b""
                if i + 3 >= n:
                    return b""
                i += 2 + ((d[i + 2] << 8) | d[i + 3])
            return b""
        return b""

    # -- deep file inspection: text layers, signatures, QR --
    @staticmethod
    def strings(data, min_len=4):
        """Printable-ASCII runs (like the `strings` command) as a list."""
        return _strings(data, min_len)

    @staticmethod
    def text_layers(data, qr=False):
        """Every readable text layer of a file as (source, text) pairs — the raw
        printable strings PLUS decoded content that `strings` can't see: PNG
        tEXt/zTXt/iTXt chunks, inflated PDF streams, ZIP/Office entries, and
        (when qr=True) a QR code's decoded payload."""
        d = _as_bytes(data)
        layers = [("bytes", "\n".join(_strings(d)))]
        kind = _Util.magic(d)
        if kind == "png":
            for t in _png_text(d):
                layers.append(("png:text", t))
        elif kind == "pdf":
            for t in _pdf_text(d):
                layers.append(("pdf:stream", t))
        elif kind == "zip":
            for t in _zip_text(d):
                layers.append(("zip:entry", t))
        if qr:
            for t in _qr_decode(d):
                layers.append(("qr", t))
        return layers

    @staticmethod
    def qr_decode(data):
        """Decode a QR code from an image (PNG/GIF/BMP) → list of decoded strings
        ([] if it isn't a decodable QR). Best-effort: clean, axis-aligned QR
        codes, all versions 1-40, numeric/alphanumeric/byte modes, all masks."""
        return _qr_decode(_as_bytes(data))

    @staticmethod
    def find_payload(data, categories=None, qr=False):
        """Scan every text layer for a known attack signature. Returns a dict
        {category, label, source, match} on the first hit, else None — so a
        filter can do `if util.find_payload(flow.content, qr=True): drop`.
        categories optionally restricts to e.g. ("sqli","shell")."""
        for src, text in _Util.text_layers(data, qr=qr):
            if not text:
                continue
            for cat, pats in _SIG_DB:
                if categories and cat not in categories:
                    continue
                for rx, lbl in pats:
                    m = rx.search(text)
                    if m:
                        return {"category": cat, "label": lbl,
                                "source": src, "match": m.group(0)[:120]}
        return None

    @staticmethod
    def scan(data, patterns, qr=False):
        """Search every text layer with your own regex/substring patterns.
        Returns the list of matched strings (empty if none)."""
        if isinstance(patterns, (str, bytes)) or hasattr(patterns, "search"):
            patterns = [patterns]
        compiled = [p if hasattr(p, "search") else re.compile(_as_text(p), re.I | re.S)
                    for p in patterns]
        hits = []
        for _, text in _Util.text_layers(data, qr=qr):
            for rx in compiled:
                m = rx.search(text or "")
                if m:
                    hits.append(m.group(0)[:120])
        return hits

    @staticmethod
    def inspect(data, qr=False):
        """A quick structured report for the Test panel: file type, size,
        appended (polyglot) bytes, the text-layer sources found, and the first
        attack signature (if any)."""
        d = _as_bytes(data)
        return {
            "type": _Util.magic(d) or "?",
            "size": len(d),
            "trailing": len(_Util.trailing_data(d)),
            "layers": [s for s, _ in _Util.text_layers(d, qr=qr)],
            "payload": _Util.find_payload(d, qr=qr),
        }

    # -- paths / URIs --
    @staticmethod
    def normpath(p, decode=2):
        """URL-decode (up to `decode` passes), fold backslashes and duplicate
        slashes, and resolve . / .. — so you can inspect the real target path."""
        s = _as_text(p)
        for _ in range(max(1, decode)):
            nxt = unquote(s)
            if nxt == s:
                break
            s = nxt
        s = re.sub(r"[\\/]+", "/", s)
        return posixpath.normpath(s)

    @staticmethod
    def uri_scheme(s):
        """The URI scheme (lowercased) if s carries one — "http", "file",
        "telnet://" → "telnet", bare "file:" → "file" — else ""."""
        m = _SCHEME_RE.match(_as_text(s).strip())
        if not m:
            return ""
        scheme = m.group(1).lower()
        if m.group(2) or scheme in _DANGEROUS_SCHEMES:
            return scheme
        return ""

    @staticmethod
    def path_escapes(p):
        """True if a (supposedly relative) path is unsafe: a NUL byte, a URI
        scheme, an absolute path, or traversal that climbs out of the root."""
        raw = _as_text(p)
        if "\x00" in raw or _Util.uri_scheme(raw):
            return True
        n = _Util.normpath(raw)
        return n.startswith("/") or n == ".." or n.startswith("../")

    # -- json / objects --
    @staticmethod
    def valid_json(s):
        """True only if s is one complete, well-formed JSON document (no
        truncation, no trailing bytes)."""
        t = _as_text(s)
        if not t.strip():
            return False
        try:
            json.loads(t)
            return True
        except Exception:
            return False

    @staticmethod
    def extra_keys(obj, allowed):
        """The set of keys in dict `obj` that aren't in `allowed` — for spotting
        mass-assignment (unexpected fields the checker never sends)."""
        if not isinstance(obj, dict):
            return set()
        return set(obj) - set(allowed)


util = _Util()


def _compile_scripts(scripts):
    """Compile+exec each script into its own namespace. Returns (loaded, errors)."""
    loaded = {}
    errors = {}
    for spec in scripts:
        sid = spec.get("id") or spec.get("name") or "script"
        name = spec.get("name", sid)
        ns = {"util": util}
        try:
            code = compile(spec.get("code", ""), "<pyfilter:%s>" % name, "exec")
            exec(code, ns)  # noqa: S102 - intentional user code execution
            fn = ns.get("match")
            if not callable(fn):
                errors[sid] = "script must define a top-level match(flow) function"
                continue
            # Optional module-level DIRECTION = "request" | "response" lets a
            # script declare which side it cares about; Janus then skips the
            # other direction instead of the script guarding it every call.
            loaded[sid] = {"name": name, "fn": fn, "direction": _norm_direction(ns.get("DIRECTION"))}
        except Exception:
            errors[sid] = _short_traceback()
    return loaded, errors


def _normalize(res):
    """Turn a match() return value into {"reason","block"}, or None."""
    if res is None or res is False:
        return None
    if res is True:
        return {"reason": "", "block": False}
    if isinstance(res, str):
        return {"reason": res, "block": False}
    if isinstance(res, dict):
        # "drop" and "block" are synonyms: both ask Janus to drop the CURRENT
        # message inline (honored only for Blocking filters). Any truthy value
        # counts, so {"drop": True} and {"drop": "reason text"} both block.
        block = bool(res.get("drop")) or bool(res.get("block"))
        # A drop/block directive implies a match even without an explicit "match".
        if res.get("match") or block:
            return {"reason": str(res.get("reason", "")), "block": block}
        return None
    if res:
        return {"reason": "", "block": False}
    return None


def _evaluate(scripts, flow):
    """Run every script against flow; returns (matches, rewrite-or-None)."""
    if not isinstance(flow, Flow):
        flow = Flow(flow)
    _record(flow)  # record once per message, before any script runs
    direction = flow.get("direction")
    matches = []
    for sid, s in scripts.items():
        # Skip scripts that declared DIRECTION for the other side.
        if s.get("direction") and direction and s["direction"] != direction:
            continue
        flow["__sid"] = sid   # namespaces flow.conn / flow.commands per script
        try:
            res = s["fn"](flow)
        except Exception:
            matches.append({
                "script": sid, "name": s["name"],
                "reason": "error: " + _short_exc_line(), "error": True,
            })
            continue
        norm = _normalize(res)
        if norm is not None:
            matches.append({
                "script": sid, "name": s["name"],
                "reason": norm["reason"], "block": norm["block"], "error": False,
            })
    return matches, _rewrite_of(flow)


def _short_traceback():
    return traceback.format_exc(limit=4).strip()


def _short_exc_line():
    lines = traceback.format_exc(limit=2).strip().splitlines()
    return lines[-1] if lines else "unknown error"


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    global SCRIPTS
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        cmd = msg.get("cmd")
        if cmd == "load":
            SCRIPTS, errors = _compile_scripts(msg.get("scripts", []))
            _send({"cmd": "load", "ok": len(errors) == 0, "errors": errors})
        elif cmd == "eval":
            matches, rewrite = _evaluate(SCRIPTS, msg.get("packet", {}))
            reply = {"id": msg.get("id"), "matches": matches}
            if rewrite is not None:
                reply["rewrite"] = rewrite
            _send(reply)
        elif cmd == "test":
            # Evaluate one script in isolation without disturbing loaded state.
            # `packets` is an ordered sequence (a whole flow, or one packet);
            # match() is called on each in turn so stateful/correlating scripts
            # see the sequence. `repeat` re-runs the whole sequence N times.
            # Returns per-step verdicts from the last pass.
            loaded, errors = _compile_scripts([msg.get("script", {})])
            if errors:
                _send({"id": msg.get("id"), "error": list(errors.values())[0]})
            else:
                try:
                    repeat = int(msg.get("repeat", 1))
                except Exception:
                    repeat = 1
                if repeat < 1:
                    repeat = 1
                packets = msg.get("packets")
                if not isinstance(packets, list) or not packets:
                    packets = [msg.get("packet", {})]
                steps = []
                for _ in range(repeat):
                    steps = []
                    for f in packets:
                        m, rewrite = _evaluate(loaded, f)
                        step = {"matches": m}
                        if rewrite is not None:
                            step["rewrite"] = rewrite
                        steps.append(step)
                _send({
                    "id": msg.get("id"),
                    "steps": steps,
                    "matches": steps[-1]["matches"] if steps else [],
                })
        elif cmd == "ping":
            _send({"pong": True})


if __name__ == "__main__":
    main()
