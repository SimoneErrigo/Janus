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
        # TCP streams (a continuous byte flow, not one-message-per-chunk):
        #   flow.conn                       # dict persisting for the whole TCP
        #                                   #   connection — your per-conn state
        #   for line in flow.lines:         # complete lines, reassembled across
        #       ...                         #   chunks by Janus (bytes, exact)
        #   for cmd in flow.commands(       # parse a line-based CLI into commands
        #       {b"1": ("register", 2),     #   trigger line -> (name, n arg lines)
        #        b"2": ("login", 2)}):      #   cmd.name / cmd.args / cmd.flagid
        #       ...
        #
        # NOTE: match(flow) runs per message. An inline (Blocking) filter only
        # sees requests, so for it flow.response/.responses are empty.
        #
        # return one of:
        #   False / None            -> no match
        #   True                    -> match (no reason)
        #   "some reason string"    -> match with a reason shown in Alerts
        #   {"match": True, "reason": "...", "drop": "<filter expr>"}
        #       -> match; if "drop" is a filter expression, Janus installs a
        #          content-only drop rule so FUTURE matching traffic is blocked
        #          by the fast in-process engine (fail2ban style). The drop
        #          expression may only use content fields (body/url/header/
        #          service); IP/port fields are rejected (SNAT-unsafe).
        #   {"match": True, "reason": "...", "drop": True}   (or "block": True)
        #       -> match; blocks the CURRENT request in real time (inline). Only
        #          takes effect for scripts marked "Blocking", which run
        #          synchronously on the request hot path.
        #
        # Inline REWRITE (Blocking filters only): assign flow.body = "..." (HTTP)
        # or flow.messages[-1].content = b"..." (TCP) to rewrite the current
        # message before Janus forwards it. Applies whether or not you also
        # return a match; ignored for non-Blocking (async) filters.
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
import traceback
from collections import deque, OrderedDict, namedtuple
from urllib.parse import urlsplit, parse_qs

# A parsed CLI command: its name, its argument lines (bytes), and whether a flag
# ID appeared anywhere within it. Yielded by flow.commands(spec).
Command = namedtuple("Command", "name args flagid")

# id -> {"name": str, "fn": callable}
SCRIPTS = {}

# --- ergonomic flow object -------------------------------------------------
# match(flow) receives a Flow: still a plain dict (flow["body"], flow.get(...)
# keep working), plus forgiving attribute access + HTTP/TCP helpers so filters
# are quick to write and never crash on a missing field.

_HISTORY = {}        # service -> deque[Flow] of recently evaluated messages
_HISTORY_MAX = 32

# Per-TCP-connection scratch: state that persists across every chunk of a
# connection (both directions), plus an internal line-reassembly buffer so
# stream filters don't have to manage a byte buffer themselves.
_CONNS = OrderedDict()   # conn_key -> {"state": {}, "linebuf": {direction: bytes}}
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
        rec = {"state": {}, "linebuf": {}}
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
    @property
    def conn(self):
        """A dict that persists across every message of THIS TCP connection
        (both directions, keyed by service + endpoints). Use it for per-
        connection state instead of a global keyed by src/port."""
        return _conn_record(self)["state"]

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
        write the state machine yourself. `spec` maps a trigger line to
        (name, n_args): a command is that trigger line followed by n_args lines.
        Returns the Command(name, args, flagid) values completed by THIS chunk;
        cross-chunk buffering and flag-ID tracking are handled for you.

            for cmd in flow.commands({b"1": ("register", 2), b"2": ("login", 2)}):
                user, password = cmd.args
        """
        table = {(k if isinstance(k, bytes) else str(k).encode()): v for k, v in spec.items()}
        # Both the per-message result cache and the cross-chunk pending state are
        # keyed by the spec, so several filters parsing the same stream with
        # different command tables don't clobber each other's parse.
        spec_key = tuple(sorted((k, v[0], v[1]) for k, v in table.items()))
        cache = self.setdefault("__commands", {})
        if spec_key in cache:
            return cache[spec_key]
        st = _conn_record(self)["state"]
        pending = st.setdefault("__cmd", {})
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
                    out.append(Command(cur["name"], cur["args"], cur["flag"]))
                    cur = None
            else:
                hit = table.get(line)
                if hit is not None:             # a trigger line -> start a command
                    name, need = hit
                    if need <= 0:
                        out.append(Command(name, [], flagid))
                    else:
                        cur = {"name": name, "need": need, "args": [], "flag": flagid}
        if cur is not None and flagid:          # keep the flag "sticky" across chunks
            cur["flag"] = True
        pending[spec_key] = cur
        cache[spec_key] = out
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


def _compile_scripts(scripts):
    """Compile+exec each script into its own namespace. Returns (loaded, errors)."""
    loaded = {}
    errors = {}
    for spec in scripts:
        sid = spec.get("id") or spec.get("name") or "script"
        name = spec.get("name", sid)
        ns = {}
        try:
            code = compile(spec.get("code", ""), "<pyfilter:%s>" % name, "exec")
            exec(code, ns)  # noqa: S102 - intentional user code execution
            fn = ns.get("match")
            if not callable(fn):
                errors[sid] = "script must define a top-level match(flow) function"
                continue
            loaded[sid] = {"name": name, "fn": fn}
        except Exception:
            errors[sid] = _short_traceback()
    return loaded, errors


def _normalize(res):
    """Turn a match() return value into {"reason","drop","block"}, or None."""
    if res is None or res is False:
        return None
    if res is True:
        return {"reason": "", "drop": "", "block": False}
    if isinstance(res, str):
        return {"reason": res, "drop": "", "block": False}
    if isinstance(res, dict):
        raw = res.get("drop")
        block = bool(res.get("block"))
        drop = ""
        # drop=True (a bare boolean) means "block the current request" — the
        # inline/synchronous drop. drop="<expr>" is the async future-traffic rule.
        if raw is True:
            block = True
        elif isinstance(raw, str) and raw:
            drop = raw
        # A drop/block directive implies a match even without an explicit "match".
        if res.get("match") or drop or block:
            return {"reason": str(res.get("reason", "")), "drop": drop, "block": block}
        return None
    if res:
        return {"reason": "", "drop": "", "block": False}
    return None


def _evaluate(scripts, flow):
    """Run every script against flow; returns (matches, rewrite-or-None)."""
    if not isinstance(flow, Flow):
        flow = Flow(flow)
    _record(flow)  # record once per message, before any script runs
    matches = []
    for sid, s in scripts.items():
        try:
            res = s["fn"](flow)
        except Exception:
            matches.append({
                "script": sid, "name": s["name"],
                "reason": "error: " + _short_exc_line(), "drop": "", "error": True,
            })
            continue
        norm = _normalize(res)
        if norm is not None:
            matches.append({
                "script": sid, "name": s["name"],
                "reason": norm["reason"], "drop": norm["drop"],
                "block": norm["block"], "error": False,
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
