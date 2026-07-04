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
import traceback
from collections import deque, OrderedDict
from urllib.parse import urlsplit, parse_qs

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
