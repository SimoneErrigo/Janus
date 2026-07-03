"""Janus Python-filter harness (mitmproxy-style addons).

Runs as a long-lived worker driven by newline-delimited JSON over stdin/stdout.
User scripts each define:

    def match(flow):
        # flow is a dict: method, url, status, headers, body, src, dst,
        # service, direction, sport, dport, flagged, contains_flagid, id, ...
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
import traceback

# id -> {"name": str, "fn": callable}
SCRIPTS = {}


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
    """Turn a match() return value into {"reason","drop"}, or None for no match."""
    if res is None or res is False:
        return None
    if res is True:
        return {"reason": "", "drop": ""}
    if isinstance(res, str):
        return {"reason": res, "drop": ""}
    if isinstance(res, dict):
        drop = res.get("drop", "")
        drop = str(drop) if drop else ""
        # A drop directive implies a match even without an explicit "match" key.
        if res.get("match") or drop:
            return {"reason": str(res.get("reason", "")), "drop": drop}
        return None
    if res:
        return {"reason": "", "drop": ""}
    return None


def _evaluate(scripts, flow):
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
                "reason": norm["reason"], "drop": norm["drop"], "error": False,
            })
    return matches


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
            _send({"id": msg.get("id"), "matches": _evaluate(SCRIPTS, msg.get("packet", {}))})
        elif cmd == "test":
            # Evaluate one script in isolation without disturbing loaded state.
            loaded, errors = _compile_scripts([msg.get("script", {})])
            if errors:
                _send({"id": msg.get("id"), "error": list(errors.values())[0]})
            else:
                _send({"id": msg.get("id"), "matches": _evaluate(loaded, msg.get("packet", {}))})
        elif cmd == "ping":
            _send({"pong": True})


if __name__ == "__main__":
    main()
