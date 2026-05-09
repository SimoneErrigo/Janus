#!/usr/bin/env python3
"""
Janus — bulk rule seeder.

Logs into the Janus API, fetches services, and creates a curated set of
drop/alert rules for known vulnerability patterns (SQLi, command injection,
path traversal, scanner UAs, sensitive paths, etc.).

Usage:
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD"
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD" --service web1 --service web2
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD" --dry-run

Environment fallbacks:
    JANUS_URL        (default http://localhost:8080)
    JANUS_PASSWORD   (read if --password not given)

Rules with action="all" target every enabled service. Rules with a specific
"service" name only attach to services whose `name` or `id` matches.

Re-running the script is safe: the backend rejects duplicates
(same service + expression + action) with HTTP 409 — those are skipped.

Customize the RULES list below to match your competition.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request


# -----------------------------------------------------------------------------
# Rule catalogue.
#
# Each rule is a dict with:
#   name        — short descriptive label (will appear in the UI)
#   expression  — Janus filter DSL (see FILTERS.md)
#   action      — "drop" | "alert" | "both"
#   priority    — int, higher runs first (default 10)
#   service     — "all" or a specific service id/name
#
# Defaults: alert. Only drop when the false-positive risk is genuinely low
# AND the request is obviously malicious. NEVER drop on flag regex (the
# checker needs the flag to validate); the auto flag rule already handles
# that as alert-only.
#
# Tip: start with everything as "alert", watch the Alerts page during the
# warmup, then switch the noisy-and-real ones to "drop" or "both".
# -----------------------------------------------------------------------------
# Use Python raw strings (r"...") so that every backslash you see in the
# expression is the EXACT same backslash the DSL parser will receive. The DSL
# escapes `\\` → `\`, so a regex `\s` must appear here as `\\s` (two chars).
# Hex-byte escapes (`\xNN`) are also DSL-level and likewise need `\\xNN`.
RULES = [
    # ---------------- SQL injection ----------------
    {
        "name": "SQLi: UNION/SELECT in body",
        "expression": r'body matches "(?i)union[\\s/*]+select"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "SQLi: tautology (or 1=1, and 1=1)",
        "expression": r"""body matches "(?i)\\b(or|and)\\b\\s+['\"]?[0-9a-z]+['\"]?\\s*=\\s*['\"]?[0-9a-z]+['\"]?" """.strip(),
        "action": "alert",
        "service": "all",
    },
    {
        "name": "SQLi: time-based (sleep/benchmark/pg_sleep/waitfor)",
        "expression": r'body matches "(?i)(sleep\\s*\\(|benchmark\\s*\\(|pg_sleep\\s*\\(|waitfor\\s+delay)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "SQLi: stacked / comment chars in URL",
        "expression": r'url matches "(?i)(\\bunion\\b|--%20|--%09|%23%23|/\\*|\\*/)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "SQLi: information_schema probing",
        "expression": '(body icontains "information_schema" OR url icontains "information_schema")',
        "action": "alert",
        "service": "all",
    },

    # ---------------- Command injection ----------------
    {
        "name": "CMDi: shell metachars in URL (URL-encoded)",
        "expression": r'url matches "(?i)(%3b|%7c|%26%26|%24%28|%60)(ls|id|cat|whoami|nc|wget|curl|sh|bash|python|perl)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "CMDi: shell metachars in body",
        "expression": r'body matches "(?i)([;&|`]|\\$\\()\\s*(ls|id|cat|whoami|uname|nc|wget|curl|sh|bash|python|perl)\\b"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "CMDi: outbound exfil via curl/wget",
        "expression": r'body matches "(?i)(curl|wget)\\s+(-[a-z]\\s+)*https?://"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "CMDi: reverse shell shapes",
        "expression": r'body matches "(?i)(bash\\s+-i|nc\\s+-e|/dev/tcp/|mkfifo\\s+/tmp/|python\\s+-c.+socket)"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- Path traversal / LFI ----------------
    {
        "name": "Path traversal: ../ or encoded variants in URL",
        # `c:[/\\]windows` is encoded as `c:[/\\\\]windows` (DSL backslash escape).
        "expression": r'url matches "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e/|%2e%2e%2f|\\.\\.%2f|%252e%252e)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "LFI: /etc/passwd, /proc/self, win.ini probes",
        "expression": r'url matches "(?i)(/etc/passwd|/proc/self|/var/log|c:[/\\\\]windows|win\\.ini|boot\\.ini)" OR body matches "(?i)(/etc/passwd|/proc/self/environ)"',
        "action": "aler",
        "service": "all",
    },
    {
        "name": "Sensitive file probing (.env / .git / .aws / .ssh)",
        "expression": r'url matches "(?i)/(\\.env(\\.[a-z0-9_]+)?|\\.git/|\\.aws/|\\.ssh/|\\.htaccess|\\.htpasswd|\\.svn/)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "Common admin/scan paths",
        "expression": r'url matches "(?i)/(phpmyadmin|wp-login\\.php|wp-admin/|xmlrpc\\.php|administrator/|server-status|server-info|cgi-bin/|adminer\\.php|/manager/html)"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- SSRF ----------------
    {
        "name": "SSRF: cloud metadata endpoints",
        "expression": r'(body matches "(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|fd00:ec2::254)") OR (url matches "(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal)")',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "SSRF: file:// gopher:// dict:// ftp:// schemes in body",
        "expression": 'body matches "(?i)(file://|gopher://|dict://|ftp://|jar:|netdoc:)"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- XSS ----------------
    {
        "name": "XSS: <script>, javascript:, on*= handlers in body",
        "expression": r'body matches "(?i)(<script[^>]*>|javascript:|on(error|load|click|mouseover)\\s*=)"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- Template / expression injection ----------------
    {
        "name": "SSTI: Jinja/EL/Twig/Smarty markers in body",
        "expression": r'body matches "(\\{\\{.+\\}\\}|\\$\\{.+\\}|<%.+%>|#\\{.+\\})"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- NoSQL / deserialization ----------------
    {
        "name": "NoSQLi: Mongo operators in JSON body",
        "expression": r'body matches "\"\\$(ne|gt|lt|gte|lte|in|nin|where|regex|exists|expr|or|and)\"\\s*:"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "Java serialized magic (rO0AB / aced0005)",
        "expression": '(body contains "rO0AB") OR (raw startswith "\\xac\\xed\\x00\\x05")',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "PHP serialized object header (O:N:\"...\")",
        "expression": r'body matches "O:[0-9]+:\"[a-zA-Z_\\\\]+\":[0-9]+:\\{"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- XXE ----------------
    {
        "name": "XXE: external entity declarations",
        "expression": r'body matches "(?i)<!ENTITY\\s+\\S+\\s+SYSTEM"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- Scanner / tooling fingerprints ----------------
    {
        "name": "Scanner UA (sqlmap/nikto/nuclei/nmap/wpscan/acunetix/etc.)",
        "expression": r'header.User-Agent matches "(?i)(sqlmap|nikto|nuclei|nmap\\s|masscan|wpscan|acunetix|w3af|whatweb|dirbuster|gobuster|feroxbuster|ffuf)"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "Empty / suspiciously short User-Agent",
        "expression": r'header.User-Agent matches "^$|^.{1,4}$"',
        "action": "alert",
        "service": "all",
    },

    # ---------------- Generic abuse / oversized payloads ----------------
    {
        # RE2 caps {N,} at 1000 — for "really big" we chain two 1000-byte
        # quantifiers to require ≥2000 bytes; see FILTERS.md "Gotchas".
        "name": "Oversized request body (>2KB) — possible fuzz / overflow",
        "expression": 'body matches ".{1000,}.{1000,}" AND direction == "request"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "Buffer-overflow probe — long run of 'A'",
        "expression": 'raw contains "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
        "action": "alert",
        "service": "all",
    },
    {
        "name": "Buffer-overflow probe — long run of NUL bytes",
        "expression": 'raw contains "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"',
        "action": "alert",
        "service": "all",
    },
]


# -----------------------------------------------------------------------------

class JanusClient:
    def __init__(self, base_url: str, password: str, display_name: str):
        self.base_url = base_url.rstrip("/")
        self.token = self._login(password, display_name)

    def _request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if hasattr(self, "token") and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                return resp.status, (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as e:
            payload = e.read().decode(errors="replace")
            return e.code, {"error": payload.strip()}

    def _login(self, password: str, display_name: str) -> str:
        status, body = self._request("POST", "/api/login",
                                     {"password": password, "display_name": display_name})
        if status != 200 or not body or "token" not in body:
            err = body.get("error") if body else "unknown"
            raise SystemExit(f"login failed (HTTP {status}): {err}")
        return body["token"]

    def list_services(self) -> list[dict]:
        status, body = self._request("GET", "/api/services")
        if status != 200:
            raise SystemExit(f"list services failed (HTTP {status}): {body}")
        return body or []

    def create_rule(self, rule: dict) -> tuple[int, dict | None]:
        return self._request("POST", "/api/rules", rule)


def resolve_services(all_services: list[dict], scope: str, only: set[str]) -> list[dict]:
    """Pick which services this rule applies to."""
    if scope == "all":
        candidates = all_services
    else:
        candidates = [s for s in all_services if s.get("id") == scope or s.get("name") == scope]
    if only:
        candidates = [s for s in candidates if s.get("id") in only or s.get("name") in only]
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Bulk-create Janus drop/alert rules.")
    parser.add_argument("--url", default=os.environ.get("JANUS_URL", "http://localhost:8080"),
                        help="Janus base URL (default: %(default)s)")
    parser.add_argument("--password", default=os.environ.get("JANUS_PASSWORD"),
                        help="Janus team password (or set JANUS_PASSWORD)")
    parser.add_argument("--display-name", default="rule-seeder",
                        help="Display name attached to created rules")
    parser.add_argument("--service", action="append", default=[],
                        help="Restrict to these service id/name(s); can repeat. Default = all enabled.")
    parser.add_argument("--include-disabled", action="store_true",
                        help="Also seed rules on disabled services (skipped by default).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be created without contacting the API.")
    args = parser.parse_args()

    if not args.password and not args.dry_run:
        try:
            args.password = getpass.getpass("Janus password: ")
        except (KeyboardInterrupt, EOFError):
            print("\naborted", file=sys.stderr)
            return 130

    only = set(args.service)

    if args.dry_run:
        print(f"[dry-run] Would seed {len(RULES)} rule template(s).")
        for r in RULES:
            print(f"  - {r['action']:5s} | service={r['service']:8s} | {r['name']}")
            print(f"            {r['expression']}")
        return 0

    client = JanusClient(args.url, args.password, args.display_name)
    services = client.list_services()
    if not args.include_disabled:
        services = [s for s in services if s.get("enabled", True)]
    if not services:
        print("No services found (or all disabled). Nothing to do.", file=sys.stderr)
        return 1

    print(f"Connected to {args.url} — {len(services)} service(s) in scope.")

    created = skipped = failed = 0
    for rule in RULES:
        targets = resolve_services(services, rule["service"], only)
        if not targets:
            print(f"  · skip (no matching services): {rule['name']}")
            continue
        for svc in targets:
            payload = {
                "service_id": svc["id"],
                "name": rule["name"],
                "expression": rule["expression"],
                "action": rule["action"],
                "priority": rule.get("priority", 10),
                "enabled": True,
            }
            status, body = client.create_rule(payload)
            tag = f"{rule['action']:5s} on {svc['id']}"
            if status in (200, 201):
                created += 1
                print(f"  ✓ {tag} — {rule['name']}")
            elif status == 409:
                skipped += 1
                print(f"  · {tag} — already exists")
            else:
                failed += 1
                err = (body or {}).get("error", body)
                print(f"  ✗ {tag} — HTTP {status}: {err}", file=sys.stderr)

    print(f"\nDone — created {created}, skipped {skipped}, failed {failed}.")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
