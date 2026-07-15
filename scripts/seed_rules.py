#!/usr/bin/env python3
"""Janus alert-rule seeder for Attack/Defense competitions.

The script logs into Janus, discovers services, validates a curated catalogue
against Janus's filter DSL, and installs the matching rules. Every built-in
rule has ``action=alert``: the catalogue is intended to surface likely exploit
traffic during a competition without risking checker availability.

Usage:
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD"
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD" --category sqli --category ssrf
    ./scripts/seed_rules.py --dry-run --category tcp
    ./scripts/seed_rules.py --password "$TEAM_PASSWORD" --validate-only

Environment fallbacks:
    JANUS_URL        (default http://localhost:2999, the Docker Compose UI/API)
    JANUS_PASSWORD   (read if --password is not given)

Rules are scoped to services *before* they are created:

* HTTP-family templates use only body, URL, and headers, the fields the live
  HTTP/HTTPS/h2(c)/gRPC rule path actually provides.
* Stream templates use only raw bytes and cover the built-in TCP framers.
  Multi-message state still belongs in a PyFilter.

The catalogue deliberately does not seed scanner User-Agent rules, broad size
heuristics, generic admin-path probes, or standalone template delimiters. Those
are frequent A/D noise. Generic CSRF and IDOR detection is also intentionally
out of scope: both require service-specific session/authorization context and
are better implemented as a narrowly scoped rule or a PyFilter.

Re-running is safe: Janus rejects exact duplicate service/expression/action
triples with HTTP 409. ``--replace-seeded`` and ``--prune-legacy`` are opt-in
cleanup actions; they never run by default.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Iterable


ALERT = "alert"
SEED_PREFIX = "[janus-seed]"
HTTP_PROTOCOLS = frozenset({"http", "https", "h2", "h2c", "grpc", "grpc-h2c"})
TCP_PROTOCOLS = frozenset({"tcp", "tcp-line", "tls", "dns-tcp", "resp", "mqtt"})


def _rule(
    category: str,
    name: str,
    expression: str,
    protocols: frozenset[str],
    *,
    priority: int = 50,
) -> dict[str, Any]:
    """Create a catalogue entry with the non-blocking action fixed to alert."""
    return {
        "category": category,
        "name": f"{SEED_PREFIX}[{category}] {name}",
        "expression": expression,
        "action": ALERT,
        "priority": priority,
        "service": "all",
        "protocols": protocols,
    }


def _http(category: str, name: str, expression: str, *, priority: int = 50) -> dict[str, Any]:
    return _rule(category, name, expression, HTTP_PROTOCOLS, priority=priority)


def _tcp(category: str, name: str, expression: str, *, priority: int = 50) -> dict[str, Any]:
    return _rule(category, name, expression, TCP_PROTOCOLS, priority=priority)


# Curated alert-only catalogue. Regexes use Go RE2 through Janus's DSL.
# These are Python raw strings and the DSL consumes one escape layer, therefore
# a regex \s or \$ must be written as \\s / \\$ below.
RULES: list[dict[str, Any]] = [
    # SQL injection
    _http(
        "sqli", "SQLi: UNION SELECT payload",
        r"""body matches '(?i)union[[:space:]]+(all[[:space:]]+)?select' OR url matches '(?i)union(%20|\\+)+(all(%20|\\+)+)?select'""",
        priority=20,
    ),
    _http(
        "sqli", "SQLi: time-delay primitive",
        r"""body matches '(?i)(sleep|benchmark|pg_sleep)[[:space:]]*\\(' OR body matches '(?i)waitfor[[:space:]]+delay' OR url matches '(?i)(sleep|benchmark|pg_sleep)(%20|\\+)*%28'""",
        priority=20,
    ),
    _http(
        "sqli", "SQLi: schema or file extraction",
        r"""body icontains "information_schema" OR url icontains "information_schema" OR body matches '(?i)(extractvalue|updatexml|load_file|into[[:space:]]+(out|dump)file)'""",
        priority=25,
    ),
    _http(
        "sqli", "SQLi: numeric tautology",
        r"""body matches '(?i)(or|and)[[:space:]]+[0-9]+[[:space:]]*=[[:space:]]*[0-9]+' OR url matches '(?i)(or|and)(%20|\\+)+[0-9]+(%20|\\+)*(=|%3d)(%20|\\+)*[0-9]+'""",
        priority=30,
    ),

    # NoSQL injection
    _http(
        "nosqli", "NoSQLi: Mongo $where expression",
        r'''body matches '(?i)\\$where[[:space:]]*[:=]' OR url icontains "%24where" OR url icontains "$where"''',
        priority=20,
    ),
    _http(
        "nosqli", "NoSQLi: operator in authentication data",
        r"""(body icontains "username" OR body icontains "password" OR body icontains "email") AND body matches '(?i)\\$(ne|regex|gt|gte|lt|lte|exists)[[:space:]]*[:=]'""",
        priority=25,
    ),
    _http(
        "nosqli", "NoSQLi: URL-encoded authentication operator",
        r"""url matches '(?i)(user|username|email|password).*(%24(ne|regex|gt|gte|lt|lte)|\\$(ne|regex|gt|gte|lt|lte))'""",
        priority=30,
    ),

    # Command injection
    _http(
        "cmdi", "CMDi: shell separator plus command",
        r"""body matches '(?i)(;|\\|\\||&&|\\||\\$\\(|`)[[:space:]]*(id|whoami|uname|cat|curl|wget|nc|ncat|bash|sh)([[:space:]]|$)'""",
        priority=20,
    ),
    _http(
        "cmdi", "CMDi: encoded shell separator plus command",
        r"""url matches '(?i)(%3b|%7c|%26%26|%60|%24%28)(%20|\\+)*(id|whoami|uname|cat|curl|wget|nc|bash|sh)'""",
        priority=20,
    ),
    _http(
        "cmdi", "CMDi: reverse-shell construction",
        r"""body matches '(?i)(/dev/tcp/|bash[[:space:]]+-i|nc[[:space:]]+-[a-z]*e|mkfifo[[:space:]]+/tmp/|python[[:space:]]+-c.*socket)'""",
        priority=15,
    ),

    # SSRF
    _http(
        "ssrf", "SSRF: cloud metadata endpoint",
        r"""body matches '(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.aws)' OR url matches '(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.aws)'""",
        priority=15,
    ),
    _http(
        "ssrf", "SSRF: dangerous URI scheme",
        r"""body matches '(?i)(file|gopher|dict|ldap|tftp|jar)://' OR url matches '(?i)(file|gopher|dict|ldap|tftp|jar)://'""",
        priority=20,
    ),
    _http(
        "ssrf", "SSRF: loopback URL target",
        r"""body matches '(?i)(https?|gopher)://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|0177\\.0\\.0\\.1|0x7f000001)' OR url matches '(?i)(https?|gopher)://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|0177\\.0\\.0\\.1|0x7f000001)'""",
        priority=20,
    ),

    # XSS
    _http(
        "xss", "XSS: active tag or handler payload",
        r"""body matches '(?i)<[[:space:]]*script([[:space:]>])' OR body matches '(?i)<[[:space:]]*(svg|img|iframe|object)[^>]*[[:space:]]on[a-z]+[[:space:]]*=' OR url matches '(?i)(%3c|&lt;)script'""",
        priority=25,
    ),
    _http(
        "xss", "XSS: javascript URI in an active attribute",
        r'''body matches '(?i)(href|src)[[:space:]]*=[[:space:]]*[^[:space:]]*javascript:' OR url icontains "javascript:"''',
        priority=30,
    ),

    # Traversal / LFI
    _http(
        "path", "Path traversal: plain, encoded, or double-encoded",
        r"""url matches '(?i)(\\.\\./|%2e%2e(%2f|%5c|/)|%252e%252e(%252f|%255c))'""",
        priority=15,
    ),
    _http(
        "lfi", "LFI: sensitive local file target",
        r"""url matches '(?i)/(etc/(passwd|shadow)|proc/self/(environ|cmdline)|windows/win\\.ini|boot\\.ini)' OR body matches '(?i)/(etc/(passwd|shadow)|proc/self/(environ|cmdline))'""",
        priority=15,
    ),
    _http(
        "lfi", "LFI: PHP or archive wrapper",
        r'''url icontains "php://filter" OR url icontains "php://input" OR url icontains "expect://" OR url icontains "phar://" OR body icontains "php://filter" OR body icontains "php://input" OR body icontains "expect://" OR body icontains "phar://"''',
        priority=20,
    ),

    # XML / template / code-execution primitives
    _http(
        "xxe", "XXE: external entity declaration",
        r"""body matches '(?i)<![[:space:]]*(DOCTYPE|ENTITY)[[:space:]][^>]*(SYSTEM|PUBLIC)'""",
        priority=15,
    ),
    _http(
        "ssti", "SSTI: dangerous template object chain",
        r"""body matches '(?i)(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__)'""",
        priority=20,
    ),
    _http(
        "jndi", "JNDI: remote lookup expression",
        r"""header matches '(?i)\\$\\{[^}]*jndi:(ldap|rmi|dns|iiop)://' OR body matches '(?i)\\$\\{[^}]*jndi:(ldap|rmi|dns|iiop)://' OR url matches '(?i)\\$\\{[^}]*jndi:(ldap|rmi|dns|iiop)://'""",
        priority=15,
    ),

    # Serialization, uploads, and HTTP parser abuse
    _http(
        "deser", "Deserialization: known gadget class",
        r"""body matches '(?i)(CommonsCollections|InvokerTransformer|TemplatesImpl|JRMPClient|ObjectStateFormatter|BinaryFormatter|TypeNameHandling)'""",
        priority=20,
    ),
    _http(
        "deser", "Deserialization: PHP object payload",
        r"""body matches '(?i)(^|[&;])[^=&]+=(O|C):[0-9]+:'""",
        priority=35,
    ),
    _http(
        "prototype-pollution", "Prototype pollution key",
        r'''body matches '(?i)"(__proto__|constructor)"[[:space:]]*:' ''',
        priority=35,
    ),
    _http(
        "upload", "Upload: executable filename",
        r'''header matches '(?i)filename=[^[:space:];]*\\.(php[0-9]?|phtml|phar|jsp|asp[x]?|cgi)(["[:space:];]|$)' ''',
        priority=30,
    ),
    _http(
        "upload", "Upload: image or document double extension",
        r'''header matches '(?i)filename=[^[:space:];]*\\.(jpg|jpeg|png|gif|pdf)\\.(php|phtml|jsp|asp[x]?|cgi)(["[:space:];]|$)' ''',
        priority=30,
    ),
    _http(
        "request-smuggling", "HTTP request smuggling: TE plus Content-Length",
        'header.Transfer-Encoding icontains "chunked" AND header.Content-Length != ""',
        priority=25,
    ),
    _http(
        "request-smuggling", "HTTP request smuggling: encoded header split",
        r"""url matches '(?i)%0d%0a(content-length|transfer-encoding|host):'""",
        priority=20,
    ),

    # TCP: raw bytes only, evaluated on client -> backend chunks.
    _tcp(
        "tcp", "TCP SQLi: UNION SELECT",
        r"""raw matches '(?i)union[[:space:]]+(all[[:space:]]+)?select'""",
        priority=25,
    ),
    _tcp(
        "tcp", "TCP SQLi: time-delay primitive",
        r"""raw matches '(?i)(sleep|benchmark|pg_sleep)[[:space:]]*\\(' OR raw matches '(?i)waitfor[[:space:]]+delay'""",
        priority=25,
    ),
    _tcp(
        "tcp", "TCP command injection: shell separator plus command",
        r"""raw matches '(?i)(;|\\|\\||&&|\\||\\$\\(|`)[[:space:]]*(id|whoami|uname|cat|curl|wget|nc|ncat|bash|sh)([[:space:]]|$)'""",
        priority=20,
    ),
    _tcp(
        "tcp", "TCP command injection: reverse-shell construction",
        r"""raw matches '(?i)(/dev/tcp/|bash[[:space:]]+-i|nc[[:space:]]+-[a-z]*e|mkfifo[[:space:]]+/tmp/)'""",
        priority=15,
    ),
    _tcp(
        "tcp", "TCP path traversal: plain, encoded, or double-encoded",
        r"""raw matches '(?i)(\\.\\./|%2e%2e(%2f|%5c|/)|%252e%252e(%252f|%255c))'""",
        priority=20,
    ),
    _tcp(
        "tcp", "TCP LFI: sensitive local file target",
        r"""raw matches '(?i)/(etc/(passwd|shadow)|proc/self/(environ|cmdline)|windows/win\\.ini|boot\\.ini)'""",
        priority=15,
    ),
    _tcp(
        "tcp", "TCP LFI: PHP or archive wrapper",
        r"""raw matches '(?i)(php://filter|php://input|expect://|phar://)'""",
        priority=20,
    ),
    _tcp(
        "tcp", "TCP SSRF: metadata or dangerous scheme",
        r"""raw matches '(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.aws|(file|gopher|dict|ldap|tftp)://)'""",
        priority=20,
    ),
    _tcp(
        "tcp", "TCP JNDI remote lookup",
        r"""raw matches '(?i)\\$\\{[^}]*jndi:(ldap|rmi|dns|iiop)://'""",
        priority=20,
    ),
    _tcp(
        "tcp", "TCP Java serialization magic",
        r'''raw startswith "\xac\xed\x00\x05"''',
        priority=15,
    ),
    _tcp(
        "tcp", "TCP format-string write probe",
        r"""raw matches '(?:%[0-9]{0,3}\\$?[npx]){3,}'""",
        priority=35,
    ),
]

# Exact names emitted by the former seeder. --prune-legacy only removes these
# when they were created by the selected --display-name.
LEGACY_RULE_NAMES = frozenset({
    "SQLi: UNION/SELECT in body",
    "SQLi: tautology (or 1=1, and 1=1)",
    "SQLi: time-based (sleep/benchmark/pg_sleep/waitfor)",
    "SQLi: stacked / comment chars in URL",
    "SQLi: information_schema probing",
    "CMDi: shell metachars in URL (URL-encoded)",
    "CMDi: shell metachars in body",
    "CMDi: outbound exfil via curl/wget",
    "CMDi: reverse shell shapes",
    "Path traversal: ../ or encoded variants in URL",
    "LFI: /etc/passwd, /proc/self, win.ini probes",
    "Sensitive file probing (.env / .git / .aws / .ssh)",
    "Common admin/scan paths",
    "SSRF: cloud metadata endpoints",
    "SSRF: file:// gopher:// dict:// ftp:// schemes in body",
    "XSS: <script>, javascript:, on*= handlers in body",
    "SSTI: Jinja/EL/Twig/Smarty markers in body",
    "NoSQLi: Mongo operators in JSON body",
    "Java serialized magic (rO0AB / aced0005)",
    "PHP serialized object header (O:N:\"...\")",
    "XXE: external entity declarations",
    "Scanner UA (sqlmap/nikto/nuclei/nmap/wpscan/acunetix/etc.)",
    "Empty / suspiciously short User-Agent",
    "Oversized request body (>2KB) — possible fuzz / overflow",
    "Buffer-overflow probe — long run of 'A'",
    "Buffer-overflow probe — long run of NUL bytes",
})

assert all(rule["action"] == ALERT for rule in RULES), "the seed catalogue must be alert-only"


class JanusClient:
    def __init__(self, base_url: str, password: str, display_name: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.display_name = display_name
        self.token = self._login(password, display_name)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if hasattr(self, "token") and self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, self._decode(response.read())
        except urllib.error.HTTPError as error:
            return error.code, {"error": error.read().decode(errors="replace").strip()}
        except urllib.error.URLError as error:
            return 0, {"error": f"network error: {error.reason}"}

    @staticmethod
    def _decode(payload: bytes) -> Any:
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {"error": payload.decode(errors="replace")}

    def _login(self, password: str, display_name: str) -> str:
        status, body = self._request("POST", "/api/login", {
            "password": password,
            "display_name": display_name,
        })
        if status != 200 or not isinstance(body, dict) or "token" not in body:
            error = body.get("error") if isinstance(body, dict) else "unknown"
            raise SystemExit(f"login failed (HTTP {status}): {error}")
        # Janus trims/caps the name at login; retain that server-authoritative
        # value so ownership-restricted cleanup keeps working for custom names.
        self.display_name = str(body.get("display_name") or self.display_name)
        return str(body["token"])

    def list_services(self) -> list[dict[str, Any]]:
        status, body = self._request("GET", "/api/services")
        if status != 200 or not isinstance(body, list):
            raise SystemExit(f"list services failed (HTTP {status}): {body}")
        return body

    def list_rules(self, service_id: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"service_id": service_id})
        status, body = self._request("GET", f"/api/rules?{query}")
        if status != 200 or not isinstance(body, list):
            raise SystemExit(f"list rules for {service_id!r} failed (HTTP {status}): {body}")
        return body

    def create_rule(self, rule: dict[str, Any]) -> tuple[int, Any]:
        return self._request("POST", "/api/rules", rule)

    def delete_rule(self, rule_id: str) -> tuple[int, Any]:
        return self._request("DELETE", f"/api/rules/{urllib.parse.quote(rule_id, safe='')}")

    def validate_expression(self, expression: str) -> tuple[bool, str]:
        status, body = self._request("POST", "/api/filter/validate", {"expression": expression})
        if status != 200:
            return False, str(body)
        if not isinstance(body, dict) or not body.get("ok"):
            return False, str((body or {}).get("error", body))
        return True, ""


def available_categories() -> tuple[str, ...]:
    return tuple(sorted({str(rule["category"]) for rule in RULES}))


def select_rules(categories: Iterable[str]) -> list[dict[str, Any]]:
    requested = {category.lower() for category in categories}
    known = set(available_categories())
    unknown = sorted(requested - known)
    if unknown:
        raise ValueError(f"unknown category: {', '.join(unknown)} (known: {', '.join(sorted(known))})")
    return [rule for rule in RULES if not requested or rule["category"] in requested]


def resolve_services(
    all_services: list[dict[str, Any]], rule: dict[str, Any], only: set[str]
) -> list[dict[str, Any]]:
    """Return services matching a template's explicit service scope and protocol."""
    scope = str(rule["service"])
    protocols = set(rule["protocols"])
    candidates = all_services if scope == "all" else [
        service for service in all_services
        if service.get("id") == scope or service.get("name") == scope
    ]
    return [
        service for service in candidates
        if (not only or service.get("id") in only or service.get("name") in only)
        and str(service.get("protocol", "")).lower() in protocols
    ]


def validate_catalogue(client: JanusClient, rules: list[dict[str, Any]]) -> bool:
    """Use the same parser/compiler as Janus before changing any rules."""
    print(f"Validating {len(rules)} template(s) against Janus's filter DSL …")
    failed = 0
    for rule in rules:
        ok, error = client.validate_expression(str(rule["expression"]))
        if ok:
            continue
        failed += 1
        print(f"  ✗ {rule['name']}: {error}", file=sys.stderr)
    if failed:
        print(f"Catalogue validation failed: {failed} invalid template(s). No rules were changed.", file=sys.stderr)
        return False
    print("Catalogue validation passed.")
    return True


def remove_owned_rules(
    client: JanusClient,
    services: list[dict[str, Any]],
    *,
    display_name: str,
    seeded_names: set[str],
    replace_seeded: bool,
    prune_legacy: bool,
) -> tuple[int, int]:
    """Delete only rules demonstrably owned by this seeder display name."""
    deleted = failed = 0
    for service in services:
        service_id = str(service["id"])
        for rule in client.list_rules(service_id):
            if rule.get("created_by") != display_name:
                continue
            name = str(rule.get("name", ""))
            # A category-scoped --replace-seeded must not remove other seeded
            # categories. Match the selected template names exactly.
            is_seeded = replace_seeded and name in seeded_names
            is_legacy = prune_legacy and name in LEGACY_RULE_NAMES
            if not (is_seeded or is_legacy):
                continue
            status, body = client.delete_rule(str(rule.get("id", "")))
            if status == 204:
                deleted += 1
                print(f"  − removed {service_id}: {name}")
            else:
                failed += 1
                print(f"  ✗ could not remove {service_id}: {name} (HTTP {status}: {body})", file=sys.stderr)
    return deleted, failed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install curated, alert-only Janus rules for CTF A/D services."
    )
    parser.add_argument(
        "--url", default=os.environ.get("JANUS_URL", "http://localhost:2999"),
        help="Janus UI/API base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--password", default=os.environ.get("JANUS_PASSWORD"),
        help="Janus team password (or set JANUS_PASSWORD)",
    )
    parser.add_argument(
        "--display-name", default="rule-seeder",
        help="Display name recorded as the rule creator (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--service", action="append", default=[],
        help="Restrict to service ID/name; repeatable. Default: every enabled compatible service.",
    )
    parser.add_argument(
        "--category", action="append", default=[],
        help="Install only a category; repeatable. Use --list-categories to inspect choices.",
    )
    parser.add_argument("--include-disabled", action="store_true", help="Also seed disabled services.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Print selected rules without contacting Janus.")
    mode.add_argument("--validate-only", action="store_true", help="Validate selected expressions without creating rules.")
    mode.add_argument("--list-categories", action="store_true", help="List available categories and exit.")
    parser.add_argument(
        "--replace-seeded", action="store_true",
        help=f"Remove matching selected {SEED_PREFIX} rules created by --display-name before reseeding.",
    )
    parser.add_argument(
        "--prune-legacy", action="store_true",
        help="Remove exact former-seeder names created by --display-name before reseeding.",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if (args.dry_run or args.validate_only or args.list_categories) and (args.replace_seeded or args.prune_legacy):
        parser.error("cleanup options require a normal seed run")
    if args.prune_legacy and args.category:
        parser.error("--prune-legacy cannot be combined with --category; it removes the complete old catalogue in scope")
    return args


def main() -> int:
    args = parse_args()
    if args.list_categories:
        counts = Counter(str(rule["category"]) for rule in RULES)
        for category in available_categories():
            print(f"{category:22s} {counts[category]:2d} template(s)")
        return 0

    try:
        rules = select_rules(args.category)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    only = set(args.service)

    if args.dry_run:
        print(f"[dry-run] Selected {len(rules)} alert-only template(s).")
        for rule in rules:
            protocols = ", ".join(sorted(rule["protocols"]))
            print(f"  - {rule['category']:22s} | {protocols:20s} | {rule['name']}")
            print(f"      {rule['expression']}")
        return 0

    if not args.password:
        try:
            args.password = getpass.getpass("Janus password: ")
        except (KeyboardInterrupt, EOFError):
            print("\naborted", file=sys.stderr)
            return 130

    client = JanusClient(args.url, args.password, args.display_name, args.timeout)
    if not validate_catalogue(client, rules):
        return 2
    if args.validate_only:
        return 0

    services = client.list_services()
    if not args.include_disabled:
        services = [service for service in services if service.get("enabled", True)]
    if only:
        services = [service for service in services if service.get("id") in only or service.get("name") in only]
    if not services:
        print("No services found in scope. Nothing to do.", file=sys.stderr)
        return 1

    print(f"Connected to {args.url} — {len(services)} service(s) in scope.")
    cleanup_failed = 0
    if args.replace_seeded or args.prune_legacy:
        removed, cleanup_failed = remove_owned_rules(
            client, services, display_name=client.display_name,
            seeded_names={str(rule["name"]) for rule in rules},
            replace_seeded=args.replace_seeded, prune_legacy=args.prune_legacy,
        )
        print(f"Cleanup removed {removed} rule(s), failed {cleanup_failed}.")

    created = skipped = failed = 0
    for rule in rules:
        for service in resolve_services(services, rule, only):
            expression = str(rule["expression"])
            payload = {
                "service_id": service["id"],
                "name": rule["name"],
                "expression": expression,
                # Expression is the source of truth. Retain a readable pattern
                # so alert/detail panels explain what triggered during the
                # legacy-model transition.
                "type": "regex",
                "scope": "expression",
                "pattern": expression,
                "action": ALERT,
                "priority": rule["priority"],
                "enabled": True,
            }
            status, body = client.create_rule(payload)
            tag = f"alert on {service['id']}"
            if status in (200, 201):
                created += 1
                print(f"  ✓ {tag} — {rule['name']}")
            elif status == 409:
                skipped += 1
                print(f"  · {tag} — already exists")
            else:
                failed += 1
                error = body.get("error", body) if isinstance(body, dict) else body
                print(f"  ✗ {tag} — HTTP {status}: {error}", file=sys.stderr)

    failed += cleanup_failed
    print(f"\nDone — created {created}, skipped {skipped}, failed {failed}.")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
