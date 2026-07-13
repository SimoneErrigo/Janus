#!/usr/bin/env python3
"""Move challenge ports behind Janus and prepare its service configuration.

The script uses static hints from each Compose service and its build context,
then lets the operator review every value.  No file is changed before the
final confirmation.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

PORT_MIN = 11500
PORT_MAX = 12000
PROTOCOLS = ("http", "https", "h2", "grpc", "tcp")
TLS_PROTOCOLS = {"https", "h2", "grpc"}
COMMENT_MAPPING_KEY = "janus-original-mapping"
COMMENT_PORT_KEY = "janus-original-port"
COMPOSE_NAMES = {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
SKIP_DIRS = {
    ".git", ".idea", ".vscode", "Janus", "__pycache__", "backend",
    "certs", "data", "frontend", "node_modules", "protos", "scripts",
}
SOURCE_SKIP_DIRS = {".git", ".idea", ".vscode", "__pycache__", "node_modules", "vendor", "data"}
SOURCE_SUFFIXES = {
    ".c", ".cc", ".conf", ".cpp", ".cs", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".json", ".jsx", ".key", ".lua", ".mjs", ".pem", ".php",
    ".proto", ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx", ".xml",
    ".yaml", ".yml", ".crt",
}
PORT_CHECK_WARNING_SHOWN = False

PORT_LINE_RE = re.compile(
    r"""^(?P<indent>\s*)-\s*(?P<quote>["']?)(?P<mapping>[^"'\s#]+)(?P=quote)(?P<tail>\s*(?:\#.*)?)$"""
)


@dataclass(frozen=True)
class PortMapping:
    bind_ip: str | None
    host_port: str
    container_port: str


@dataclass(frozen=True)
class PortPlan:
    compose: Path
    line: int
    service: str
    original_mapping: str
    original_port: int
    target_port: int
    container_port: int
    already_patched: bool


@dataclass(frozen=True)
class RestoreChange:
    compose: Path
    service: str
    patched_mapping: str
    restored_mapping: str


@dataclass
class Inference:
    protocol: str
    target_tls: bool = False
    cert: Path | None = None
    key: Path | None = None
    ca: Path | None = None
    protos: list[Path] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class ServicePlan:
    id: str
    name: str
    listen_addr: str
    listen_port: int
    target_addr: str
    protocol: str
    target_tls: bool
    tls_mode: str = ""
    cert_source: Path | None = None
    key_source: Path | None = None
    ca_source: Path | None = None
    cert_file: str = ""
    key_file: str = ""
    proto_sources: list[Path] = field(default_factory=list)
    proto_paths: list[str] = field(default_factory=list)
    enabled: bool = True

    def as_json(self) -> dict:
        value = {
            "id": self.id,
            "name": self.name,
            "listen_addr": self.listen_addr,
            "listen_port": self.listen_port,
            "target_addr": self.target_addr,
            "protocol": self.protocol,
            "enabled": self.enabled,
        }
        if self.target_tls:
            value["target_tls"] = True
        if self.tls_mode:
            value["tls_mode"] = self.tls_mode
        if self.cert_file:
            value["cert_file"] = self.cert_file
            value["key_file"] = self.key_file
        if self.proto_paths:
            value["proto_paths"] = self.proto_paths
        # protocol_id is deliberately omitted: custom protocol stays None.
        return value


def is_port_free(port: int) -> bool:
    global PORT_CHECK_WARNING_SHOWN
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except PermissionError:
            if not PORT_CHECK_WARNING_SHOWN:
                print("  warning: cannot bind-test localhost ports here; checking duplicates only")
                PORT_CHECK_WARNING_SHOWN = True
            return True
        except OSError:
            return False
    return True


class PortAllocator:
    def __init__(
        self, low: int, high: int, needed: int, start: int | None = None,
        reserved: set[int] | None = None,
    ) -> None:
        if low > high:
            raise RuntimeError("--min-port must be <= --max-port")
        self.reserved = reserved or set()
        if start is None:
            blocked = sum(low <= port <= high for port in self.reserved)
            last_start = high - max(needed, 1) - blocked + 1
            if last_start < low:
                raise RuntimeError(f"range {low}-{high} is too small for {needed} port mappings")
            start = random.randint(low, last_start)
        if start < low or start > high:
            raise RuntimeError(f"start port {start} is outside range {low}-{high}")
        self.next_port = start
        self.high = high

    def take(self) -> int:
        while self.next_port <= self.high and (
            self.next_port in self.reserved or not is_port_free(self.next_port)
        ):
            print(f"  skip occupied/reserved port {self.next_port}")
            self.next_port += 1
        if self.next_port > self.high:
            raise RuntimeError(f"no free sequential ports available up to {self.high}")
        port = self.next_port
        self.next_port += 1
        return port


def parse_mapping(raw: str) -> PortMapping | None:
    if "/" in raw or "-" in raw:
        return None
    parts = raw.split(":")
    if len(parts) == 2:
        bind_ip, host_port, container_port = None, *parts
    elif len(parts) == 3:
        bind_ip, host_port, container_port = parts
    else:
        return None
    if not host_port.isdigit() or not container_port.isdigit():
        return None
    return PortMapping(bind_ip, host_port, container_port)


def has_janus_comment(line: str) -> bool:
    return (
        COMMENT_MAPPING_KEY in line
        or COMMENT_PORT_KEY in line
        or re.fullmatch(r"\s*#\s*\d+\s*", line) is not None
    )


def extract_restore_mapping(tail: str, current: PortMapping) -> str | None:
    if not tail.strip().startswith("#"):
        return None
    parts = [part.strip() for part in tail.strip()[1:].split("|")]
    for part in parts:
        if part.startswith(f"{COMMENT_MAPPING_KEY}:"):
            return part.split(":", 1)[1].strip()
    for part in parts:
        if part.startswith(f"{COMMENT_PORT_KEY}:"):
            original_port = part.split(":", 1)[1].strip()
            if original_port.isdigit():
                return f"127.0.0.1:{original_port}:{current.container_port}"
    # Compatibility with the original helper, which saved only the checker
    # port as a bare numeric comment: "127.0.0.1:10002:3000 #5000".
    if len(parts) == 1 and parts[0].isdigit():
        bind = f"{current.bind_ip}:" if current.bind_ip else ""
        return f"{bind}{parts[0]}:{current.container_port}"
    return None


def remove_janus_comment(tail: str) -> str:
    if not tail.strip().startswith("#"):
        return tail
    keep = [
        part.strip() for part in tail.strip()[1:].split("|")
        if not part.strip().startswith((f"{COMMENT_MAPPING_KEY}:", f"{COMMENT_PORT_KEY}:"))
        and not part.strip().isdigit()
    ]
    return f" # {' | '.join(filter(None, keep))}" if any(keep) else ""


def discover_compose_files(root: Path, include_root: bool, exclude_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    for current, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in exclude_dirs and not name.startswith(".")]
        current_path = Path(current)
        for name in names:
            if name in COMPOSE_NAMES and (include_root or current_path != root):
                files.append(current_path / name)
    return sorted(files)


def current_service(
    line: str, in_services: bool, services_indent: int, service_indent: int | None
) -> tuple[str | None, bool, int, int | None]:
    stripped = line.strip()
    indent = len(line) - len(line.lstrip())
    if stripped == "services:":
        return None, True, indent, None
    if in_services and indent <= services_indent and stripped and not stripped.startswith("#"):
        return None, False, services_indent, None
    if in_services and indent > services_indent and stripped.endswith(":"):
        if service_indent is None:
            service_indent = indent
        if indent == service_indent:
            return stripped[:-1].strip("\"'"), True, services_indent, service_indent
    return None, in_services, services_indent, service_indent


def iter_port_lines(path: Path):
    in_services = False
    services_indent = -1
    service_indent: int | None = None
    service = ""
    in_ports = False
    ports_indent = -1
    for index, line in enumerate(path.read_text(encoding="utf8").splitlines()):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        found, in_services, services_indent, service_indent = current_service(
            line, in_services, services_indent, service_indent
        )
        if found is not None:
            service = found
            in_ports = False
        if in_services and stripped == "ports:":
            in_ports, ports_indent = True, indent
            continue
        if in_ports and stripped and indent <= ports_indent:
            in_ports = False
        if not in_ports:
            continue
        match = PORT_LINE_RE.match(line)
        if match:
            yield index, service or "<unknown>", match, parse_mapping(match.group("mapping"))


def count_unpatched_mappings(paths: list[Path]) -> int:
    return sum(
        1 for path in paths for _, _, match, mapping in iter_port_lines(path)
        if mapping is not None and not has_janus_comment(match.group("tail"))
    )


def patched_target_ports(paths: list[Path]) -> set[int]:
    return {
        int(mapping.host_port)
        for path in paths for _, _, match, mapping in iter_port_lines(path)
        if mapping is not None and extract_restore_mapping(match.group("tail"), mapping) is not None
    }


def build_port_plans(paths: list[Path], allocator: PortAllocator) -> list[PortPlan]:
    plans: list[PortPlan] = []
    for path in paths:
        for line, service, match, current in iter_port_lines(path):
            raw = match.group("mapping")
            if current is None:
                print(f"  skip {path}: unsupported port mapping {raw!r}")
                continue
            original_raw = extract_restore_mapping(match.group("tail"), current)
            already_patched = original_raw is not None
            original = parse_mapping(original_raw) if original_raw else current
            if original is None:
                print(f"  skip {path}: invalid Janus restore comment")
                continue
            target_port = int(current.host_port) if already_patched else allocator.take()
            plans.append(PortPlan(
                path, line, service, original_raw or raw, int(original.host_port),
                target_port, int(current.container_port), already_patched,
            ))
    return plans


def patch_compose(plans: list[PortPlan]) -> None:
    by_file: dict[Path, list[PortPlan]] = {}
    for plan in plans:
        if not plan.already_patched:
            by_file.setdefault(plan.compose, []).append(plan)
    for path, changes in by_file.items():
        lines = path.read_text(encoding="utf8").splitlines(keepends=True)
        for change in changes:
            line = lines[change.line]
            newline = "\n" if line.endswith("\n") else ""
            body = line[:-1] if newline else line
            match = PORT_LINE_RE.match(body)
            if not match:
                raise RuntimeError(f"port line changed while reviewing: {path}:{change.line + 1}")
            quote = match.group("quote") or '"'
            tail = match.group("tail").strip()
            comment = f"# {COMMENT_MAPPING_KEY}: {match.group('mapping')}"
            if tail:
                comment = f"{tail} | {COMMENT_MAPPING_KEY}: {match.group('mapping')}"
            lines[change.line] = (
                f"{match.group('indent')}- {quote}127.0.0.1:{change.target_port}:{change.container_port}{quote} "
                f"{comment}{newline}"
            )
        path.write_text("".join(lines), encoding="utf8")


def restore_compose(path: Path, dry_run: bool) -> list[RestoreChange]:
    lines = path.read_text(encoding="utf8").splitlines(keepends=True)
    changes: list[RestoreChange] = []
    for index, service, match, current in iter_port_lines(path):
        if current is None or not has_janus_comment(match.group("tail")):
            continue
        restored = extract_restore_mapping(match.group("tail"), current)
        if restored is None:
            continue
        line = lines[index]
        newline = "\n" if line.endswith("\n") else ""
        quote = match.group("quote") or '"'
        tail = remove_janus_comment(match.group("tail"))
        lines[index] = f"{match.group('indent')}- {quote}{restored}{quote}{tail}{newline}"
        changes.append(RestoreChange(path, service, match.group("mapping"), restored))
    if changes and not dry_run:
        path.write_text("".join(lines), encoding="utf8")
    return changes


def service_block(path: Path, wanted: str) -> list[str]:
    lines = path.read_text(encoding="utf8").splitlines()
    in_services = False
    services_indent = -1
    service_indent: int | None = None
    active = False
    block: list[str] = []
    for line in lines:
        found, in_services, services_indent, service_indent = current_service(
            line, in_services, services_indent, service_indent
        )
        if found is not None:
            if active:
                break
            active = found == wanted
        if active:
            block.append(line)
    return block


def service_sources(compose: Path, service: str) -> tuple[list[Path], list[Path], str]:
    block = service_block(compose, service)
    base = compose.parent
    roots: list[Path] = []
    files: list[Path] = []
    build_indent: int | None = None
    for line in block:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped.startswith("build:"):
            value = stripped.split(":", 1)[1].strip().strip("\"'")
            if value:
                roots.append((base / value).resolve())
            else:
                build_indent = indent
            continue
        if build_indent is not None and indent > build_indent and stripped.startswith("context:"):
            value = stripped.split(":", 1)[1].strip().strip("\"'")
            roots.append((base / value).resolve())
        if stripped.startswith("-") and ":" in stripped:
            host = stripped[1:].strip().strip("\"'").split(":", 1)[0]
            if host.startswith("./") or host.startswith("../"):
                candidate = (base / host).resolve()
                (files if candidate.is_file() else roots).append(candidate)
    fallback = base / service
    if not roots and fallback.is_dir():
        roots.append(fallback.resolve())
    return list(dict.fromkeys(roots)), list(dict.fromkeys(files)), "\n".join(block).lower()


def source_files(roots: list[Path], explicit: list[Path]):
    seen: set[Path] = set()
    for path in explicit:
        if path.is_file() and path not in seen:
            seen.add(path)
            yield path
    for root in roots:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = (
                path for path in root.rglob("*")
                if path.is_file() and not any(part in SOURCE_SKIP_DIRS for part in path.parts)
            )
        else:
            continue
        for path in candidates:
            if path in seen or path.stat().st_size > 512_000:
                continue
            if path.suffix.lower() in SOURCE_SUFFIXES or path.name.lower() in {"dockerfile", "requirements.txt", "gemfile"}:
                seen.add(path)
                yield path


def find_tls_files(paths: list[Path]) -> tuple[Path | None, Path | None, Path | None]:
    pem = [path for path in paths if path.suffix.lower() in {".pem", ".crt", ".key"}]
    contents = {path: path.read_text(encoding="ascii", errors="ignore") for path in pem}
    keys = [path for path in pem if "key" in path.name.lower() or "PRIVATE KEY" in contents[path]]
    cas = [path for path in pem if any(word in path.name.lower() for word in ("ca", "chain", "root"))]
    certs = [
        path for path in pem
        if path not in keys and path not in cas and "BEGIN CERTIFICATE" in contents[path]
    ]
    return (certs[0] if certs else None, keys[0] if keys else None, cas[0] if cas else None)


def infer_service(plan: PortPlan) -> Inference:
    roots, explicit, compose_text = service_sources(plan.compose, plan.service)
    paths = list(source_files(roots, explicit))
    text_parts = [compose_text]
    protos: list[Path] = []
    for path in paths:
        if path.suffix.lower() == ".proto":
            protos.append(path)
        if path.suffix.lower() in {".pem", ".crt", ".key"}:
            continue
        try:
            text_parts.append(path.read_text(encoding="utf8", errors="ignore").lower())
        except OSError:
            pass
    text = "\n".join(text_parts)
    grpc = bool(protos) or any(hint in text for hint in ("grpc.server", "grpc_server", "grpcio", "add_insecure_port", "add_secure_port"))
    h2 = any(hint in text for hint in ("http2", "http/2", "h2c", "nextprotos"))
    http = (
        plan.service.lower() in {"frontend", "web", "nginx", "apache"}
        or any(hint in text for hint in (
            "nginx", "apache2", "express(", "from flask", "import flask", "fastapi(",
            "http.server", "listenandserve", "gunicorn", "uwsgi", "php-fpm",
        ))
        or plan.container_port in {80, 443, 3000, 5000, 8000, 8080, 8081}
    )
    tls = any(hint in text for hint in (
        "ssl_server_credentials", "add_secure_port", "listenandservetls", "ssl_context",
        "certfile", "keyfile", "ssl_certificate", "listen 443", "server-cert", "server_key",
    )) or plan.container_port == 443
    cert, key, ca = find_tls_files(paths)
    if cert and key:
        tls = True

    if grpc:
        protocol = "grpc"
        evidence = ["riferimenti gRPC/.proto nel build context"]
    elif h2:
        protocol = "h2"
        evidence = ["riferimenti HTTP/2 nel build context"]
    elif http:
        protocol = "https" if tls else "http"
        evidence = ["frontend/framework o porta HTTP"]
    else:
        protocol = "tcp"
        evidence = ["nessun protocollo applicativo riconosciuto (fallback TCP)"]
    if tls:
        evidence.append("TLS rilevato nel codice/configurazione")
    return Inference(protocol, tls, cert, key, ca, sorted(protos), evidence)


def read_env_value(path: Path, key: str) -> str:
    if not path.exists():
        return ""
    for raw in path.read_text(encoding="utf8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip("\"'")
    return ""


def ask(prompt: str, default: str = "", required: bool = True) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip() or default
        if value or not required:
            return value
        print("  value required")


def ask_bool(prompt: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} [{hint}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "s", "si", "sì"}:
            return True
        if value in {"n", "no"}:
            return False
        print("  answer y or n")


def ask_choice(prompt: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        value = ask(f"{prompt} ({'/'.join(choices)})", default).lower()
        if value in choices:
            return value
        print(f"  choose one of: {', '.join(choices)}")


def ask_port(prompt: str, default: int) -> int:
    while True:
        value = ask(prompt, str(default))
        if value.isdigit() and 0 < int(value) <= 65535:
            return int(value)
        print("  port must be between 1 and 65535")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    return slug or "svc"


def unique_id(name: str, used: set[str]) -> str:
    base = slugify(name)
    candidate = base
    number = 2
    while candidate in used:
        candidate = f"{base}-{number}"
        number += 1
    used.add(candidate)
    return candidate


def suggested_names(plans: list[PortPlan]) -> dict[tuple[Path, str, int], str]:
    compose_counts: dict[Path, int] = {}
    service_counts: dict[tuple[Path, str], int] = {}
    for plan in plans:
        compose_counts[plan.compose] = compose_counts.get(plan.compose, 0) + 1
        key = (plan.compose, plan.service)
        service_counts[key] = service_counts.get(key, 0) + 1
    names = {}
    for plan in plans:
        project = plan.compose.parent.name
        name = project if compose_counts[plan.compose] == 1 else f"{project}-{plan.service}"
        if service_counts[(plan.compose, plan.service)] > 1:
            name += f"-{plan.original_port}"
        names[(plan.compose, plan.service, plan.original_port)] = name
    return names


def existing_services(path: Path) -> list[dict]:
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf8"))
    if not isinstance(value, list):
        raise RuntimeError(f"{path} must contain a JSON list")
    return value


def proto_destination(source: Path, service_id: str) -> tuple[Path, str]:
    relative = Path(service_id) / source.name
    return relative, f"/protos/{relative.as_posix()}"


def review_services(
    port_plans: list[PortPlan], team_ip: str, services_file: Path
) -> tuple[list[ServicePlan], list[PortPlan]]:
    existing = existing_services(services_file)
    used = {str(service.get("id", "")) for service in existing}
    existing_ids = {
        str(service.get("name", "")): str(service.get("id", ""))
        for service in existing if service.get("name") and service.get("id")
    }
    names = suggested_names(port_plans)
    reviewed: list[ServicePlan] = []
    selected_ports: list[PortPlan] = []
    for port in port_plans:
        inference = infer_service(port)
        rel = port.compose.relative_to(Path.cwd()) if port.compose.is_relative_to(Path.cwd()) else port.compose
        state = "già spostata" if port.already_patched else "da spostare"
        print(f"\n[{rel} / {port.service}] {port.original_port} -> 127.0.0.1:{port.target_port} ({state})")
        print(f"  rilevamento: {inference.protocol}, backend TLS={'yes' if inference.target_tls else 'no'}; {'; '.join(inference.evidence)}")
        if not ask_bool("Configurare questa porta in Janus?", True):
            continue

        default_name = names[(port.compose, port.service, port.original_port)]
        name = ask("Name", default_name)
        listen_addr = ask("Listen address", team_ip)
        listen_port = ask_port("Listen port", port.original_port)
        target_addr = ask("Target address", f"127.0.0.1:{port.target_port}")
        protocol = ask_choice("Protocol", PROTOCOLS, inference.protocol)
        target_tls = ask_bool("Backend uses TLS?", inference.target_tls)
        service_id = existing_ids.get(name) or unique_id(name, used)
        plan = ServicePlan(service_id, name, listen_addr, listen_port, target_addr, protocol, target_tls)

        if protocol in TLS_PROTOCOLS:
            default_mode = "challenge" if inference.cert and inference.key else "selfsigned"
            plan.tls_mode = ask_choice("TLS mode", ("selfsigned", "challenge"), default_mode)
            if plan.tls_mode == "challenge":
                plan.cert_source = Path(ask("Server certificate", str(inference.cert or ""))).expanduser().resolve()
                plan.key_source = Path(ask("Server key", str(inference.key or ""))).expanduser().resolve()
                ca = ask("CA certificate (optional, appended to fullchain)", str(inference.ca or ""), required=False)
                plan.ca_source = Path(ca).expanduser().resolve() if ca else None
                plan.cert_file = f"/certs/{service_id}-fullchain.pem"
                plan.key_file = f"/certs/{service_id}-key.pem"
                for source in (plan.cert_source, plan.key_source, plan.ca_source):
                    if source is not None and not source.is_file():
                        raise RuntimeError(f"certificate file not found: {source}")

        if protocol in {"grpc", "h2"}:
            default_protos = ",".join(str(path) for path in inference.protos)
            raw = ask("Local .proto files to copy (comma-separated, optional)", default_protos, required=False)
            plan.proto_sources = [Path(value.strip()).expanduser().resolve() for value in raw.split(",") if value.strip()]
            for source in plan.proto_sources:
                if not source.is_file():
                    raise RuntimeError(f".proto file not found: {source}")
            if len({path.name for path in plan.proto_sources}) != len(plan.proto_sources):
                raise RuntimeError("selected .proto files must have distinct names")
            plan.proto_paths = [proto_destination(path, service_id)[1] for path in plan.proto_sources]
        reviewed.append(plan)
        selected_ports.append(port)
    return reviewed, selected_ports


def print_summary(port_plans: list[PortPlan], services: list[ServicePlan], services_file: Path) -> None:
    print("\nPlanned changes:")
    for port in port_plans:
        if not port.already_patched:
            print(f"  compose  {port.compose}: {port.original_mapping} -> 127.0.0.1:{port.target_port}:{port.container_port}")
    for service in services:
        tls = f", TLS={service.tls_mode}, backend-TLS={service.target_tls}" if service.protocol in TLS_PROTOCOLS else f", backend-TLS={service.target_tls}"
        print(
            f"  service  {service.name}: {service.listen_addr}:{service.listen_port} -> "
            f"{service.target_addr}, {service.protocol}{tls}, custom=None"
        )
        if service.proto_paths:
            print(f"           proto: {', '.join(service.proto_paths)}")
    print(f"  config   {services_file}")


def write_assets(services: list[ServicePlan], certs_dir: Path, protos_dir: Path) -> None:
    for service in services:
        if service.tls_mode == "challenge":
            certs_dir.mkdir(parents=True, exist_ok=True)
            fullchain = service.cert_source.read_bytes()
            if not fullchain.endswith(b"\n"):
                fullchain += b"\n"
            if service.ca_source:
                fullchain += service.ca_source.read_bytes()
                if not fullchain.endswith(b"\n"):
                    fullchain += b"\n"
            (certs_dir / Path(service.cert_file).name).write_bytes(fullchain)
            key_target = certs_dir / Path(service.key_file).name
            shutil.copyfile(service.key_source, key_target)
            key_target.chmod(0o600)
        for source in service.proto_sources:
            relative, _ = proto_destination(source, service.id)
            target = protos_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)


def write_services(path: Path, services: list[ServicePlan]) -> None:
    current = existing_services(path)
    by_id = {str(service.get("id", "")): service for service in current}
    for service in services:
        by_id[service.id] = service.as_json()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(by_id.values()), indent=2) + "\n", encoding="utf8")


def is_janus_root(path: Path) -> bool:
    return (
        (path / "docker-compose.yml").is_file()
        and (path / "backend/internal/storage/models.go").is_file()
    )


def find_janus_root() -> Path:
    configured = os.environ.get("JANUS_DIR")
    candidates = [Path(configured)] if configured else []
    candidates.append(Path(__file__).resolve().parent.parent)
    for parent in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        candidates.extend((parent, parent / "Janus", parent / "janus"))
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if is_janus_root(resolved):
            return resolved
    raise RuntimeError("Janus root not found; pass --janus-dir /path/to/Janus")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch Compose ports and configure Janus services with operator review.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How to run:
  Prefer the script inside the Janus repository. It can be invoked from any
  directory; pass the directory containing the challenge services:

    /path/to/Janus/scripts/janus_compose_ports.py /path/to/services

  From the parent directory of Janus and the services, for example:

    ./Janus/scripts/janus_compose_ports.py ./services

  If this script was copied outside the Janus repository, identify Janus
  explicitly (otherwise auto-detection must find a nearby Janus checkout):

    ./janus_compose_ports.py --janus-dir /path/to/Janus /path/to/services

  Review without changing files:

    /path/to/Janus/scripts/janus_compose_ports.py --dry-run /path/to/services

The selected Janus root is printed before review. By default the script writes
Janus/data/services.json, Janus/certs/ and Janus/protos/. Inside the container,
Janus/data/services.json is mounted as /data/services.json. Restart the Janus
backend after applying changes so it reloads the service configuration.
""",
    )
    parser.add_argument("paths", nargs="*", type=Path, help="service directories or Compose files (default: scan below cwd)")
    parser.add_argument("--janus-dir", type=Path, help="Janus repository root (auto-detected by default)")
    parser.add_argument("--restore", action="store_true", help="restore mappings saved in Janus comments")
    parser.add_argument("--include-root", action="store_true", help="also inspect Compose files in the current directory")
    parser.add_argument("--dry-run", action="store_true", help="review everything without writing files")
    parser.add_argument("--exclude-dir", action="append", default=[], metavar="NAME")
    parser.add_argument("--min-port", type=int, default=PORT_MIN)
    parser.add_argument("--max-port", type=int, default=PORT_MAX)
    parser.add_argument("--start-port", type=int)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--services-file", type=Path)
    parser.add_argument("--certs-dir", type=Path)
    parser.add_argument("--protos-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        janus_root = args.janus_dir.expanduser().resolve() if args.janus_dir else find_janus_root()
    except RuntimeError as exc:
        parser.error(str(exc))
    if not is_janus_root(janus_root):
        parser.error(f"not a Janus repository: {janus_root}")
    args.janus_dir = janus_root
    args.env_file = (args.env_file or janus_root / ".env").expanduser().resolve()
    args.services_file = (args.services_file or janus_root / "data/services.json").expanduser().resolve()
    args.certs_dir = (args.certs_dir or janus_root / "certs").expanduser().resolve()
    args.protos_dir = (args.protos_dir or janus_root / "protos").expanduser().resolve()
    return args


def compose_targets(paths: list[Path], include_root: bool, exclude_dirs: set[str]) -> list[Path]:
    if not paths:
        return discover_compose_files(Path.cwd(), include_root, exclude_dirs)
    targets: list[Path] = []
    for raw in paths:
        path = raw.expanduser().resolve()
        if path.is_file() and path.name in COMPOSE_NAMES:
            targets.append(path)
        elif path.is_dir():
            targets.extend(discover_compose_files(path, True, exclude_dirs))
        else:
            print(f"  skip {path}: not a Compose file or directory")
    return sorted(set(targets))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    print(f"Janus root: {args.janus_dir}")
    targets = compose_targets(args.paths, args.include_root, SKIP_DIRS | set(args.exclude_dir))
    if not targets:
        print("No Compose files found.")
        return 0

    if args.restore:
        changes = [change for target in targets for change in restore_compose(target, args.dry_run)]
        if not changes:
            print("No Janus-patched port mappings found.")
            return 0
        print("Planned restores:" if args.dry_run else "Restored mappings:")
        for change in changes:
            print(f"  {change.compose} [{change.service}]: {change.patched_mapping} -> {change.restored_mapping}")
        return 0

    if not sys.stdin.isatty():
        print("error: interactive review requires a terminal", file=sys.stderr)
        return 2
    try:
        needed = count_unpatched_mappings(targets)
        allocator = PortAllocator(
            args.min_port, args.max_port, needed, args.start_port, patched_target_ports(targets)
        )
        port_plans = build_port_plans(targets, allocator)
        if not port_plans:
            print("No supported host port mappings found.")
            return 0
        team_ip = read_env_value(args.env_file, "TEAM_IP")
        if not team_ip:
            team_ip = ask("TEAM_IP / default listen address")
        services, selected_ports = review_services(port_plans, team_ip, args.services_file)
        if not selected_ports:
            print("Nothing selected; no files changed.")
            return 0
        print_summary(selected_ports, services, args.services_file)
        if args.dry_run:
            print("Dry run: no files changed.")
            return 0
        if not ask_bool("Apply all changes?", False):
            print("Cancelled: no files changed.")
            return 0
        patch_compose(selected_ports)
        write_assets(services, args.certs_dir, args.protos_dir)
        write_services(args.services_file, services)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled: no files changed.", file=sys.stderr)
        return 130
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Applied {sum(not plan.already_patched for plan in selected_ports)} port changes and {len(services)} Janus services.")
    print("Restart Janus if it was already running so it reloads data/services.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
