#!/usr/bin/env python3
"""
Move challenge service compose ports behind Janus.

The script only edits docker compose files found below service directories:
host ports are rebound to 127.0.0.1:<random 11500-12000>, while the original
mapping is kept in an inline comment for restore.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

PORT_MIN = 11500
PORT_MAX = 12000
COMMENT_MAPPING_KEY = "janus-original-mapping"
COMMENT_PORT_KEY = "janus-original-port"
COMPOSE_NAMES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}
SKIP_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "Janus",
    "__pycache__",
    "backend",
    "certs",
    "data",
    "frontend",
    "protos",
    "scripts",
}
PORT_CHECK_WARNING_SHOWN = False

PORT_LINE_RE = re.compile(
    r"""
    ^(?P<indent>\s*)-\s*
    (?P<quote>["']?)
    (?P<mapping>[^"'\s#]+)
    (?P=quote)
    (?P<tail>\s*(?:\#.*)?)$
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class PortMapping:
    bind_ip: str | None
    host_port: str
    container_port: str


@dataclass(frozen=True)
class Change:
    compose: Path
    service: str
    original_port: str
    new_port: int
    container_port: str


@dataclass(frozen=True)
class RestoreChange:
    compose: Path
    service: str
    patched_mapping: str
    restored_mapping: str


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
    def __init__(self, low: int, high: int, needed: int, start: int | None = None) -> None:
        if needed <= 0:
            self.next_port = low
            self.high = high
            return

        if start is None:
            max_start = high - needed + 1
            if max_start < low:
                raise RuntimeError(f"range {low}-{high} is too small for {needed} port mappings")
            start = random.randint(low, max_start)
        elif start < low or start > high:
            raise RuntimeError(f"start port {start} is outside range {low}-{high}")

        self.next_port = start
        self.high = high

    def take(self) -> int:
        port = self.next_port
        while port <= self.high and not is_port_free(port):
            print(f"  skip occupied port {port}")
            port += 1
        if port > self.high:
            raise RuntimeError(f"no free sequential ports available up to {self.high}")
        self.next_port = port + 1
        return port


def parse_mapping(raw: str) -> PortMapping | None:
    if "/" in raw or "-" in raw:
        return None

    parts = raw.split(":")
    if len(parts) == 2:
        host_port, container_port = parts
        bind_ip = None
    elif len(parts) == 3:
        bind_ip, host_port, container_port = parts
    else:
        return None

    if not host_port.isdigit() or not container_port.isdigit():
        return None

    return PortMapping(bind_ip, host_port, container_port)


def has_janus_comment(line: str) -> bool:
    return COMMENT_MAPPING_KEY in line or COMMENT_PORT_KEY in line


def extract_restore_mapping(tail: str, current: PortMapping) -> str | None:
    if not tail.strip().startswith("#"):
        return None

    comment_parts = [part.strip() for part in tail.strip()[1:].split("|")]
    for part in comment_parts:
        if part.startswith(f"{COMMENT_MAPPING_KEY}:"):
            return part.split(":", 1)[1].strip()

    for part in comment_parts:
        if part.startswith(f"{COMMENT_PORT_KEY}:"):
            original_port = part.split(":", 1)[1].strip()
            if not original_port.isdigit():
                return None
            return f"127.0.0.1:{original_port}:{current.container_port}"

    return None


def remove_janus_comment(tail: str) -> str:
    if not tail.strip().startswith("#"):
        return tail

    keep = []
    for part in tail.strip()[1:].split("|"):
        part = part.strip()
        if part.startswith(f"{COMMENT_MAPPING_KEY}:") or part.startswith(f"{COMMENT_PORT_KEY}:"):
            continue
        if part:
            keep.append(part)

    return f" # {' | '.join(keep)}" if keep else ""


def discover_compose_files(root: Path, include_root: bool, exclude_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    for current, dirs, filenames in os.walk(root):
        dirs[:] = [name for name in dirs if name not in exclude_dirs and not name.startswith(".")]
        current_path = Path(current)
        for filename in filenames:
            if filename not in COMPOSE_NAMES:
                continue
            path = current_path / filename
            if not include_root and path.parent == root:
                continue
            files.append(path)
    return sorted(files)


def current_service(
    line: str,
    in_services: bool,
    services_indent: int,
    service_indent: int | None,
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


def find_patchable_mappings(path: Path) -> int:
    return sum(1 for _, _, mapping in iter_port_lines(path) if mapping is not None)


def iter_port_lines(path: Path):
    lines = path.read_text(encoding="utf8").splitlines(keepends=True)
    in_services = False
    services_indent = -1
    service_indent: int | None = None
    service = ""
    in_ports = False
    ports_indent = -1

    for i, line in enumerate(lines):
        body = line[:-1] if line.endswith("\n") else line
        stripped = body.strip()
        indent = len(body) - len(body.lstrip())

        maybe_service, in_services, services_indent, service_indent = current_service(
            body, in_services, services_indent, service_indent
        )
        if maybe_service is not None:
            service = maybe_service
            in_ports = False

        if in_services and stripped == "ports:":
            in_ports = True
            ports_indent = indent
            continue

        if in_ports and stripped and indent <= ports_indent:
            in_ports = False

        if not in_ports or has_janus_comment(body):
            continue

        match = PORT_LINE_RE.match(body)
        if not match:
            continue

        mapping = parse_mapping(match.group("mapping"))
        yield i, service or "<unknown>", mapping


def patch_compose(path: Path, allocator: PortAllocator, dry_run: bool) -> list[Change]:
    lines = path.read_text(encoding="utf8").splitlines(keepends=True)
    changed = False
    changes: list[Change] = []

    in_services = False
    services_indent = -1
    service_indent: int | None = None
    service = ""
    in_ports = False
    ports_indent = -1

    for i, line in enumerate(lines):
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        stripped = body.strip()
        indent = len(body) - len(body.lstrip())

        maybe_service, in_services, services_indent, service_indent = current_service(
            body, in_services, services_indent, service_indent
        )
        if maybe_service is not None:
            service = maybe_service
            in_ports = False

        if in_services and stripped == "ports:":
            in_ports = True
            ports_indent = indent
            continue

        if in_ports and stripped and indent <= ports_indent:
            in_ports = False

        if not in_ports or has_janus_comment(body):
            continue

        match = PORT_LINE_RE.match(body)
        if not match:
            continue

        mapping = parse_mapping(match.group("mapping"))
        if mapping is None:
            print(f"  skip {path}: unsupported port mapping {match.group('mapping')!r}")
            continue

        new_port = allocator.take()
        quote = match.group("quote") or '"'
        tail = match.group("tail").strip()
        comment = f"# {COMMENT_MAPPING_KEY}: {match.group('mapping')}"
        if tail:
            comment = f"{tail} | {COMMENT_MAPPING_KEY}: {match.group('mapping')}"
        replacement = (
            f"{match.group('indent')}- {quote}127.0.0.1:{new_port}:{mapping.container_port}{quote}"
            f" {comment}"
            f"{newline}"
        )
        lines[i] = replacement
        changed = True
        changes.append(Change(path, service or "<unknown>", mapping.host_port, new_port, mapping.container_port))

    if changed and not dry_run:
        path.write_text("".join(lines), encoding="utf8")

    return changes


def restore_compose(path: Path, dry_run: bool) -> list[RestoreChange]:
    lines = path.read_text(encoding="utf8").splitlines(keepends=True)
    changed = False
    changes: list[RestoreChange] = []

    in_services = False
    services_indent = -1
    service_indent: int | None = None
    service = ""
    in_ports = False
    ports_indent = -1

    for i, line in enumerate(lines):
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        stripped = body.strip()
        indent = len(body) - len(body.lstrip())

        maybe_service, in_services, services_indent, service_indent = current_service(
            body, in_services, services_indent, service_indent
        )
        if maybe_service is not None:
            service = maybe_service
            in_ports = False

        if in_services and stripped == "ports:":
            in_ports = True
            ports_indent = indent
            continue

        if in_ports and stripped and indent <= ports_indent:
            in_ports = False

        if not in_ports or not has_janus_comment(body):
            continue

        match = PORT_LINE_RE.match(body)
        if not match:
            continue

        current = parse_mapping(match.group("mapping"))
        if current is None:
            print(f"  skip {path}: unsupported patched mapping {match.group('mapping')!r}")
            continue

        restored_mapping = extract_restore_mapping(match.group("tail"), current)
        if restored_mapping is None:
            print(f"  skip {path}: cannot read restore comment")
            continue

        quote = match.group("quote") or '"'
        tail = remove_janus_comment(match.group("tail"))
        lines[i] = f"{match.group('indent')}- {quote}{restored_mapping}{quote}{tail}{newline}"
        changed = True
        changes.append(
            RestoreChange(
                path,
                service or "<unknown>",
                match.group("mapping"),
                restored_mapping,
            )
        )

    if changed and not dry_run:
        path.write_text("".join(lines), encoding="utf8")

    return changes


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch service docker-compose host ports for Janus.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="service directories or compose files to patch (default: recursive scan below cwd)",
    )
    parser.add_argument("--restore", action="store_true", help="restore mappings saved in janus inline comments")
    parser.add_argument("--include-root", action="store_true", help="also patch compose files in the current directory")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing files")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="directory name to exclude from recursive scans (can be used multiple times)",
    )
    parser.add_argument("--min-port", type=int, default=PORT_MIN, help=f"lowest random start port (default: {PORT_MIN})")
    parser.add_argument("--max-port", type=int, default=PORT_MAX, help=f"highest allowed port (default: {PORT_MAX})")
    parser.add_argument("--start-port", type=int, help="fixed first port; otherwise chosen randomly inside the range")
    return parser.parse_args(argv)


def compose_targets(paths: list[Path], include_root: bool, exclude_dirs: set[str]) -> list[Path]:
    if not paths:
        return discover_compose_files(Path.cwd(), include_root, exclude_dirs)

    targets: list[Path] = []
    for path in paths:
        path = path.expanduser().resolve()
        if path.is_file():
            if path.name not in COMPOSE_NAMES:
                print(f"  skip {path}: not a compose file")
                continue
            targets.append(path)
        elif path.is_dir():
            targets.extend(discover_compose_files(path, include_root=True, exclude_dirs=exclude_dirs))
        else:
            print(f"  skip {path}: path does not exist")
    return sorted(set(targets))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.min_port > args.max_port:
        print("error: --min-port must be <= --max-port", file=sys.stderr)
        return 2

    exclude_dirs = SKIP_DIRS | set(args.exclude_dir)
    targets = compose_targets(args.paths, args.include_root, exclude_dirs)
    if not targets:
        print("No compose files found.")
        return 0

    if args.restore:
        restored: list[RestoreChange] = []
        for target in targets:
            restored.extend(restore_compose(target, args.dry_run))

        if not restored:
            print("No Janus-patched port mappings found.")
            return 0

        print("Planned restores:" if args.dry_run else "Restored mappings:")
        for change in restored:
            rel = change.compose.relative_to(Path.cwd()) if change.compose.is_relative_to(Path.cwd()) else change.compose
            print(
                f"  {rel} [{change.service}]: "
                f"{change.patched_mapping} -> {change.restored_mapping}"
            )
        return 0

    needed_ports = sum(find_patchable_mappings(target) for target in targets)
    try:
        allocator = PortAllocator(args.min_port, args.max_port, needed_ports, args.start_port)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    all_changes: list[Change] = []
    try:
        for target in targets:
            all_changes.extend(patch_compose(target, allocator, args.dry_run))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not all_changes:
        print("No editable host port mappings found.")
        return 0

    print("Planned changes:" if args.dry_run else "Applied changes:")
    for change in all_changes:
        rel = change.compose.relative_to(Path.cwd()) if change.compose.is_relative_to(Path.cwd()) else change.compose
        print(
            f"  {rel} [{change.service}]: checker/original {change.original_port} "
            f"-> service target 127.0.0.1:{change.new_port} "
            f"(container {change.container_port})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
