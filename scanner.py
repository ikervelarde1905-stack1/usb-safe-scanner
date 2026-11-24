#!/usr/bin/env python3
"""Educational, read-only USB file scanner.

This tool never executes discovered files and has no propagation or payload behavior.
"""

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import psutil
except ImportError:
    psutil = None


EICAR_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
MAX_FILE_SIZE = 100 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_hashes(path: Path | None) -> set[str]:
    if path is None:
        return set()
    if not path.exists():
        raise FileNotFoundError(f"Hash list not found: {path}")

    hashes = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip().lower()
        if value and not value.startswith("#"):
            hashes.add(value.split()[0])
    return hashes


def iter_files(paths: Iterable[Path]):
    for root in paths:
        root = root.expanduser()
        if root.is_file():
            yield root
            continue
        if not root.exists():
            print(f"Path not found: {root}", file=sys.stderr)
            continue
        try:
            for path in root.rglob("*"):
                if path.is_file():
                    yield path
        except PermissionError as exc:
            print(f"Cannot traverse {root}: {exc}", file=sys.stderr)


def removable_drives() -> list[Path]:
    if psutil is None:
        raise RuntimeError("Install psutil with: py -m pip install -r requirements.txt")

    drives = []
    for partition in psutil.disk_partitions(all=False):
        options = {option.lower() for option in partition.opts.split(",")}
        if "removable" in options or partition.mountpoint.lower().startswith(("/media/", "/mnt/")):
            drives.append(Path(partition.mountpoint))
    return drives


def quarantine_file(path: Path, quarantine_root: Path) -> Path:
    quarantine_root.mkdir(parents=True, exist_ok=True)
    destination = quarantine_root / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{path.name}"
    shutil.move(str(path), str(destination))
    return destination


def scan(path: Path, denied_hashes: set[str]) -> dict | None:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None

        file_hash = sha256_file(path)
        reason = None
        if file_hash in denied_hashes:
            reason = "hash"

        if reason is None:
            with path.open("rb") as handle:
                data = handle.read(len(EICAR_SIGNATURE) + 1024)
            if EICAR_SIGNATURE in data:
                reason = "eicar-test-signature"

        if reason is None:
            return None

        return {
            "path": str(path),
            "sha256": file_hash,
            "reason": reason,
            "size": path.stat().st_size,
        }
    except (PermissionError, FileNotFoundError, OSError) as exc:
        return {"path": str(path), "error": str(exc)}


def default_quarantine_dir() -> Path:
    local_app_data = __import__("os").environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / ".local" / "share"
    return base / "USB-Safe-Scanner" / "Quarantine"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only educational USB file scanner")
    parser.add_argument("paths", nargs="*", help="Files or directories to scan")
    parser.add_argument("--usb", action="store_true", help="Scan removable USB/drive partitions")
    parser.add_argument("--hashes", type=Path, help="Text file containing denied SHA-256 hashes")
    parser.add_argument("--quarantine", action="store_true", help="Move detections to a local quarantine folder")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        denied_hashes = load_hashes(args.hashes)
    except (OSError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    roots = [Path(value) for value in args.paths]
    if args.usb:
        try:
            roots.extend(removable_drives())
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    if not roots:
        print("No paths supplied. Use --usb or pass a file/directory.", file=sys.stderr)
        return 2

    matches = []
    errors = []
    for file_path in iter_files(roots):
        result = scan(file_path, denied_hashes)
        if result is None:
            continue
        if "error" in result:
            errors.append(result)
            continue

        if args.quarantine:
            try:
                result["quarantined_to"] = str(quarantine_file(file_path, default_quarantine_dir()))
            except OSError as exc:
                result["quarantine_error"] = str(exc)
        matches.append(result)

    report = {
        "safe_scanner": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "matches": matches,
        "errors": errors,
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Scanned paths: {', '.join(str(path) for path in roots)}")
        print(f"Matches: {len(matches)}")
        for match in matches:
            print(f"- {match['path']} [{match['reason']}] {match['sha256']}")
            if "quarantined_to" in match:
                print(f"  quarantined to: {match['quarantined_to']}")
        for error in errors:
            print(f"- Error: {error['path']}: {error['error']}")

    return 1 if matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
