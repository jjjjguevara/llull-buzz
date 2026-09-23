#!/usr/bin/env python3
"""Bundle the selected Rust target's available license evidence deterministically.

The inventory is evidence of what was found in resolved source packages. A missing
license text is reported, never silently replaced with a guessed SPDX template.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


LICENSE_NAMES = ("license", "licence", "copying", "copyright", "notice")
TREE_PACKAGE = re.compile(r"^([^ ]+) v([^ ]+)")
PINNED_LICENSES = {
    ("bitcoin-io", "0.1.101"): (
        "rust-bitcoin-CC0-1.0.txt",
        "7179683e8000e6bdc9bbc60d85edf0a4ac8e76f951857f54fcb775d5886f1309",
        "https://github.com/rust-bitcoin/rust-bitcoin/blob/a010f1e9fd7752ee5e7ca60a909d32a58e0d3297/LICENSE",
    ),
    ("bitcoin_hashes", "0.14.101"): (
        "rust-bitcoin-CC0-1.0.txt",
        "7179683e8000e6bdc9bbc60d85edf0a4ac8e76f951857f54fcb775d5886f1309",
        "https://github.com/rust-bitcoin/rust-bitcoin/blob/a010f1e9fd7752ee5e7ca60a909d32a58e0d3297/LICENSE",
    ),
    ("nostr", "0.44.8"): (
        "nostr-MIT.txt",
        "a333d394b9f31b6ca64d08f3048a8a38125c181d68d3d376c4ddf988cffd12d2",
        "https://github.com/nostrdevkit/nostr/blob/a86ce27c3b4d0dcab186a707336237653a01b114/LICENSE",
    ),
}


def cargo(*arguments):
    return subprocess.check_output(["cargo", "+1.98.1", *arguments], text=True)


def selected_packages(package, target):
    lines = cargo(
        "tree", "--locked", "--offline", "--target", target, "-p", package,
        "-e", "normal,build", "--prefix", "none", "--format", "{p}",
    ).splitlines()
    selected = set()
    for line in lines:
        match = TREE_PACKAGE.match(line.removesuffix(" (*)"))
        if not match:
            raise ValueError(f"unrecognized Cargo tree package: {line!r}")
        selected.add(match.groups())
    return selected


def license_files(package_root):
    files = []
    for child in package_root.iterdir():
        lower = child.name.lower()
        if child.is_file() and lower.startswith(LICENSE_NAMES):
            files.append(child)
        elif child.is_dir() and lower == "licenses":
            files.extend(path for path in child.rglob("*") if path.is_file())
    return sorted(files)


def workspace_license(package_root, source):
    if source is not None and not source.startswith("git+"):
        return None
    for ancestor in list(package_root.parents)[:3]:
        if (ancestor / "Cargo.lock").is_file() and (ancestor / "LICENSE").is_file():
            return ancestor / "LICENSE"
    return None


def build(package, target, output):
    output.mkdir(parents=True, exist_ok=False)
    metadata = json.loads(cargo("metadata", "--locked", "--offline", "--format-version", "1"))
    candidates = {}
    for entry in metadata["packages"]:
        candidates.setdefault((entry["name"], entry["version"]), []).append(entry)
    records = []
    for name, version in sorted(selected_packages(package, target)):
        matches = candidates.get((name, version), [])
        if len(matches) != 1:
            raise ValueError(f"expected exactly one resolved source for {name} {version}: {len(matches)}")
        entry = matches[0]
        root = Path(entry["manifest_path"]).parent.resolve(strict=True)
        package_dir = output / "packages" / f"{name}-{version}"
        files = {path: path.relative_to(root).as_posix() for path in license_files(root)}
        if entry.get("license_file"):
            source = (root / entry["license_file"]).resolve(strict=True)
            if not source.is_relative_to(root):
                raise ValueError(f"license file escapes package root: {name} {version}")
            files[source] = source.relative_to(root).as_posix()
        if not files and (source := workspace_license(root, entry["source"])):
            files[source] = "WORKSPACE-LICENSE"
        pinned_source = None
        if not files and (pinned := PINNED_LICENSES.get((name, version))):
            filename, expected, pinned_source = pinned
            source = Path(__file__).resolve().parents[1] / "deploy" / "licenses" / filename
            if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise ValueError(f"pinned license text differs for {name} {version}")
            files[source] = "PINNED-UPSTREAM-LICENSE"
        gathered = []
        for source, relative in sorted(files.items(), key=lambda pair: pair[1]):
            destination = package_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            gathered.append({
                "path": relative,
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            })
        records.append({
            "name": name,
            "version": version,
            "source": entry["source"],
            "declared_license": entry.get("license"),
            "license_files": gathered,
            "pinned_license_source": pinned_source,
            "missing_local_license_text": not bool(gathered),
        })
    manifest = {
        "schema": "llull-buzz-distribution-inventory-v1",
        "root_package": package,
        "target": target,
        "dependency_edges": "normal,build",
        "cargo_lock_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "Cargo.lock").read_bytes()
        ).hexdigest(),
        "package_count": len(records),
        "missing_local_license_text_count": sum(item["missing_local_license_text"] for item in records),
        "packages": records,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if manifest["missing_local_license_text_count"] or any(
        not item["declared_license"] for item in records
    ):
        raise ValueError("a selected package lacks a declared license or bundled text")
    print(json.dumps({key: manifest[key] for key in (
        "root_package", "target", "package_count", "missing_local_license_text_count"
    )}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build(args.package, args.target, args.output)
