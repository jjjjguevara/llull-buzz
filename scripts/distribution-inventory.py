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
    ("aws-creds", "0.39.1"): (
        "upstream/rust-s3-MIT.txt",
        "fd7003282055eb957f6ba61fc0d2c1d299506b323332eb3bccc531edc7d53833",
        "https://github.com/durch/rust-s3/blob/b584ce7d53825705332c13136769546166622ad1/LICENSE.md",
    ),
    ("aws-region", "0.28.1"): (
        "upstream/rust-s3-MIT.txt",
        "fd7003282055eb957f6ba61fc0d2c1d299506b323332eb3bccc531edc7d53833",
        "https://github.com/durch/rust-s3/blob/aad5f6e24a98e4a415b3022e308d636e7d81b8c9/LICENSE.md",
    ),
    ("bitcoin-io", "0.1.4"): (
        "rust-bitcoin-CC0-1.0.txt",
        "7179683e8000e6bdc9bbc60d85edf0a4ac8e76f951857f54fcb775d5886f1309",
        "https://github.com/rust-bitcoin/rust-bitcoin/blob/29a07abb2f1cf91ba7aa4820216ea091ee8b91e8/LICENSE",
    ),
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
    ("bitcoin_hashes", "0.14.1"): (
        "rust-bitcoin-CC0-1.0.txt",
        "7179683e8000e6bdc9bbc60d85edf0a4ac8e76f951857f54fcb775d5886f1309",
        "https://github.com/rust-bitcoin/rust-bitcoin/blob/76690fc2a3b2f092ec2151e51adc4d91b91fc760/LICENSE",
    ),
    ("enum-assoc", "1.3.0"): (
        "upstream/enum-assoc-Apache-2.0.txt",
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        "https://www.apache.org/licenses/LICENSE-2.0",
    ),
    ("iroh-base", "1.0.3"): (
        "upstream/iroh-Apache-2.0.txt",
        "903131e2786f073a942fbf8fae122d9e576e4dad758c6da7f9f2ba58fd8611ab",
        "https://github.com/n0-computer/iroh/blob/e5c710a29fbd06bdce35fd23ad94d04a62acf15a/LICENSE-APACHE",
    ),
    ("iroh-dns", "1.0.3"): (
        "upstream/iroh-Apache-2.0.txt",
        "903131e2786f073a942fbf8fae122d9e576e4dad758c6da7f9f2ba58fd8611ab",
        "https://github.com/n0-computer/iroh/blob/e5c710a29fbd06bdce35fd23ad94d04a62acf15a/LICENSE-APACHE",
    ),
    ("iroh-metrics-derive", "1.0.1"): (
        "upstream/iroh-metrics-Apache-2.0.txt",
        "7953ad8cebf4e01199521a5faa221ef59bec5cee0a9856b179590613a8560cbc",
        "https://github.com/n0-computer/iroh-metrics/blob/a9afb7cd49bb3804fffefec61647993851f9b8c8/LICENSE-APACHE",
    ),
    ("n0-error-macros", "1.0.0"): (
        "upstream/iroh-metrics-Apache-2.0.txt",
        "7953ad8cebf4e01199521a5faa221ef59bec5cee0a9856b179590613a8560cbc",
        "https://github.com/n0-computer/n0-error/blob/56019f01cd4c838edccd9f9b074953a45d87b6ef/LICENSE-APACHE",
    ),
    ("netwatch", "0.19.1"): (
        "upstream/net-tools-Apache-2.0.txt",
        "7986218ec4ea89de3511a843ae27fea2584a525036c220ff7b26589179f07888",
        "https://github.com/n0-computer/net-tools/blob/051ab8761006d7f2155e34a49f6bb881b582d5ab/LICENSE-APACHE",
    ),
    ("nostr", "0.44.7"): (
        "nostr-MIT.txt",
        "a333d394b9f31b6ca64d08f3048a8a38125c181d68d3d376c4ddf988cffd12d2",
        "https://github.com/nostrdevkit/nostr/blob/94dac28e9a718d853170308aeb551b1ebf89a0d0/LICENSE",
    ),
    ("nostr", "0.44.8"): (
        "nostr-MIT.txt",
        "a333d394b9f31b6ca64d08f3048a8a38125c181d68d3d376c4ddf988cffd12d2",
        "https://github.com/nostrdevkit/nostr/blob/a86ce27c3b4d0dcab186a707336237653a01b114/LICENSE",
    ),
    ("opentelemetry", "0.32.0"): (
        "upstream/opentelemetry-Apache-2.0.txt",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "https://github.com/open-telemetry/opentelemetry-rust/blob/ec289cb3c6f8260951699c51df968560943c1451/LICENSE",
    ),
    ("opentelemetry-otlp", "0.32.0"): (
        "upstream/opentelemetry-Apache-2.0.txt",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "https://github.com/open-telemetry/opentelemetry-rust/blob/ec289cb3c6f8260951699c51df968560943c1451/LICENSE",
    ),
    ("opentelemetry-proto", "0.32.0"): (
        "upstream/opentelemetry-Apache-2.0.txt",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "https://github.com/open-telemetry/opentelemetry-rust/blob/ec289cb3c6f8260951699c51df968560943c1451/LICENSE",
    ),
    ("opentelemetry_sdk", "0.32.1"): (
        "upstream/opentelemetry-Apache-2.0.txt",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "https://github.com/open-telemetry/opentelemetry-rust/blob/284a37d93b3856e1975c2807ba3af1421ebd9b52/LICENSE",
    ),
    ("rmcp", "1.8.0"): (
        "upstream/rmcp-Apache-2.0.txt",
        "0382b0057770ca05e9c350a50aa3b1c1fea84da0bc81d723bf00b9aa841be58a",
        "https://github.com/modelcontextprotocol/rust-sdk/blob/25220361d5540715294c501c289d79de4bec2bfc/LICENSE",
    ),
    ("rust-s3", "0.37.2"): (
        "upstream/rust-s3-MIT.txt",
        "fd7003282055eb957f6ba61fc0d2c1d299506b323332eb3bccc531edc7d53833",
        "https://github.com/durch/rust-s3/blob/b584ce7d53825705332c13136769546166622ad1/LICENSE.md",
    ),
    ("tonic-prost", "0.14.6"): (
        "upstream/tonic-MIT.txt",
        "e24a56698aa6feaf3a02272b3624f9dc255d982970c5ed97ac4525a95056a5b3",
        "https://github.com/hyperium/tonic/blob/6cb6056b5a748bc5a29bd48f4602dbc4e552bb7d/LICENSE",
    ),
}


def cargo(workspace, *arguments):
    return subprocess.check_output(
        ["cargo", "+1.98.1", *arguments], cwd=workspace, text=True
    )


def selected_packages(packages, target, workspace, features):
    roots = [argument for package in packages for argument in ("-p", package)]
    feature_args = ["--features", ",".join(features)] if features else []
    lines = cargo(
        workspace, "tree", "--locked", "--offline", "--target", target, *roots,
        *feature_args,
        "-e", "normal,build", "--prefix", "none", "--format", "{p}",
    ).splitlines()
    selected = set()
    for line in lines:
        if not line:
            continue
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


def build(package, target, output, workspace, features):
    output.mkdir(parents=True, exist_ok=False)
    packages = package.split(",")
    if not packages or any(not item for item in packages):
        raise ValueError("at least one nonempty package is required")
    feature_args = ["--features", ",".join(features)] if features else []
    metadata = json.loads(cargo(workspace, "metadata", "--locked", "--offline", "--format-version", "1", *feature_args))
    candidates = {}
    for entry in metadata["packages"]:
        candidates.setdefault((entry["name"], entry["version"]), []).append(entry)
    records = []
    for name, version in sorted(selected_packages(packages, target, workspace, features)):
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
        "features": features,
        "dependency_edges": "normal,build",
        "cargo_lock_sha256": hashlib.sha256(
            (workspace / "Cargo.lock").read_bytes()
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
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--feature", action="append", default=[])
    args = parser.parse_args()
    build(args.package, args.target, args.output, args.workspace.resolve(strict=True), args.feature)
