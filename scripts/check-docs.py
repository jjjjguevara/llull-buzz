#!/usr/bin/env python3
"""Portable complete-checkout documentation stage, shared with manual hosted jobs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "f3fe82e94e878eba7173aaf326085b77b9c9bc51"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs-check")
    args = parser.parse_args()
    base = git("rev-parse", "--verify", args.base + "^{commit}")
    subject = git("rev-parse", "--verify", args.subject + "^{commit}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checker = "docs/bootstrap/check_provider_docs.py"
    supplement = "docs/bootstrap/check_profile_package.py"
    commands = [
        [sys.executable, checker, "--self-test"],
        [sys.executable, supplement, "--self-test"],
        [sys.executable, "-m", "unittest", "discover", "-s", "docs/bootstrap", "-p", "test_provider_docs.py"],
        [sys.executable, checker, "--stage", "implementation", "--base", base,
         "--subject", subject, "--output", str(output / "report.json")],
    ]
    # Preserve and verify the original bootstrap checker through the unchanged
    # supplement. Its full owning-ID/schema/ADR/AC assertions still execute.
    with tempfile.TemporaryDirectory(prefix="bz-docs-legacy-") as scratch:
        legacy = Path(scratch) / "check_provider_docs.py"
        legacy.write_text(git("show", BASELINE + ":" + checker) + "\n")
        tree = {}
        for line in git("ls-tree", "-r", subject).splitlines():
            meta, name = line.split("\t", 1)
            tree[name] = {"sha": meta.split()[2]}
        documents = {name: meta for name, meta in tree.items()
                     if name.startswith(("docs/", ".scratch/", ".github/workflows/"))
                     or name in {"README.md", "AGENTS.md", ".gitignore", "LICENSE"}}
        index = output / "document-index.json"
        index.write_text(json.dumps({
            "repository": "jjjjguevara/llull-buzz", "subject_sha": subject,
            "comparison_base_sha": base, "changed": documents, "known_targets": tree,
            "materialization": "complete Git checkout; all tracked documents, including unchanged contracts",
            "source": "local git ls-tree at the stated subject; not remote publication verification",
        }, indent=2) + "\n")
        commands.append([sys.executable, supplement, "--root", str(ROOT), "--index", str(index),
                         "--legacy", str(legacy), "--output", str(output / "profile-report.json")])
        results = []
        for i, command in enumerate(commands):
            with (output / f"stage-{i + 1}.log").open("w") as log:
                result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            results.append({"argv": command, "exit": result.returncode})
            print(json.dumps(results[-1]), flush=True)
        (output / "commands.json").write_text(json.dumps(results, indent=2) + "\n")
        return int(any(row["exit"] for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
