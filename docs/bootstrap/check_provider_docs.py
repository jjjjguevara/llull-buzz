#!/usr/bin/env python3
"""Author-only documentation checks. Never imports or executes product code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import yaml


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate mapping key: {key}")
        result[key] = value
    return result


class UniqueLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node, deep=False):
    return unique_pairs((loader.construct_object(k, deep=deep),
                         loader.construct_object(v, deep=deep)) for k, v in node.value)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def parse_yaml(text):
    return yaml.load(text, Loader=UniqueLoader)


def unfenced(text):
    return re.sub(r"(?ms)^\s*(`{3,}|~{3,})[^\n]*\n.*?^\s*\1\s*$", "", text)


def anchors(text):
    found, counts = set(), {}
    for title in re.findall(r"(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", unfenced(text)):
        title = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", title)
        slug = re.sub(r"[^\w\- ]", "", title.lower(), flags=re.UNICODE).replace(" ", "-")
        n = counts.get(slug, 0)
        found.add(slug if n == 0 else f"{slug}-{n}")
        counts[slug] = n + 1
    found.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', text, flags=re.I))
    return found


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def self_test():
    assert "a--b" in anchors("# A — B\n")
    assert "duplicate-1" in anchors("# Duplicate\n# Duplicate\n")
    assert "hidden" not in anchors("```md\n# Hidden\n```\n")
    assert parse_yaml("x: [one, two]\n")["x"] == ["one", "two"]
    for parser, text in ((parse_yaml, "x: 1\nx: 2\n"),
                         (lambda t: json.loads(t, object_pairs_hook=unique_pairs), '{"x":1,"x":2}')):
        try:
            parser(text)
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate key was accepted")
    print("self-test: 6 checks passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--subject")
    parser.add_argument("--output", default="docs-check/report.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.base or not args.subject:
        parser.error("--base and --subject are required")
    root = Path(git("rev-parse", "--show-toplevel")).resolve()
    os.chdir(root)
    subject, base = git("rev-parse", args.subject), git("rev-parse", args.base)
    errors, files, external = [], {}, set()
    if git("rev-parse", "HEAD") != subject:
        errors.append("checkout HEAD does not match stated subject")
    if git("status", "--porcelain", "--untracked-files=no"):
        errors.append("tracked checkout differs from subject")
    paths = git("diff", "--name-only", "--diff-filter=ACMR", base, subject).splitlines()
    check = subprocess.run(["git", "diff", "--check", base, subject], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check.returncode:
        errors.append("git diff --check: " + check.stdout + check.stderr)
    texts = {}
    parsed = {}
    for name in paths:
        path = root / name
        data = path.read_bytes()
        files[name] = {"sha256": digest(data), "git_blob": git("hash-object", name),
                       "bytes": len(data)}
        allowed = (name.startswith(("docs/", ".scratch/", ".github/workflows/"))
                   or name in {"README.md", "AGENTS.md", ".gitignore", "LICENSE"})
        if not allowed:
            errors.append(f"out-of-scope changed artifact: {name}")
        if path.suffix.lower() not in {".md", ".yaml", ".yml", ".json", ".py", ".txt"}:
            continue
        try:
            text = data.decode("utf-8")
            texts[name] = text
            if data and not data.endswith(b"\n"):
                errors.append(f"missing final newline: {name}")
            if "\r" in text:
                errors.append(f"non-LF line ending: {name}")
            if re.search(r"(?m)^(<<<<<<< |=======\s*$|>>>>>>> )", text):
                errors.append(f"merge conflict marker: {name}")
            if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{30,}|[?&]token=[A-Za-z0-9]{20,}", text):
                errors.append(f"credential pattern: {name}")
            if path.suffix in {".yaml", ".yml"}:
                parsed[name] = parse_yaml(text)
            elif path.suffix == ".json":
                parsed[name] = json.loads(text, object_pairs_hook=unique_pairs)
            elif path.suffix == ".md" and text.startswith("---\n"):
                front = parse_yaml(text.split("---\n", 2)[1])
                if isinstance(front, dict) and front.get("subtype") == "adr":
                    if front.get("status") != "proposed" or front.get("approval_ref") is not None or front.get("decision_date") is not None:
                        errors.append(f"proposal status/approval changed: {name}")
        except (UnicodeError, ValueError, yaml.YAMLError, IndexError) as exc:
            errors.append(f"parse error {name}: {exc}")
    for name, text in texts.items():
        if not name.endswith(".md"):
            continue
        for raw in re.findall(r"!?\[[^\]\n]*\]\(([^\s]+?)(?:\s+\"[^\"]*\")?\)", unfenced(text)):
            raw = raw.strip("<>")
            uri = urlsplit(raw)
            if uri.scheme or uri.netloc:
                if uri.scheme not in {"https", "http", "mailto"}:
                    errors.append(f"unsupported link scheme {name}: {raw}")
                external.add(raw)
                continue
            target = ((root / name).parent / unquote(uri.path)).resolve() if uri.path else root / name
            if not target.is_relative_to(root):
                errors.append(f"link escapes repository {name}: {raw}")
            elif not target.exists():
                errors.append(f"missing link {name}: {raw}")
            elif uri.fragment and target.suffix == ".md" and unquote(uri.fragment) not in anchors(target.read_text()):
                errors.append(f"missing anchor {name}: {raw}")
    manifest_name = "docs/bootstrap/PROFILE-COVERAGE.json"
    manifest = parsed.get(manifest_name)
    if manifest is None:
        errors.append("missing or invalid PROFILE-COVERAGE.json")
        manifest = {}
    registry = parsed.get(manifest.get("components_path"), {})
    components = registry.get("components", []) if isinstance(registry, dict) else []
    ids = [row.get("id") for row in components]
    if len(ids) != len(set(ids)):
        errors.append("duplicate component IDs")
    required = {"id", "owner", "version", "license", "rationale", "alternative", "footprint", "adaptation"}
    for row in components:
        if required - row.keys():
            errors.append(f"component selection fields missing {row.get('id')}: {sorted(required - row.keys())}")
    corpus = "\n".join(texts.values())
    caps = manifest.get("capabilities", [])
    expected = manifest.get("expected_capabilities", [])
    if sorted(row.get("id", "") for row in caps) != sorted(expected) or not expected:
        errors.append("capability coverage mismatch")
    for row in caps:
        if not row.get("mechanism") or not row.get("technical_profiles") or not row.get("human_cases"):
            errors.append(f"incomplete capability proof mapping: {row.get('id')}")
        for comp in row.get("component_ids", []):
            if comp not in ids:
                errors.append(f"unknown component {comp} in {row.get('id')}")
        for ident in [row.get("id", ""), *row.get("technical_profiles", []), *row.get("human_cases", [])]:
            if ident not in corpus:
                errors.append(f"unknown capability/proof/UAT reference: {ident}")
    for item in manifest.get("required_files", []):
        if not (root / item).is_file():
            errors.append(f"required profile artifact missing: {item}")
    for source in manifest.get("source_bindings", []):
        if source.get("repository") and not re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")):
            errors.append(f"source commit is not immutable: {source}")
    tool = Path(__file__).read_bytes()
    report = {"evidence_type": "author-documentation-checks", "subject_sha": subject,
              "comparison_base_sha": base, "checkout": "complete Git checkout",
              "checker_sha256": digest(tool), "checker_git_blob": git("hash-object", str(Path(__file__))),
              "python": sys.version, "pyyaml": yaml.__version__, "commands": [
                  {"argv": ["git", "diff", "--check", base, subject], "exit": check.returncode,
                   "stdout": check.stdout, "stderr": check.stderr},
                  {"argv": sys.argv, "exit": int(bool(errors))}],
              "files": files, "errors": errors, "documentation_checks_passed": not errors,
              "owner_decisions_pending": manifest.get("owner_decisions_pending", []),
              "bootstrap_complete": not errors and not manifest.get("owner_decisions_pending"),
              "external_links": sorted(external),
              "external_link_check": "URI syntax here; source qualification is separately recorded, not HTTP availability",
              "not_evidence_for": ["product runtime", "security certification", "performance", "human UAT", "reviewer approval"]}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
