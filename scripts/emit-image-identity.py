#!/usr/bin/env python3
"""Build-time identity only; this is not installed-runtime certification."""
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
paths = ["/opt/llull/upstream/buzz-agent", "/opt/llull/upstream/buzz-acp", "/opt/llull/bin/llull-buzz-mcp-probe"]
record = {"upstream_commit": "01b6174a1cbad249e93f31df97d4b2ed1d0e8638", "executable_sha256": {p: hashlib.sha256((root / p.lstrip('/')).read_bytes()).hexdigest() for p in paths}}
(root / "opt/llull/identities.json").write_text(json.dumps(record, indent=2) + "\n")
