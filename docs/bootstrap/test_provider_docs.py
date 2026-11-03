"""Checkout-level regressions for stage applicability and retained assertions."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = Path(__file__).with_name("check_provider_docs.py")
BOOTSTRAP = "f3fe82e94e878eba7173aaf326085b77b9c9bc51"


class CheckoutChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bz-docs-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        archive = self.root / "source.tar"
        with archive.open("wb") as out:
            subprocess.run(["git", "archive", BOOTSTRAP], cwd=ROOT, stdout=out, check=True)
        with tarfile.open(archive) as source:
            source.extractall(self.root, filter="data")
        archive.unlink()
        shutil.copyfile(CHECKER, self.root / "docs/bootstrap/check_provider_docs.py")
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic checker test")
        self.git("config", "user.email", "checker@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def check(self, stage="implementation"):
        self.git("add", ".")
        self.git("commit", "-qm", "candidate", "--allow-empty")
        subject = self.git("rev-parse", "HEAD")
        result = subprocess.run(
            [sys.executable, "docs/bootstrap/check_provider_docs.py", "--stage", stage,
             "--base", self.base, "--subject", subject], cwd=self.root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        report_path = self.root / "docs-check/report.json"
        self.assertTrue(report_path.exists(), result.stderr)
        report = json.loads(report_path.read_text())
        self.assertEqual(result.returncode, int(bool(report["errors"])))
        return report

    def add_source(self, content="pub fn ready() -> bool { true }\n"):
        path = self.root / "crates/example/src/lib.rs"
        path.parent.mkdir(parents=True)
        path.write_text(content)

    def test_implementation_reads_unchanged_contracts(self):
        self.add_source()
        report = self.check()
        self.assertEqual(report["errors"], [])
        self.assertIn("docs/bootstrap/PROFILE-COVERAGE.json", report["files"])
        self.assertIn("docs/architecture/components/REGISTRY.yaml", report["files"])
        self.assertIn("crates/example/src/lib.rs", report["changed_files"])

    def test_bootstrap_still_rejects_product_source(self):
        self.add_source()
        self.assertIn("out-of-scope changed artifact: crates/example/src/lib.rs",
                      self.check("bootstrap")["errors"])

    def test_implementation_allows_local_legal_text_attributes(self):
        (self.root / ".gitattributes").write_text(
            "deploy/licenses/upstream.txt whitespace=-blank-at-eof\n")
        self.assertEqual(self.check()["errors"], [])

    def test_implementation_still_checks_private_key_patterns(self):
        self.add_source('// ' + '-----BEGIN ' + 'PRIVATE KEY-----\n')
        self.assertIn("credential pattern: crates/example/src/lib.rs", self.check()["errors"])

    def test_unchanged_component_mapping_is_not_omitted(self):
        path = self.root / "docs/architecture/components/REGISTRY.yaml"
        path.write_text(path.read_text().replace("owner: runtime", "owner_removed: runtime", 1))
        self.git("add", ".")
        self.git("commit", "-qm", "invalid registry before comparison base")
        self.base = self.git("rev-parse", "HEAD")
        self.add_source()
        errors = self.check()["errors"]
        self.assertTrue(any("component selection fields missing" in e for e in errors), errors)

    def test_deleted_required_contract_fails(self):
        (self.root / "docs/architecture/contracts/WIRE-PROFILE.md").unlink()
        errors = self.check()["errors"]
        self.assertTrue(any("required profile artifact missing" in e for e in errors), errors)

    def test_false_adr_approval_still_fails(self):
        path = self.root / "docs/architecture/decisions/adr_buzz-002_restricted-execution-and-publication.md"
        path.write_text(path.read_text().replace("status: proposed", "status: accepted", 1))
        self.assertTrue(any("proposal status/approval changed" in e for e in self.check()["errors"]))


if __name__ == "__main__":
    unittest.main()
