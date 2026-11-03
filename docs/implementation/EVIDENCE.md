# Author evidence — source publication, not runtime acceptance

**Historical remote-author record.** The sections below describe the original source-only
handoff. The later [local validation](LOCAL-VALIDATION.md) records dependency resolution,
reproduced failures, fixes and revision-bound runtime results. Its results supersede the
execution-pending statements below for their named subjects; they do not rewrite this history.

Source subject: `d409c11446746e2aa7993cb84d118b63a61050bb`.
Starting main: `f3fe82e94e878eba7173aaf326085b77b9c9bc51`.
Draft implementation PR: https://github.com/jjjjguevara/llull-buzz/pull/2

The [machine record](evidence/source-inventory.json) records source identities,
commands, exits and interpreter versions. The PR records the final candidate, including
this handoff. It does not relabel these checks as tests of the Rust implementation.

## Checks actually executed

| Check | Result | Meaning |
| --- | --- | --- |
| `bash -n` on all four shell scripts | Exit 0 each | Shell syntax only; no containers or native executables ran. |
| Python `tomllib` on five manifests/toolchain files | Exit 0 | TOML syntax; dependencies were not resolved. |
| Python JSON parsing on accepted schema/examples | Exit 0 | JSON syntax, not implementation behavior. |
| Draft 2020-12 validation of six baseline examples | Exit 0; all expectations matched, one negative | Historical schema fixtures remain consistent; foundation extensions are not covered by these examples. |
| Python AST parse of `emit-image-identity.py` | Exit 0 | Python syntax only. |
| Unchanged `check_provider_docs.py --self-test` | Exit 0; six checks | Checker self-test, not a full candidate documentation or product run. |
| Unchanged `check_profile_package.py --self-test` | Exit 0; ten assertions | Checker self-test, not profile activation. |
| Published Git-tree read-back against local sources | Matching crate, script, deploy and migration tree IDs | Publication identity, not compiled or installed identity. |

The 33 source/build/test files in the machine record were compared against published
Git objects. The crate-tree comparison initially differed because the local build script
had different whitespace and an empty test directory was incorrectly included in local
tree reconstruction. After using the published build-script bytes and excluding empty
Git-untracked directories, all 23 crate files matched. No executable test was inferred
from that comparison. Shell/deploy/migration tree identities also matched remote read-back.

Reproduce the simple source checks without executing product code:

```sh
for f in scripts/*.sh deploy/*.sh; do bash -n "$f" || exit; done
python3 docs/bootstrap/check_provider_docs.py --self-test
python3 docs/bootstrap/check_profile_package.py --self-test
python3 - <<'PY'
import ast, json, tomllib
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
for p in [Path('Cargo.toml'), Path('rust-toolchain.toml'), *Path('crates').glob('*/Cargo.toml')]:
    tomllib.loads(p.read_text())
for p in Path('scripts').glob('*.py'):
    ast.parse(p.read_text())
coverage = json.loads(Path('docs/bootstrap/PROFILE-COVERAGE.json').read_text())
for entry in coverage['schema_examples']:
    schema = json.loads(Path(entry['schema']).read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for row in json.loads(Path(entry['examples']).read_text())['cases']:
        assert validator.is_valid(row[entry.get('instance_field', 'instance')]) == row.get('schema_valid', True), row['id']
print('source syntax and historical schema checks passed; no Rust executed')
PY
```

## Demonstrated execution limits

The remote sandbox has Python 3.13.5, Bash 5.2.37 and native C/C++ build utilities,
but no `cargo`, `rustc`, `rustfmt`, PostgreSQL client/server or Docker executable.
A direct Git clone failed with DNS resolution of github.com (exit 128). An optional
Python Rust/SQL parser installation probe failed with no matching distributions on the
available index (exit 1); no parser result is claimed. GitHub connector read/write and
historical artifact download worked. GitHub is not a source-publication blocker.

Harmless connected-runner discovery found no existing verified worker: Railway reported
zero projects in the available workspace; Replit search returned no worker app; Vercel
sandbox discovery did not expose a verified native command worker. Runtime/toolchain,
remaining usage and controlled teardown were not established together, so no substantial
resource was provisioned. No remote resource was created, upgraded or deleted, and no
provider or connector credential was transferred. No Actions job was dispatched or rerun.

The smallest local resolution is the Rust/native build environment described in
[LOCAL-REVIEW](LOCAL-REVIEW.md), ordinary dependency resolution and a committed lockfile,
followed by the authored disposable PostgreSQL and container probes. No product redesign,
serverless workaround, paid upgrade or new GitHub permission is required.

## Tests authored, not executed

The source contains eight wire/state unit tests, one pricing unit test, three launch
unit tests and one ignored PostgreSQL scenario covering multiple real-boundary cases.
The positive typed command path uses real provider admission and PostgreSQL, with only
the external consumer replaced by a neutral synthetic double. The scenario includes
real signatures, concurrent budget/root admissions, real lease and absolute-expiry waits,
revocation and owner-effect recovery. The shell setup also restarts PostgreSQL and
compares durable records. OCI probes exercise actual processes and network/filesystem
restrictions only when run locally.

There was **no executable Rust failing-test → implementation → passing-test cycle** in
this environment. Tests and production code were authored together under the stated
execution limit; calling that completed red/green TDD would be inaccurate. No Rust
compilation, formatting, Clippy, SQL migration/concurrency, server restart, native
ACP/MCP compatibility, OS/network isolation, live model, delivery, cross-product
integration, installed inventory, security/performance certification or human UAT
has passed by virtue of this PR.

`Cargo.lock` is absent. Full dependency/source/license closure and clean-checkout locked
build reproducibility remain unresolved until local resolution is published and tested.
The OCI tags in the local probe recipe also require recorded immutable image digests.

## Review ownership

Local task 03 remains claimed. AC-BZ02/03/05/06, BZ-PF01/02/03/04/05/07 and affected
BZ-UAT01/02/04/05 identify obligations, not completed whole profiles or human cases.
Do not approve, merge, mark the restricted profile active, or resolve reviewer findings
in the implementation session. Return corrections through this same draft PR with
revision-bound regression evidence.

## Explicit Google free accounting profile — 2026-10-24

Source `46beff7f5b9b79ef83165b3dce4bdb1f3bb7dc69` adds
`google-gemini-3.5-flash-lite-free/v1` for `gemini-3.5-flash-lite`.
This profile requires a zero USD manifest cap and both registered token rates
exactly zero. Real attempts and input/output tokens still consume their finite
budgets. Positive-cost profiles retain their original validation; a zero-cost
charge cannot enter their positive-cost manifests. The provider does not decide
whether a caller currently qualifies for Google's free tier.

The published JSON schema now describes the same separate profile/budget
branches. Its actual SHA256 is
`e1703a76bd086c45d010b0eccfab1a72f41620592822e6c5c78ea4ff3e154e9b`;
rebuilt discovery advertises those bytes. Retained discovery observations keep
their original hashes. No installed provider image is relabeled by this change.

Actual local Rust 1.98.1 checks used `CARGO_BUILD_JOBS=2` and the unchanged lock:
`cargo test --locked --workspace --lib` passed 68 tests, with the existing
native catalog test explicitly ignored because it requires its separate isolated
PostgreSQL roles/migrations. `cargo clippy --locked --workspace --all-targets
-- -D warnings` and formatting passed. Initial Darwin Clippy found six redundant
casts in the retained file-identity implementation; the narrow Darwin branch
preserves all identity fields and meaningful conversions, leaving Linux and the
generic fallback unchanged. Twenty-one actual JSON Schema cases passed,
including Google zero-cost acceptance, paid-cost rejection, legacy zero-cost
rejection and all retained budget bounds.

Those were library/schema-only results. At that checkpoint, Google model calls,
new-profile installed PostgreSQL settlement, provider activation and a productive
downstream task remained unrun; existing qualification and human acceptance
remain separate.

# Google free-profile database execution — 2026-10-24

At `bcb729f00cda1def108100e7f7f0c72b79f4fa50`, the new
`model_dispatch::google_free_postgres_dispatch_settlement_and_unknown_recovery_preserve_zero_cost_caps`
case passed against a new disposable PostgreSQL 16 database (2.36 seconds,
one selected case, 42 filtered). It uses actual migrations, provider signatures
and SQL, with explicitly synthetic gateway counts and usage. No Google count
or generation call was made.

```sh
# TEST_DATABASE_URL points only to the owned disposable PostgreSQL 16 database.
CARGO_BUILD_JOBS=2 cargo test --locked -p llull-buzz-provider --test postgres \
  model_dispatch::google_free_postgres_dispatch_settlement_and_unknown_recovery_preserve_zero_cost_caps \
  -- --ignored --exact --test-threads=1
```

The actual case preserves positive finite attempts/token caps with exactly zero
dollar allocation, refuses paid or mismatched pricing without accounting
changes, and joins reserve/dispatch/settlement through exact signed retries.
Unknown dispatch keeps its maxima through cancellation and late settlement;
neither generation, immutable root record nor stopped authority is reset.
All 31 public tables remained identical across a physical PostgreSQL restart:
one root/member, two model reservations/dispatches, nine commands. The final
181,695-byte dump was retained and its listing checked; restoration is unrun.
Only the new database container and its own loopback forward were retired. The
four previous application containers remained stopped.

The first attempt failed compilation because SQLx 0.9 refused dynamic query
text. The snapshot now uses seven literal SQL statements, without bypassing
the guard. The second attempt's forward ended with its previous compile-failed
parent and the pool timed out before migrations; the third verified an actual
connection and empty database before execution. Both failures remain retained.
Independent source/result/cleanup review accepted this bounded result. It does
not qualify provider HTTP, the selected agent, live model usage, native Akita
composition or broader recovery. Production source remains the existing
`46beff7f` library tree; these two commits change only the test harness/case.
