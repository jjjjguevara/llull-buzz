# Local review and execution — restricted provider PR

Review the draft [PR #2](https://github.com/jjjjguevara/llull-buzz/pull/2), not a chat
archive. [Initial scope](SLICE-1.md), [foundation evidence](EVIDENCE.md),
[local validation](LOCAL-VALIDATION.md) and [completion evidence](COMPLETION.md)
distinguish implemented source from executed checks and remaining boundaries.
Keep the PR draft; return findings
to the same PR with the full candidate SHA. No Actions dispatch, rerun, minutes purchase or check weakening is
part of this procedure.

## 1. Clean checkout and dependency closure

Use a disposable Linux development environment with Git, Rustup, C/C++ build tools,
CMake, Clang, pkg-config, CA certificates, Python 3.11+, Docker and GNU coreutils/timeout.
The Docker probe recipe lists its build packages. The local validation record identifies
the actual toolchains, image digests and tested revisions; it is not a remote CI result.

```sh
git clone https://github.com/jjjjguevara/llull-buzz.git
cd llull-buzz
git fetch origin impl/restricted-task-foundation
git switch --track origin/impl/restricted-task-foundation
git rev-parse HEAD
git diff --check
rustup toolchain install 1.98.1 --profile minimal --component rustfmt --component clippy
rustc +1.98.1 -vV
cargo +1.98.1 -V
```

**Cargo.lock is committed.** The initial remote handoff could not resolve dependencies;
the local continuation resolved and inventoried them. Reuse the reviewed lockfile:

```sh
cargo +1.98.1 metadata --locked --format-version 1 > /tmp/llull-buzz-metadata.json
cargo +1.98.1 tree --locked > /tmp/llull-buzz-dependencies.txt
cargo +1.98.1 fmt --all -- --check
```

If formatting differs, run `cargo +1.98.1 fmt --all`, review the change and publish it
in a normal non-forced commit. Do not regenerate Cargo.lock during validation, change
selected source pins or loosen tests to obtain a green build. Report unavailable package
versions or API incompatibilities as revision-bound implementation findings. After an
authorized dependency correction changes the lockfile, a fresh checkout must pass the
locked sequence below without rewriting it. Record the full lockfile SHA-256, compiler
target, dependency versions, upstream source SHA and actual image digests in local evidence.

```sh
cargo +1.98.1 test --locked --workspace --lib
cargo +1.98.1 build --locked --workspace --all-targets
cargo +1.98.1 clippy --locked --workspace --all-targets -- -D warnings
bash scripts/build-upstream.sh
```

The upstream script builds the selected native executables with the upstream lockfile,
records source/binary hashes under ignored `artifacts/`, preserves upstream license
notices and deletes only its own temporary checkout. No real provider credentials are
needed. Compilation, formatting and dependency-leaf corrections are expected to return
through this PR with regression coverage, not by declaring an unexecuted build successful.

## 2. Early executable / ACP / MCP / isolation probe

Run the first boundary probe before attempting consumer integration:

```sh
bash scripts/test-containment.sh
```

This builds `deploy/Dockerfile.probe` and uses a task-created container with no network,
read-only root, dropped capabilities, no-new-privileges, finite process/memory/CPU limits,
and a small noexec scratch tmpfs. The launch probe verifies binary identity and ownership,
checks the actual child environment, negotiates ACP v2 initialization and a session with
the SDK-native MCP probe, cancels it, and checks the pinned `buzz-acp --help` executable.
It does not run a prompt, business tool, native relay or model call. Kernel probes attempt
forbidden filesystem writes and public/metadata network connections.

The script requires a clean tracked checkout and committed lockfile, archives its starting
Git revision, and builds that immutable context. It records the candidate and image ID and
removes only its temporary context, uniquely named image and containers. Do not mount
home directories, host sockets, provider keys, a credential
store or the control-plane database into the agent container. Resolve base-image tags to
immutable digests and retain those identities in the review evidence. Run failures against
the exact image: a shell syntax check is not a substitute for execution. `buzz-acp --help`
and direct-agent ACP are early seam probes, not a complete host/native-client matrix.

## 3. PostgreSQL, budgets, restart and revocation

```sh
bash scripts/test-postgres.sh
```

The script requires a committed lockfile. It discovers the nine non-live
ignored scenarios and gives each a uniquely named disposable PostgreSQL 16
container, synthetic database/user/password and loopback-only random port.
After each real-database case it restarts that server and compares durable
root, effect, publication, binding and observation snapshots. It removes only
its own container. The two live-relay cases use
`scripts/local-stack.py check-publication-live` with the separate private stack.
Never substitute a live database or existing user resource.

The test `postgres_foundation_contracts` uses actual SQLx transactions, migrations,
Nostr signatures and ES256 evidence. Only the external consumer is doubled. It covers:

| Native obligation | Authored regression / expected behavior |
| --- | --- |
| 03.2 / AC-BZ05 / BZ-PF01,05 | Wrong intended key, challenge replay and repeated authentication fail. Independent module enrollment survives another module's revocation. Attribution history cannot be deleted. |
| 03.4 / AC-BZ02,06 / BZ-PF01,04 | Authorized typed command completes once; changed intent, forged scope, bad signature/purpose/raw-body proof and missing payload hash fail. Exact known effects permit explicit task completion. |
| 03.3 / AC-BZ02,06 / BZ-PF04,05 | Children share root model/tool budgets; concurrent final-slot admissions have one winner. Real lease expiry advances generation without replenishment; stale generations and absolute expiry fail. Six concurrent roots admit only four. |
| 03.4 / AC-BZ03,06 / BZ-PF03,04 | Lost response retains an unknown effect. New IDs/roots cannot repeat it. Lookup recovers the original result without another execute. Publication content/audience/release substitutions fail; separate live-relay tests cover signed delivery and reconciliation. |
| 03.2–03.4 / BZ-PF05 | Revocation fences a previously minted dispatch permit. An externally advanced recovery epoch rejects the old restored admission namespace. |

For one manual case in an already created **disposable** test environment, set
`TEST_DATABASE_URL` to a PostgreSQL 16 database named exactly `bz_foundation_test`, then:

```sh
cargo +1.98.1 test --locked -p llull-buzz-provider --test postgres zz_postgres_foundation_contracts -- --ignored --exact --test-threads=1
```

The suite intentionally waits for real lease/expiry boundaries; do not replace these with
an in-memory repository or suppress ignored-test execution. Default `cargo test` alone
skips this suite. A server restart snapshot does not certify power-loss recovery, full
backup restoration or arbitrary PostgreSQL failover.

## 4. Trusted service assembly and publication review

Operator commands are separate from the HTTP router and must run outside the agent
container. Use only disposable credentials and a disposable database while reviewing:

```sh
export DATABASE_URL='postgresql://DISPOSABLE_USER:DISPOSABLE_PASSWORD@127.0.0.1:DISPOSABLE_PORT/bz_foundation_test'
export PUBLIC_ORIGIN='https://provider.synthetic.invalid'
export EXTERNAL_RECOVERY_EPOCH=1
cargo +1.98.1 run --locked -p llull-buzz-provider -- migrate
cargo +1.98.1 run --locked -p llull-buzz-provider -- --help
```

Construct a `Registration` from the public Rust DTO using newly generated ES256 public
verification material and a disposable native service public key. The test `Rig` is a
complete neutral fixture generator; no checked-in private key or real consumer is used.
Register with `register FILE` (and expected digest for updates). Keep private consumer
signing and native service credentials in the trusted test gateway, never in agent env.
Terminate HTTPS at the registered public origin without changing canonical request paths.
Do not derive signature targets from client Host/Forwarded values. Apply private-network
and least-privilege database roles; production schema ownership must not be granted to
untrusted consumers. Evidence rows and backups require appropriate access controls and
encryption. The schema's append-only triggers are not protection against a database admin.

A real consumer assembly must implement a closed `ConsumerCommand`, mount its typed
routes and use a fixed trusted `ConsumerPort`/`HttpConsumer`. Test with a synthetic HTTPS
owner that independently validates fresh invocation, resource revision and exact intent
**at its effect commit**. Simulate a committed effect with a dropped response; verify one
owner effect and original-ID lookup. An owner lookup miss must remain unknown because the
original request may still be in flight. Test service revocation between admission and
effect commit. This network/owner-commit integration is not replaced by the included mock.

For publication, submit a fresh signed release for exact text and destination.
The provider now persists the original signed event before dispatch, rechecks
the current audience and task scope, and reconciles a lost response through
original-event lookup. Alter text/hash, audience revision, destination or
attachments without the corresponding exact release and require rejection.
The real PostgreSQL scenario covers ledger behavior; the separate live-relay
cases cover accepted delivery and lost-response recovery. Native subscriber and
media gateway mediation remain unqualified.

For restore review, advance the trusted deployment's recovery-epoch floor outside the
PostgreSQL backup before using a restored database. Old claims must fail. The operator
`advance-recovery-epoch EXPECTED` fences old roots; it does not turn unknown owner effects
into safe retries. Hold the floor independently of the restored state.

## 5. Evidence and return loop

Record each command, exit, full candidate SHA, lockfile digest, compiler/target, source
pin, image digest and test boundary. Keep synthetic tokens and private keys out of logs.
Attach failed commands and minimal repros to this PR; remediation returns through the
same branch with regression tests and revision-bound replies. Do not approve, merge or
resolve the reviewer's findings as the implementation agent.

Use [completion evidence](COMPLETION.md) for current command results and exact
tested revisions. HTTPS consumer commit fencing, signed text publication,
selected-engine builds, nine isolated PostgreSQL cases and a protected synthetic
native-key restore have local passes at their recorded sources. Model dispatch,
consequential MCP bridging, native/media gateway coverage, production backup
escrow and complete distribution applicability remain open. BZ-UAT01..05 are
named human judgments, not completed acceptance. No full restricted-profile
activation or certification is claimed.

## 6. Protected synthetic-key backup review

Use the operator-only Python environment from
[`scripts/requirements-operator.txt`](../../scripts/requirements-operator.txt).
Keep a separately managed raw 32-byte backup key in an ignored owner-only
file outside `artifacts/completion/backups`; provide only its path to
`--backup-key-file`. Never print, commit or mount the key into an agent.
`backup-storage` now encrypts native signing identities, quiesces only its
owned provider/relay/SeaweedFS services, and records DB/volume digests.
`restore-storage` authenticates the encrypted identity archive before changing
target storage. Test a wrong-key denial first, then restore into a newly owned
stack and compare retained event/media/publication/table identities. Restore
the provider image with the original service identity and run `check-provider`
and `probe-provider-origin` before removing only the restore namespace.
The exact passing command inputs, image IDs and limits are in
[completion evidence](COMPLETION.md). Earlier plaintext synthetic-key backups
require the explicit `--allow-legacy-plaintext-keys` flag; they are historical
evidence, not the new backup format. Full production key escrow and whole-archive
protection remain to be implemented.
