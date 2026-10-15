# Local validation — 2026-09-21

Original PR #2 candidate: `ab910b153168729f4fc8693db0a6ea7f7e81192b`.
The initial head, comments, reviews and main were inspected before changes. Main was
`f3fe82e94e878eba7173aaf326085b77b9c9bc51`; no comments or reviews were present.
This is execution evidence and remediation, not independent approval or permission to merge.

The [machine record](evidence/local-validation.json) binds command exits, log hashes and
source identities. The [Cargo inventory](evidence/local-cargo-inventory.json) records the
resolved packages and their declared licenses. Full raw logs and native build outputs are
retained under ignored `artifacts/` in the local checkout.

## Revision-bound results

| Check | Actual result | Subject and boundary |
| --- | --- | --- |
| Dependency resolution, locked metadata and dependency tree | Passed; committed Cargo.lock | 337 Cargo packages including three workspace crates; declared package licenses recorded, not a complete distribution notice audit. |
| Rustfmt | Exit 0 | Clean checkout `f469e8e3d0a63ba222713b98a9a0c1dbc4606c3d`. |
| `cargo +1.98.1 test --locked --workspace --lib` | Exit 0; 12 passed | Clean checkout `f469e8e3d0a63ba222713b98a9a0c1dbc4606c3d`; three launch, one pricing and eight wire/state tests. |
| `cargo +1.98.1 build --locked --workspace --all-targets` | Exit 0 | Clean checkout `f469e8e3d0a63ba222713b98a9a0c1dbc4606c3d`; libraries, binaries and integration-test target compile. |
| `cargo +1.98.1 clippy --locked --workspace --all-targets -- -D warnings` | Exit 0 | Clean checkout `f469e8e3d0a63ba222713b98a9a0c1dbc4606c3d`; no lint suppression or relaxed assertion was added. |
| `bash scripts/test-postgres.sh` | Exit 0; ignored real-database scenario explicitly ran and passed | Clean checkout `4dce675ada8a38ebd1017f35412308f69e3c3ef5`; PostgreSQL 16.15, real migrations/transactions/signatures, concurrency, lease/expiry waits and server restart. Only the external consumer is doubled. |
| Operator CLI `--help` | Exit 0 | Clean checkout `4dce675ada8a38ebd1017f35412308f69e3c3ef5`; no service, registration or real credential use. |
| `bash scripts/build-upstream.sh` | Exit 0 | Unmodified `block/buzz@01b6174a1cbad249e93f31df97d4b2ed1d0e8638`, upstream lockfile, Rust 1.98.1, aarch64-apple-darwin release executables. Source/binary hashes and upstream notices retained locally. |
| `bash scripts/test-containment.sh` | Exit 0 | Archived commit `f469e8e3d0a63ba222713b98a9a0c1dbc4606c3d`; executable identity/ownership and actual child environment, ACP2 initialization/session/cancel, SDK-native MCP, pinned ACP CLI, non-root/filesystem/public-network/metadata-network negative probes. |

Provider/wire Rust sources, manifests, root lockfile and migrations are unchanged after
the clean Rust/PostgreSQL checks. The later launcher correction was separately rebuilt
and its unit tests rerun. The clean source checkout reused
the local Cargo dependency/build cache; it was not presented as an empty-cache build.
The container build uses an immutable Git archive, independently of later checkout edits.

The PostgreSQL positive path completed one admitted typed `SetLabel` effect and explicitly
completed its task. Lost-response recovery queried the original external owner and identity
without a second execution. Other assertions covered intended-key proof/replay, independent
module enrollment, immutable attribution, exact signature/body/scope checks, shared budgets,
concurrent final-slot/root admission, expiry/generation fencing, publication substitutions,
revocation and recovery epochs. These are the scenario's assertions, not whole AC/proof or
human-UAT acceptance.

The final PostgreSQL restart snapshot SHA-256 was
`e6e0830a20780c7caf7924cf27558d79bcaf52bef140511b360268645fda66b7` before and after
restart. It covers the script's roots, attempts, publications, enrollments, recovery epoch
and evidence count. This is not a power-loss, arbitrary failover or full backup-restore test.

## Reproduced failures and corrections

1. The initial formatting check failed. Applied Rustfmt to the authored Rust source.
2. Compilation failed with E0599 because `jsonwebtoken` disabled default features but used
   `from_ec_pem`. Enabled its `use_pem` feature on the unchanged selected 10.4.0 version;
   resolved its ordinary PEM/ASN.1 dependency leaves into Cargo.lock.
3. The PostgreSQL fixture failed compilation with E0373. Its concurrent-admission futures
   now own their captured references; all six attempts and the four-winner assertion remain.
4. Strict Clippy identified a test initializer, non-Linux unreachable code, oversized internal
   helper argument lists and a large admission enum. Used conditional compilation, paired
   signed request headers/body, an enrollment validity range and boxed enum payloads. No
   authority, freshness, identity or effect-recovery checks were removed. Callers matching
   `ToolAdmission` now receive boxed permit/attempt payloads; HTTP/wire encodings are unchanged.
5. The Docker build inherited upstream's Rust 1.95.0 selection. Stopped that attempt and made
   both image builds explicitly use 1.98.1. The upstream revision and lockfile remain unchanged.
6. The empty-container cleanup loop failed under Bash 3.2 with nounset. Corrected empty-array
   handling and requested removal of failed build containers. Extended existing Docker context
   exclusions to local tracker and desktop metadata.
7. A clean PostgreSQL retry briefly accepted the image's socket-only initialization server,
   then reported “rejecting connections” during its shutdown. The installed image entrypoint
   confirms this temporary server has `listen_addresses=''`. Readiness now requires TCP;
   the corrected script and real scenario passed together.
8. Container evidence previously read HEAD after a long build. The script now captures the
   starting revision, requires committed review inputs, builds its Git archive and labels
   the image with that revision.
9. The first complete container image exited before returning an ACP response. Running
   the same pinned agent with stderr visible showed the missing `BUZZ_AGENT_PROVIDER`;
   source inspection also identified the required model value. Fixed synthetic provider/model
   values are now present in the closed environment. A second startup attempt exposed the
   missing CA trust store in Debian slim; installing `ca-certificates` allowed client
   initialization. The diagnostic then negotiated ACP initialization/session/cancel and
   an SDK-native MCP handshake, with no prompt or external network. The model identifier
   and API key are deliberately nonfunctional synthetic values; the endpoint remains
   loopback port 9 inside the network-disabled container.

The first Docker PostgreSQL invocation also failed because the host's existing Docker
configuration referenced an unavailable Desktop credential helper. A task-local empty
Docker configuration resolved the public-image pull; no user credential configuration was
changed. An obsolete-context container build was stopped after caching the successful
pinned upstream layer and before building the adapter snapshot. Canceled runs are not passes.

## Environment and identities

Host: macOS 27.0, arm64. Final Rust checks used the official Rustup 1.98.1 toolchain,
compiler commit `48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8. Earlier local
unit execution also passed using Homebrew's build of the same compiler revision; the
final clean-checkout results above used Rustup binaries first in PATH.

The Rustup 1.98.1 toolchain and local Colima, Docker CLI, CMake and GNU coreutils
prerequisites were installed for execution. Developer tools, raw logs and native build
artifacts remain available locally. Both scripts removed their test containers, and
the task-only Colima VM, images and volume data were deleted with `--data --force`.
The original `desktop-linux` Docker context remains selected.

Cargo.lock SHA-256:
`669f646c3190f62d09365c27c42f855384d17e8d9b0c4b58c886fc10a6117c86`.

A task-created Colima profile used four CPUs, 6 GiB memory, a 40 GiB virtual data disk,
no host directory mounts, no SSH-agent forwarding and no change to the active Docker context.
Docker client: 29.8.1. Actual Linux Docker server: 29.5.2, arm64, kernel 6.8.0-117-generic.
These local results do not claim execution on the selected production Engine 29.8.1 or
certification of the complete Ubuntu deployment profile.

Observed base-image identities:

- `rust:1.98.1-bookworm`: `sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e`.
- `debian:bookworm-slim`: `sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`.
- `postgres:16`: `sha256:a3b7f434b2dc57ce85a67e171163eb8ab1a1ebcb39d27484661f26b1dfbe30d6`.

Tested Linux probe image:
`sha256:4e1c7c539db0afb8e36f14fa31125486796df1c15808468e228b635425ef8fce`.
The machine record also retains its three admitted executable hashes. The runtime trust
store layer installed `ca-certificates` `20250419~deb12u1` with OpenSSL `3.0.20-1~deb12u2`;
these installed package observations are not a complete distribution/license audit.

Native macOS executable SHA-256 values:

- `buzz-agent`: `ad0fea79d28e4298f37c4524d9276741a5061e50115401efd596ea6021696bab`.
- `buzz-acp`: `cdd7ed4268dca4e34a9fb42be8b3268b8a65efe420aa470d6d6666d9a00f30e5`.

## Source and reference checks

Shell syntax passed for four scripts; five TOML files parsed; script Python syntax and
implementation-evidence JSON parsed; all six historical schema-example expectations matched.
Both unchanged document-checker self-tests passed (six checks and ten assertions).
Reference checks found consistent mappings among 21 components, eight capabilities,
14 commitments, seven technical profiles and five human cases, including task 03’s compact
references. These checks do not execute or accept the human cases.

## Remaining boundaries

Real HTTPS consumer commit-time authorization/revocation and lost-response integration
remain unexecuted; the database scenario uses the authored synthetic ConsumerPort double.
Full native/client/media coverage, consequential business MCP bridging, live model execution,
publication delivery, cross-product integration, complete installed OS/upstream license
closure, production restore/failover and human UAT remain outside the demonstrated evidence.
No full restricted-profile activation, security/performance certification or merge is claimed.

The existing hosted [provider-docs failure](https://github.com/jjjjguevara/llull-buzz/actions/runs/35648867633)
was read without dispatching or rerunning it. Its bootstrap-only checker reports implementation
files as out of scope and expects PROFILE-COVERAGE.json in the changed-document set. Local
runtime success does not make that hosted check pass. Its workflow/checker was not weakened.

[Task 03](../../.scratch/llull-buzz/issues/03-restricted-task-foundation.md) remains claimed.
The existing AC-BZ02/03/05/06, BZ-PF01/02/03/04/05/07 and BZ-UAT01/02/04/05 bindings retain
separate technical and human ownership. Remediation reproduced failures and reran checks;
it does not retroactively convert the original concurrent code/test authoring into TDD.
