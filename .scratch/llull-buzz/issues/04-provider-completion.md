# Complete and qualify the restricted communication provider

Type: task
Status: claimed
Blocked by: none
Driver: Codex local implementation and test operator, 2026-09-21
Parent: [Provider map](../map.md)

## Authority and completion criterion

Owner instruction: complete the entire accepted restricted provider, with actual
agent execution, governed business tools, publication, native/media surfaces,
recovery, distribution closure and test deployment. Continue draft PR #2 using
non-forced commits. Foundation-only and stop-before-integration restrictions are
superseded. No new Wayfinder session, client fork or replacement agent loop.

Complete production paths and applicable automated qualification for BZ-C01..08;
bind exact sources, dependencies, images, clients, commands and results. Supply a
working isolated test deployment and automatable human journeys. Actual human UAT
and independent review remain attributable judgments. A partial suite cannot resolve
this ticket or accept a whole proof profile. Preserve task 03's reviewer-owned state.

## Claimed work and existing contracts

| Item | Implementation / selected component | Capability / commitment | Controls, technical and human applicability |
| --- | --- | --- | --- |
| 04.1 | Discovery, enrollment, current authority and context retirement; contract ports / identity binding | BZ-C01/02; BZ-CMT01/02/03/06/09/14 | BZ-CTL01/06; BZ-PF01/05/07; AC-BZ05; BZ-UAT02 |
| 04.2 | Native intake, attachments, retained evidence, ordered observations and durable ACK; delivery ledger / publisher | BZ-C03/07/08; BZ-CMT02/08/10/12 | BZ-CTL03/05/07; BZ-PF01/03/04/06/07; AC-BZ01/04/06; BZ-UAT03/05 |
| 04.3 | Actual buzz-acp / buzz-agent, admitted model proxy and typed MCP bridge; launch protocol / task supervisor / tool gateway | BZ-C04/05; BZ-CMT05/06/07/09/10/11/12 | BZ-CTL01/02/04/05/06; BZ-PF01/02/04/05; AC-BZ02/06; BZ-UAT01/05 |
| 04.4 | Durable signed publication, audience changes, native and Blossom gateways; publisher / media | BZ-C06/07; BZ-CMT06/08/09/10/12 | BZ-CTL01/03/05/07; BZ-PF01/03/04/06; AC-BZ03/04; BZ-UAT03/04 |
| 04.5 | Real HTTPS consumer commit-time authority and original-owner recovery; tool gateway | BZ-C04/05; BZ-CMT06/10/11/12 | BZ-CTL01/04/05/06; BZ-PF01/02/04/05; AC-BZ02/06; BZ-UAT01/05 |
| 04.6 | Restore, upgrades, operations, performance, dependency/OS notices, portable delivery and isolated deployment | BZ-C01..08; BZ-CMT04/10/11/12/13/14 | BZ-CTL02/05/06/08; BZ-PF02/04/05/07; AC-BZ01..06; BZ-UAT01..05 setup only |

Contracts: [provided/required](../../../docs/architecture/contracts/PROVIDED-REQUIRED.md),
[wire](../../../docs/architecture/contracts/WIRE-PROFILE.md),
[profile](../../../docs/bootstrap/INITIAL-PROFILE.md),
[components](../../../docs/architecture/components/REGISTRY.yaml),
[assurance](../../../docs/architecture/security/ASSURANCE.md),
[human cases](../../../docs/acceptance/UAT-CATALOG.md).
These bindings claim work, not completed capability or acceptance.

## Comments

2026-09-21 — Starting inspection: local and remote PR head
`667f8118b2386e5a4dd98e90885b266a4432bfc9`; main
`f3fe82e94e878eba7173aaf326085b77b9c9bc51`. Clean local checkout, PR open/draft,
no comments or reviews. PCR2 remains accepted at bootstrap scope. Historical local
validation and hosted failures remain intact.

2026-09-21 — Owner answer to test-provider question: “Use codex/chatgpt pro oauth”.
This directs the model-provider amendment away from the initial Anthropic selection;
compatibility, token/accounting limits and isolated credential handling require actual
qualification. Local `codex-cli 0.155.1` reports “Logged in using ChatGPT”. No token
value was printed or copied into the repository. Pinned buzz-agent supports the
OpenAI Responses base-URL seam; that source fact alone does not prove OAuth service
compatibility. No paid API fallback or new spend is inferred.

2026-09-21 — Owner answer to deployment/private-coordination question: “continue
independently until that lane completes”. Independent implementation and isolated
local qualification proceed. Composed counterpart evidence and the external target
remain pending; interim synthetic counterparts are not final integrated evidence.

2026-09-21 — Item 04.6: six checkout regression cases first failed against the old
checker (unsupported implementation-stage argument), then passed after stage-aware
applicability and complete-subject contract loading. Both original helper self-tests
also passed. The portable command retains the unchanged supplement and verifies its
preceding checker against the immutable bootstrap object. Full current-subject results
are recorded separately after committing a clean subject. Hosted history is preserved;
automatic PR runs are replaced by explicit manual dispatch while Actions is exhausted.

2026-09-21 — Items 04.1/04.2: authenticated discovery and a transactionally ordered,
module/context-scoped observation journal are implemented in the working tree.
Three new real PostgreSQL/signature scenarios passed after missing-method red tests
and a corrected invalid-query test helper. See [continuation details](../../../docs/implementation/COMPLETION.md).
No whole capability/proof profile is accepted; snapshot recovery, native mediation
and background effect coverage remain in progress. Item 04.5 is adding an actual
HTTPS/independent-database synthetic owner, not a `ConsumerPort` double.

The first OAuth compatibility request returned HTTP 400 for `max_output_tokens`.
The exact backend output-limit behavior is a qualification gap, not a reason to
silently drop cumulative accounting or declare a live model pass.

2026-09-22 — Clean-source continuation results: discovery/observations at
`d6e9288cff7613c9e793367e9ee804bfa666eea2`, HTTPS owner commit/recovery at
`2fb25e84d6b6e8580cf796a62a93212e501eda21`, and retained native intake at
`8b9056f96f262b53e1415fb07bd42a2e28fe220c` passed their targeted PostgreSQL scenarios.
Strict Clippy passed before the latter clean-source reruns; the full portable document
stage passed at `8b9056f…`. That source is pushed to the same draft PR, whose description
now reflects full completion scope and continuing work. No new hosted Actions run
appeared after publication; the historical failures remain visible.

Item 04.4 now has a passing working-tree publication ledger scenario: frozen signed
identity, original-owner lookup after lost response, changed-audience denial and
preserved canceled-root scope. Its native transport remains an explicit fixture pending
the real relay/client run. Item 04.6 has an isolated Ubuntu 24.04.4 arm64 VM running
the selected Docker 29.8.1; pinned native executables are compiling there. Full gateway,
agent/model/tool, media, restore and distribution qualification remains claimed work,
not an accepted capability or proof profile.

2026-09-22 — All seven PostgreSQL scenarios and twelve library tests passed at
`953767bbda59018ebe4b9f9aad19126937a6e3a4`. Item 04.2 adds frozen, scoped snapshot
recovery with final-page durable acknowledgment, plus explicit duplicate-receipt
conflicts. Its working-tree PostgreSQL scenario passed after a missing-implementation
red and fixture correction. Current scope and precise remaining boundaries remain
in [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Item 04.6: the selected Docker 29.8.1 task VM built the unmodified
upstream `buzz-agent`, `buzz-acp`, `buzz-relay`, `buzz` and `buzz-admin` at the
pinned revision. The build log SHA-256 is
`410b1dc2d0bf7e2202a8ba2628691f5a5e78c905a70a72867fb6d4736fba4282`.
The isolated PostgreSQL 16.15, SeaweedFS 4.47/PostgreSQL filer and Valkey 8.1.10
storage stack passed real authenticated S3 write/read/range and role/access
denials, with evidence recorded in continuation details. These qualify the
storage component, not yet the native relay/agent/client or media gateway.

2026-09-22 — Items 04.4/04.6: the pinned upstream relay and real `buzz` CLI
passed private-channel create, signed-message recovery, relay enrollment
denial, channel-member grant/revocation and owned relay restart with exact
event/media recovery on the selected Docker Engine. A real Blossom upload
then exposed a concrete disclosure counterexample: the original signed
private-channel message carried the PNG `imeta` digest, yet a relay-enrolled
identity outside that channel retrieved the exact PNG by hash.
`probe-media` records the failed artifact gate and exits nonzero. The origin
has no host-published port; this is not permission to activate the profile.
Provider media mediation and bypass-proof native routing under item 04.4
remain required. See [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Item 04.6: a corrected task-only backup/restart and a fresh
isolated PostgreSQL/Seaweed/relay-data restore passed. The first attempts
exposed a relay-versus-Seaweed startup race; the corrected path waits for an
authenticated retained S3 object before starting the relay. The new namespace
recovered the original signed event, exact media digest and revoked-channel
denial after rebuilding its disposable Valkey cache. The restored provider DB
contained no populated command/effect records, and protected key backup is
still open; this does not resolve item 04.6 or BZ-PF05. Evidence and exact
source/target identities are in [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Items 04.2/04.4/04.6: a BuildKit image from committed provider
source `eae913c6e4c9a9d4cfcf25bbd2c59be648aba438` booted with the real
PostgreSQL database and pinned relay in the owned private stack. The initial
`wss://host` switch changed upstream tenant authority from `host:3000` and
created a new empty community. Commit `8ec269206ebbb86d776b406c8c52a364addf4649`
retains the host and port while changing only the signing scheme. The production
`HttpNativeOrigin` then recovered the original signed event and current
two-member audience; a clean-source WSS-posture backup/restart also passed.
The image used an exact-ID cached dependency builder, so a clean independent
distribution build remains open. No external TLS terminator, live publication
command, media gateway, model/tool execution, populated-effect restore or
human UAT is qualified by these results. The status stays claimed.

2026-09-22 — Items 04.4/04.6: a compiled Linux arm64 test executed a signed
synthetic `publish` command through the running provider, real PostgreSQL and
unmodified pinned relay. It recovered the exact signed event from the relay;
a fresh signed retry reused the original native identity with one delivery
row. The manually invoked case exited 0 at test source `c3d6bd0ef19a02ce2a4fc1fb9c974b4a7e95a42e`;
its private log SHA-256 is
`83de1724375ec0499293234679d3b09e21ba9ed3ba4c35d7a009c8ea8be7b5c3`.
An initial scripted cold build hit root-versus-UID key permissions, and a
revised run retained a completed test executable but timed out compiling the
provider CLI. The credential-separated runner is being qualified separately;
these failures are not erased by the direct positive case.

The selected stack then backed up and freshly restored two completed
publication rows into a separately owned PostgreSQL/Seaweed/relay namespace.
Signed-byte digests, native event IDs and completed states matched, both
native events were present, and the original media digest and revoked-channel
denial recovered. Backup and restore exited 0; manifest SHA-256 is
`b5c486d487f4d17293f293705bc339238972047fcae7800c7fd6eab53802fcda`.
The restore-only namespaces were removed by exact owner labels; the source
test deployment remains running. Protected-key restoration and full native
gateway coverage remain open.

Item 04.3: `codex exec` with ChatGPT login completed one synthetic
`gpt-5.6-luna` turn (`OK`, 17,960 input/five output tokens, no tools); log
SHA-256 is `49f6438698d2a939af60cd53499b7942da1d84d8d308604781c142aeee56bb69`.
This does not cure the observed 400 for `max_output_tokens`, prove a bounded
Buzz model proxy or execute the ACP agent loop. Pinned `buzz` CLI source also
refuses to sign media GET for a non-relay origin; the current publisher emits
provider-origin attachment URLs. Item 04.4 requires a relay-origin governed
media gateway and actual artifact release before attachment UAT. No item or
whole proof profile is accepted.

Item 04.6: the locked Linux arm64 provider target has 222 distinct package
versions, not 290 once repeated Cargo tree entries are collapsed. A new build
inventory copies each selected package's license/notice texts, pinned workspace
root texts, and three exact upstream texts absent from published crate archives.
The host run exited 0 with no undeclared or missing texts; its manifest SHA-256
is `96c56e0a775a350602c911ff89ad1f31ea41b39320edc8e652b4bc1166520a52`.
The revised Dockerfile records OS package versions and copyright-file hashes
and requires every installed package's copyright file. This source has not yet
produced a revised image, so distribution closure stays open.
