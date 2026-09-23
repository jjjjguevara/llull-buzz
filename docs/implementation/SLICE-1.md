# Restricted task and identity foundation — slice 1

Status: implemented source with [revision-bound local validation](LOCAL-VALIDATION.md);
reviewer acceptance and human UAT remain outstanding.
Draft PR: https://github.com/jjjjguevara/llull-buzz/pull/2

Starting main: `f3fe82e94e878eba7173aaf326085b77b9c9bc51`.
Original implementation source snapshot: `d409c11446746e2aa7993cb84d118b63a61050bb`.
The PR records its published head; local validation names the later tested revisions
and corrections individually. The original snapshot itself was not runtime-validated.

Read [local execution](LOCAL-REVIEW.md), [actual evidence](EVIDENCE.md), and
[native task 03](../../.scratch/llull-buzz/issues/03-restricted-task-foundation.md).
Items 03.1–03.5 remain claimed until local review. The existing tracker, capability,
commitment, proof and UAT identities remain controlling; no competing tracker exists.

## Implemented boundaries

| Surface | Production symbols and records | Boundary in this slice |
| --- | --- | --- |
| Strict wire and state | `llull-buzz-wire`: `parse`, `canonical`, `Command`, `TaskManifest`, `TaskState` | Duplicate keys, unsafe numbers, unknown typed fields, oversize data, changed intent, expiry and exhausted reservations fail. Pure functions are not durability evidence. |
| Registration and authentication | `Provider::register`, `set_service_active`, `auth::verify`, PostgreSQL replay guards | Independent operator registration; exact native resource proof plus ES256 invocation. No token-supplied keys, invitation-based authority or new password directory. |
| Intended-key enrollment | `enroll`, `prove_key`, `change_access`, `retire_key` | Consumer-attested authenticated browser principal, fixed key/module/community/transaction, single-use signed native proof, revocation epochs and immutable historical attribution. No installed IdP login UI or complete native identity gateway. |
| Durable task ownership | `start_task`, `worker_control`, `observe_task`, `control_task`, `complete_task` | Root intent and deadline are immutable. Children and restarts share counters. PostgreSQL locks serialize admission. Exact known effect references are required for completion. |
| Typed consumer command | `admit_tool<C>`, `dispatch`, `typed_routes<C,P>`, `HttpConsumer<C>` | Compiled command schema and validation, fresh scope, durable reservation, one immutable owner/intent/digest, bounded dispatch and original-owner lookup. A neutral synthetic consumer tests the positive path. |
| Model-budget records | `reserve_model_budget`, `Pricing` | Checked cumulative token/cost upper-bound reservations using operator pricing. These are not model-dispatch permits. Model transport and independent prompt/token counting are unavailable. |
| Publication preflight | `admit_publication` | Exact text, attachment metadata, audience and release tuple are stored immutably. Returns pending with `delivery: unavailable`. Native audience recheck, signing and delivery are not implemented. |
| Launch configuration | `llull-buzz-launch`, `ImageIdentity`, `AcpGuard`, `checked_command` | Fixed binaries/args/cwd/environment and one closed MCP declaration; hashes and ownership checks. Only synthetic ACP initialization/session/cancel probes. Prompts and consequential MCP tools remain unavailable. |

The provider daemon exposes no operator-registration HTTP endpoint and mounts no arbitrary
consumer tool. A trusted consumer assembly compiles a particular `ConsumerCommand` and
mounts `typed_routes` with an operator-fixed port and worker identity. The included
`HttpConsumer` uses fixed HTTPS endpoints, no inherited proxy or redirects, bounded
responses, native service authentication and forwarded exact invocation evidence.

Production persistence is PostgreSQL, not an in-memory adapter. The migration owns only
provider registration, identity, task, reservation, evidence and effect metadata. It adds
append-only history and immutable-root/attempt constraints. A coarse ordered transaction
lock is intentional for the initial four-root ceiling; no throughput result is claimed.

## Identity and recovery invariants

Consumer registration admits an issuer, verification keys, service principal/key,
community, modules, actions, context domains and compiled tool schemas. It is separate
from consumer-attested human authentication. Email address, channel membership, proof of
an arbitrary native key and model labels never establish consumer business authority.

An enrollment challenge fixes issuer, subject, intended key, community, module and browser
transaction before returning its nonce. It also records registration and recovery epochs.
Proof uses the pinned native signature verifier and an ordinary signed channel message.
A wrong key does not consume the challenge. A new intent cannot consume a used challenge.
Revocation affects the selected binding and its tasks, not an unrelated module. Retiring a
key requires fresh browser authentication; old attribution remains immutable, and access
restore cannot unretire the key.

The native request proof must include its exact raw-body SHA-256, URL and method. An
independent ES256 assertion binds the canonical invocation, resource revision, scope,
policy, registration revision, epochs and short validity window. Database time is used
after lock acquisition and before committing consequential admission. Signed evidence and
its registration snapshot remain in access-restricted PostgreSQL history.

A dispatch attempt is reserved durably first, then marked `effect-unknown` durably before
the external call. Timeout, missing response, process death or lookup miss does not refund
its budget or authorize a new effect identity. An unresolved owner/action/resource slot
blocks a replacement ID, root or resource revision. Recovery calls the original owner's
lookup, never execute. Only an exact completed result or an owner-fenced terminal denial
can settle the attempt. A 404 or absent receipt is not a terminal denial.

Cancellation/revocation fences new work. It does not relabel a completed external effect
as canceled-before-effect. Completed roots remain completed; partially completed roots
require explicit reconciliation/completion. A separately held recovery-epoch floor must
be advanced before admitting work against a restored database. It must not be restored
from the same backup as PostgreSQL.

## Foundation wire additions

The accepted [wire profile](../architecture/contracts/WIRE-PROFILE.md), schemas and
examples remain unchanged. This candidate does not claim complete coverage of those
contracts. The closed Rust DTOs add an explicitly versioned foundation surface:

| Route family | Closed DTO / operation |
| --- | --- |
| `/integration/foundation/v1/key-retirements` | `retire-key`, exact enrollment and expected revision |
| `/integration/foundation/v1/tasks/{id}/claim`, `/renew`, `/complete` | `WorkerRequest`, `CompleteTask`; current generation and exact completed-effect tuple |
| `/integration/foundation/v1/model-reservations` | `ModelReservation`; pricing revision, prompt digest, input/output upper bounds |
| `/integration/foundation/v1/tool-admissions/{compiled-schema}` | `ToolCall<C>` with compiled arguments, root/task/generation, immutable effect owner/intent, resource and schema digest |
| `/integration/foundation/v1/effects/{attempt}/reconcile/{compiled-schema}` | `RecoverEffect`, signed fresh lookup authority against the original attempt |

`auth::Claims` is closed: it requires current module/context, registration revision,
authority-check time and epochs in addition to the exact invocation tuple. Optional
browser authentication, enrollment/delegation and release records have closed typed
shapes. Consumers must use these exact DTOs; historical JSON examples alone do not
exercise these additions. Wire compatibility and extension acceptance remain local
review obligations before any composed integration.

## Pinned upstream seams inspected

Upstream source: `block/buzz@01b6174a1cbad249e93f31df97d4b2ed1d0e8638`.
No upstream files were copied into the provider or modified.

* [Shared native authentication](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-auth/src/lib.rs),
  [NIP-98](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-auth/src/nip98.rs), and
  [replay trait](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-auth/src/nip98_replay.rs):
  resource authentication is reused through public APIs. Upstream permits an absent
  payload tag; this adapter additionally requires it, including SHA-256 of empty GET bytes.
* [ACP crate](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-acp/src/lib.rs),
  [agent entry](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/lib.rs),
  [wire](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/wire.rs), and
  [MCP spawning](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/mcp.rs):
  private orchestration modules are not provider APIs. Use admitted executables and
  supported protocol frames, not a replacement agent loop.
* [Agent configuration](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/config.rs):
  inherited MCP commands/environment are not safe defaults. The probe clears inherited
  values and blocks prompt execution. The pinned config rejects zero MCP restart attempts,
  so the non-consequential probe uses one; durable live-MCP restart mediation is later work.
* [rmcp server example](https://github.com/modelcontextprotocol/rust-sdk/blob/53c86d5d9d2f323b5f8044cdf2e575404aff6a6b/examples/servers/src/common/calculator.rs):
  the SDK-native stdio probe uses `ServerHandler`/`ServerInfo`, not an invented MCP dialect.

Cargo binds selected public Buzz crates by full revision; build scripts check out that
same revision for `buzz-agent` and `buzz-acp`. Original work is Apache-2.0. Build recipes
preserve upstream LICENSE/NOTICE files. The local Cargo inventory records declared
dependency licenses; complete installed OS/upstream distribution license closure remains open.

## Explicitly unavailable and remaining

Full native-protocol/media gateway enforcement, native-client surface coverage, live
model usage and independent token counting, business MCP bridging, publication signing/
delivery and native audience recheck, complete observation streams, context-release
composition, retention compaction preserving tombstones, and cross-product integration
are later slices. Unknown routes return unavailable rather than permissive placeholders.
The launch binary accepts only `probe`; ACP prompt/steer/model-change/tool-execution paths
are rejected. Health responses state `restricted_profile_active: false`.

The launch guard is not an OS sandbox. Unit tests cannot prove process/network isolation,
upstream compatibility or PostgreSQL concurrency. Read the local validation record for
the executed real-boundary probes and remaining gaps. No certification or human UAT
result is implied by this candidate.
