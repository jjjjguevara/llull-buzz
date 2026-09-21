# Reusable communication and agent integration

Label: wayfinder:map
Status: open

## Destination

A reusable provider profile with concrete mechanisms, reciprocal contracts, recoverable
useful completion and separate technical/human evidence, submitted to the designated reviewer.

## Notes

The existing [tracker procedure](TRACKER.md) and [methods](../../docs/discovery/METHODS.md)
remain controlling. [Contract review](issues/01-contract-ratification.md) is historical review
work; this execution does not resolve it. The owner authorized documentary realization before
that review finishes. [The existing realization ticket](issues/02-realization-plan.md) is claimed.
No implementation epic, competing tracker or additional ratification session is introduced.

## Decisions so far

The initial `buzz-acp` plus `buzz-agent` foundation is preserved. The
[initial profile](../../docs/bootstrap/INITIAL-PROFILE.md) now selects Rust, upstream source,
SDKs, native clients, enrollment and intended-key proof, ES256 invocation evidence independent
of resource authority, process and credential boundaries, PostgreSQL persistence, finite root
budgets, model admission, publication control, recovery and persistent-container topology.
The [register](../../docs/architecture/components/REGISTRY.yaml) records the choices and
alternatives; [wire definitions](../../docs/architecture/contracts/WIRE-PROFILE.md) bind encodings.
PCR1 accepted the technical scope at `d45c1793b859815127bf9986e084500e2ad9b115`.
The ADR lifecycle remains proposed; no runtime or human conformance is implied.

## Original-work license answered

The owner selected Apache-2.0 for original code/documentation on 2026-09-21.
[The existing realization ticket](issues/02-realization-plan.md) records the answer;
[LICENSING](../../docs/bootstrap/LICENSING.md) and [LICENSE](../../LICENSE) apply it.
No owner license question remains. Execution is submitted for the focused delta review,
not reopened for Wayfinder or delegated back to implementation. Reviewer findings and
PR merge status remain under the designated reviewer's authority.

## Remaining implementation evidence

Implement the selected adapters and migrations; resolve ordinary dependency leaves; produce
installed inventories and image/client digests; bind actual symbols, fault tests and human UAT.
Those are implementation obligations, not unexplained language/storage/security/topology slots.
No test, deployment, independent certification or merge is performed by this document.

## Current implementation frontier — 2026-09-21

[Restricted task and identity foundation](issues/03-restricted-task-foundation.md) is
claimed by the remote implementation driver in
[draft PR #2](https://github.com/jjjjguevara/llull-buzz/pull/2). Items 03.1–03.5 bind
the slice to existing capability, commitment, AC, proof and human-UAT identities.
The bootstrap paragraphs above are historical; merged PR #1 is not reopened.

[Implemented surfaces](../../docs/implementation/SLICE-1.md),
[local execution and review](../../docs/implementation/LOCAL-REVIEW.md), and
[actual evidence](../../docs/implementation/EVIDENCE.md) are the current handoff.
The [local continuation](../../docs/implementation/LOCAL-VALIDATION.md) records the
lockfile, clean Rust checks, real PostgreSQL execution, remediations and exact probe limits.
Task 03 remains claimed for reviewer acceptance. No human case, whole proof profile or
restricted-profile activation is marked passed.
