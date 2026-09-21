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
These selections and the revised ADRs are proposed, not reviewer-accepted or implemented.

## Unresolved owner decision

Original llull-buzz distribution/license remains unanswered after inspection and an owner
question. Apache-2.0 is recommended; proprietary commercial terms are the alternative.
Do not infer an answer or call this distribution-ready. Other architecture is not delegated
back to implementation while this decision is pending.

## Remaining implementation evidence

Implement the selected adapters and migrations; resolve ordinary dependency leaves; produce
installed inventories and image/client digests; bind actual symbols, fault tests and human UAT.
Those are implementation obligations, not unexplained language/storage/security/topology slots.
No test, deployment, independent certification or merge is performed by this document.
