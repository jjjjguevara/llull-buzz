# Documentation bootstrap contract

Status: proposed provider contracts and concrete initial realization. Updated 2026-09-20.
Decision owner: Josue Guevara. Finding: PC-BZ-01. Reviewer verdict: not supplied by execution.

## Destination and acceptance

Provide an independently reusable communication/agent integration, not a replacement client,
model loop, business engine or consumer database. The
[provided/required contract](contracts/PROVIDED-REQUIRED.md) owns capability semantics;
[wire definitions](contracts/WIRE-PROFILE.md) own initial encodings;
[initial profile](../bootstrap/INITIAL-PROFILE.md) owns selected realization;
[ADRs](decisions/README.md) justify it; the [register](components/REGISTRY.yaml) qualifies
components. [Assurance](security/ASSURANCE.md) and
[human acceptance](../acceptance/UAT-CATALOG.md) remain distinct evidence types.

## Authority and effect ownership

Consumers own operational business state, permission meaning and required human verdicts.
The provider owns enrolled bindings, task/budget generations, delivery and publication attempts,
release policy enforcement and observation recovery. Native Buzz owns its conversation storage.
The adapter ledger is not a duplicate business ledger. A finished model turn is not effect success.

Principal, enrollment, module scope, represented actor, delegation and approval are separate.
The selected profile authenticates native keys without a second human password directory and
requires current scoped authority. Agents cannot manufacture approval or bypass typed consumer
ports with database, shell or administrative APIs. Consumer schemas and role names stay private.

Every provider publication path is audience-controlled, including ordinary replies, previews,
attachments, observations and diagnostics. Evidence upload and useful authorized completion
remain supported. Revocation stops new access/effects without claiming to erase delivered copies
or roll back committed fiscal/business results. Operational Web Push belongs to its consumer.

## Selection evidence versus implementation evidence

Every deliberate component has a stable ID, purpose/owner, inspected version or source identity,
license, rationale, relevant alternative, dependency/effect footprint and adaptation boundary.
The register is a design inventory, not an installed manifest. Ordinary resolved dependency
leaves, build digests, installed inventories and exhaustive symbol/test bindings are later build
and implementation evidence. This distinction does not permit an unexplained material mechanism.
Copied code, if later authorized, needs file/commit/notices and local-delta pedigree.

Changes map controls to actual enforcing boundaries, technical proof and affected human cases.
Positive authorized completion is required alongside denials. No CI result, score or signature
creates a human verdict or independent certification. Validation binds its exact subject SHA;
a later evidence-storage commit is not automatically the checked subject.

## Execution boundary

The [existing realization ticket](../../.scratch/llull-buzz/issues/02-realization-plan.md) records
this documentary correction, not a new decision gate. Engineering choices are specified now.
Later implementation supplies the selected adapters, schemas, migrations, builds and real tests.
This session permits only documents, definitions/examples, source inspection and proportional
document checks; no product dependencies, runtime execution, operational effects or deployments.

The original project license/distribution decision remains explicitly open. Its absence prevents
claiming complete distribution-ready bootstrap. The designated reviewer alone decides whether
PC-BZ-01 is corrected and whether this draft PR is ready; the execution author does not approve,
resolve findings, certify runtime behavior or merge.
