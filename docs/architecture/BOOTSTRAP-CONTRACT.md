# Documentation bootstrap contract

Status: proposed detailed contracts under owner-directed reusable product boundary.
Date: 2026-09-18. Decision owner: Josue Guevara.

## Destination and acceptance

Produce a provider contract that independent consumers can implement without importing
one another. The integration reuses conversation/agent primitives and supplies missing
identity, authority, publication and recovery adapters. It is neither business authority
nor a new communication client. The primary interface is neutral meaning; transport and
package topology follow explicit realization decisions.

[Provided/required interfaces](contracts/PROVIDED-REQUIRED.md) own capability semantics.
[ADRs](decisions/README.md) justify the boundaries. [Components](components/REGISTRY.yaml)
identify every prospective unit. [Assurance](security/ASSURANCE.md) binds security and
data-integrity evidence. [Human acceptance](../acceptance/UAT-CATALOG.md) evaluates
useful completion at the actual adopted-client and consumer surfaces.

## Authoritative commitments

Consumer business state, permission meaning and human verdicts remain with the consumer.
Upstream Buzz owns conversations; this integration owns its adapter configuration,
verified bindings, delivery/task attempts and recovery coordinates. Its transport ledger
is not a competing business ledger. A completed runtime turn is not a completed command.

Neutral contracts use consumer, tenant, actor, resource, task, operation, conversation
and evidence references. An actor is not an email label. Enrollment, role, identity
verification and delegation are distinct. Agents never inherit unrestricted authority
from an administrator message or from their runtime's permission callback.

Shared outputs default to authorized summaries and authenticated links; copies require
explicit audience/retention policy. Receiving uploaded evidence remains supported.
Every publication route, including errors and previews, is in the authority surface.

## Admission and no drift

Every selected atomic component needs a stable ID, exact release/source and artifact
pin, license, rationale, alternative, owner, dependency/effect footprint and upgrade
obligations. Enumerate transitive and runtime-installed dependencies in the observed
release manifest, with introduction rationale inherited from the named parent unless
separately customized. Copied code retains file/commit/notices and local-delta pedigree.

Every change maps risks to controls, real enforcement areas, technical proof and scoped
attestation. Positive authorized completion must coexist with denial tests. No code
suite, risk score or signature creates a human verdict. Security evidence does not mean
zero possible vulnerabilities. Technical attestation binds the exact tested profile.

## Planning versus implementation

The [realization planning ticket](../../.scratch/llull-buzz/issues/02-realization-plan.md)
receives actual wire schemas, selected libraries, task budgets, operating profiles and
code/test bindings after contract review. Examples and IDs here are design artifacts,
not executable APIs. No runtime scaffold, package install, deployment or test execution
is included. No production credentials or real provider calls are needed for review.

The bootstrap is ready for review when every capability has provider and consumer
duties, explicit outcomes/recovery, AC/assurance/UAT bindings and a planning owner.
Release acceptance additionally requires actual implementation and applicable evidence.
