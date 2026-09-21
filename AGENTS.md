# Repository operating contract

## Mission and authority

Maintain reusable communication and agent-integration contracts, configuration and
adapters. Read README, the bootstrap contract, public interfaces and current Wayfinder
map before work. Owner decisions live in tracker tickets; ADRs own architectural
commitments; interfaces own public meaning; components own selections; tests and
human UATs have distinct evidence. Do not invent consumer-specific business semantics.

## This bootstrap's scope

Only documentation is authorized by this PR. Do not deploy, run upstream source,
install dependencies, contact mail/fiscal providers, introduce real credentials,
merge, or mark ADRs accepted. Keep upstream repositories read-only. Follow later
explicit authorization for implementation; do not reinterpret a plan as code approval.

Do not copy another product's private notes, data or implementation into this public
repository. Use synthetic fixtures and public source pins. This is not a Buzz fork.
Generic consumer ports must not import a particular consumer, ORM or proprietary schema.
No code path may treat a prompt, channel membership, tool-permission response or actor
label as business authorization. Preserve useful authorized completion.

## Workflow

Use .scratch/llull-buzz/TRACKER.md. Claim before work, preserve concurrent changes,
and record attributed decisions only on explicit approval. New ADRs use the local
portable template without external overlays. Source basis is not conformance evidence.
Keep proposed ceilings and implementation gaps separate from accepted scope.

Before code, bind actual work items, public guarantees, component choices and risk
controls. Use test-driven positive/negative and recovery cases at real boundaries.
Evidence binds exact code/configuration/provider profiles. No agent or CI can supply
a human UAT verdict. No global friction or new approval is justified merely by a
risk label. Every external effect has one declared owner and durable recovery semantics.

## Publication checks

Check changed document links, identifiers, dependency edges, formatting, source pins,
license boundaries and credential patterns. Record only checks actually performed.
No speculative source recipe execution is part of document checks. Keep draft PRs
unmerged until owner review. A published proposal is not an operational service.
