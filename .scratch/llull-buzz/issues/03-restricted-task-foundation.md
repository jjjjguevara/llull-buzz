# Restricted task and identity foundation — implementation slice 1

Type: task
Status: claimed
Blocked by: none
Driver: ChatGPT remote implementation agent

## Authority and starting point

The owner's 2026-09-21 implementation instruction authorizes code, tests, dependency
resolution and available remote unit/build execution. It supersedes only the historical
bootstrap session's documentation-only restriction. It does not authorize a client fork,
replacement agent harness, shared business database, password directory, live effects,
independent certification, approval or merge.

Starting main: `f3fe82e94e878eba7173aaf326085b77b9c9bc51`.
Branch: `impl/restricted-task-foundation`. No implementation PR existed at inspection.
[PCR2 bootstrap acceptance](https://github.com/jjjjguevara/llull-buzz/pull/1#pullrequestreview-5269336874)
is preserved; PR #1 remains merged and is not reopened. Prior tickets are historical.

## Work items and acceptance bindings

| Item | Scope | Capability / commitment | AC / technical proof / human case |
| --- | --- | --- | --- |
| 03.1 | Rust workspace, pinned executable/auth seams and trusted launch/configuration | BZ-C01; BZ-CMT01/04/05/07/14 | AC-BZ02; BZ-PF02/07; BZ-UAT01 |
| 03.2 | Independent registrations, fixed-key enrollment, epochs and historical attribution | BZ-C02; BZ-CMT03/06/09 | AC-BZ05; BZ-PF01/05; BZ-UAT02 |
| 03.3 | PostgreSQL task generations, reservations, deadlines, restart/child accounting | BZ-C04/05; BZ-CMT02/10/11/12 | AC-BZ02/06; BZ-PF04/05; BZ-UAT01/05 |
| 03.4 | Exact typed tool and publication admission, immutable effect lookup | BZ-C04/06; BZ-CMT06/08/10/12 | AC-BZ02/03/06; BZ-PF01/03/04; BZ-UAT01/04/05 |
| 03.5 | Synthetic regression tests, real-boundary local probes and revision-bound handoff | BZ-CMT13; partial BZ-CMT04/14 | BZ-PF01/02/03/04/05/07; affected human cases remain not-run |

All items are claimed by the driver above before implementation. Bindings identify
obligations, not proof that an entire capability or human case has passed.

## Completion criterion

Publish coherent production code, migrations, test sources and reproducible validation
commands in a draft PR against main; record actual execution separately from unrun tests,
unsupported surfaces and the smallest local resolution of demonstrated limitations.
Keep this task claimed until the local reviewer accepts its implementation scope.

## Comments

2026-09-21 — Remote implementation driver: actual main matches the supplied baseline.
The local sandbox lacks cargo/rustc/PostgreSQL and cannot resolve github.com for git
clone. GitHub connector read/write and historical artifact download work. No Actions
job is dispatched or rerun. Execution-resource probing continues without paid provisioning.
Only public upstream source and neutral synthetic fixtures may enter this public repository.

Controlling records: [tracker](../TRACKER.md), [map](../map.md),
[profile](../../../docs/bootstrap/INITIAL-PROFILE.md),
[contracts](../../../docs/architecture/contracts/PROVIDED-REQUIRED.md),
[assurance](../../../docs/architecture/security/ASSURANCE.md),
[acceptance](../../../docs/acceptance/UAT-CATALOG.md).
