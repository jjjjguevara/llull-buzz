# Proposed architecture decisions

Use [the portable template](ADR-TEMPLATE.md). No decision below is accepted.

| ADR | Responsibility | Status |
| --- | --- | --- |
| [001](adr_buzz-001_reusable-provider-boundary.md) | Consumer-neutral capabilities, wire profile and component selections | proposed |
| [002](adr_buzz-002_restricted-execution-and-publication.md) | Native enrollment, invocation evidence, contained useful execution and all-path publication | proposed |
| [003](adr_buzz-003_recovery-and-assurance.md) | PostgreSQL ownership, finite budgets, observation/recovery and separate evidence types | proposed |

The [initial profile](../../bootstrap/INITIAL-PROFILE.md) and
[wire definitions](../contracts/WIRE-PROFILE.md) realize these proposals for
`bz-restricted-2026-09/v1`. They replace the former unexplained realization slots without
making the selected vendor, language, model or hosting arrangement universal. Stable ADR,
BZ-CMT, BZ capability, proof and UAT identities remain intact. Source pins are not tested builds.

Publication does not accept an ADR, lower a capability, authorize implementation or create a
new reviewer. The original project license remains an unanswered owner decision. Acceptance
references/dates remain null until the designated review and owner authority actually supply them.
