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
