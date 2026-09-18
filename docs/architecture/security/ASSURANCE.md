# Security and data-integrity assurance

Status: proposed controls and proof profiles; no security attestation exists.
Owner: the enforcing component and its implementation work item, not a separate tracker.

## Risk and control inventory

The scenarios below derive from the [source register](../../discovery/SOURCE-REGISTER.md)
and [public interfaces](../contracts/PROVIDED-REQUIRED.md). Source behavior is not a
reported exploit. Preventive, detection and recovery obligations apply together.

| Risk | Scenario / consequence | Control / implementation area | Technical profile |
| --- | --- | --- | --- |
| BZ-RSK01 | Wrong issuer, audience, key, consumer or role reaches another resource. | BZ-CTL01: verified identity/enrollment and current scoped authority; identity/tool adapters. | BZ-PF01 |
| BZ-RSK02 | ACP parameters, mounts, alternate tools or inherited environment disclose secrets or bypass commands. | BZ-CTL02: complete admitted executable/protocol/credential boundary; launch/tool adapters. | BZ-PF02 |
| BZ-RSK03 | Warm history or a changed audience leaks previously restricted data. | BZ-CTL03: access-domain-bound context and explicit release on all output/diagnostic paths; session/publisher. | BZ-PF03 |
| BZ-RSK04 | Advisory hook, forged actor field or auto-allow becomes a business verdict. | BZ-CTL04: backend-verified grant/revision and retained human evidence independent of runtime permission; tool gateway. | BZ-PF01/02 |
| BZ-RSK05 | Duplicate delivery, process loss or cancellation repeats a committed effect or loses accepted work. | BZ-CTL05: durable attempt/inbox/outbox, fencing and existing-result reconciliation; recovery. | BZ-PF04 |
| BZ-RSK06 | Restart/steering renews authority or cumulative cost; offboarding misses active work. | BZ-CTL06: absolute grants, budget reservations and recoverable live revocation; supervisor/identity. | BZ-PF05 |
| BZ-RSK07 | Untrusted content, unsafe attachment or link causes unintended fetch, execution or disclosure. | BZ-CTL07: bounded parsing/fetch and content-as-data; evidence/tool adapters. | BZ-PF06 |
| BZ-RSK08 | Unknown dependency or stale/fabricated report falsely certifies a profile. | BZ-CTL08: exact observed composition, trusted evidence producer and independent applicability verification; release owner. | BZ-PF07 |

## Required proof profiles

Every profile pairs valid permitted completion with negative cases. A denial response
must leave no prohibited database, publication or provider effect. Mocks returning
successful authentication cannot prove the verifier. Use synthetic keys/content.

| Profile | Real boundary and oracle | Required cases |
| --- | --- | --- |
| BZ-PF01 | Actual verifier, enrollment and scoped command boundary; protected resource/effect observation. | Valid subject; wrong issuer/audience/type/key/tenant; expired/revoked grant; stale approval; identity dependency outage. |
| BZ-PF02 | Actual child launch and ACP declarations plus tool dispatch. | Canary signing secret absent from restricted process/logs; extra MCP/skill/shell route denied; admitted tool succeeds; advisory hook timeout cannot authorize. |
| BZ-PF03 | Context and publisher at audience change. | Restricted canary absent from broad reply/preview/error/observer output; permitted summary/link and explicitly approved copy succeed; retire affected warm context. |
| BZ-PF04 | Durable receipt/attempt store and provider boundary. | Duplicate and reordered messages; crash before/after effect; lost ACK; worker replacement; cancel-after-commit reconciles instead of repeats. |
| BZ-PF05 | Concurrent model/tool admission and live access lifecycle. | Budget exhaustion with outstanding calls; restart/steering; offline worker revoked; unrelated enrollment still works. |
| BZ-PF06 | Actual parsing/fetch/attachment adapter with controlled fixtures. | Oversized/malformed data, unauthorized URL/resource and prompt injection; valid uploaded evidence remains usable. |
| BZ-PF07 | Build/profile and evidence verification boundary. | Missing/skipped cases, wrong artifact/config digest, altered report, unadmitted executable/dependency and incompatible contract cannot pass. |

## Attestation and change applicability

A run records claim/profile/control versions, source commit and artifact digest,
observed components, effective configuration/policy, fixture/environment/provider mode,
expected/discovered/executed/skipped cases, result hashes and trusted producer identity.
A separate verifier checks applicability and completeness. Signing authenticates the
record, not the adequacy of its tests. No standard-certification badge is inferred.

TDD demonstrates a new/fixed safeguard fails before the fix; an existing working control
uses a baseline plus a weakened variant or equivalent sensitivity check. Do not invent
historic failed results. Real cryptographic, persistence and process boundaries need
real conformance evidence before the corresponding claim. Safe provider simulations
must state their limits. Live access requires separate authorization.

Scope each change by its affected control/dependency closure. Unaffected evidence needs
an attributable no-impact rationale; affected evidence becomes retest-required. Controls
may share tests without duplicating risk identity. Additional friction is not a control
objective. [Human UAT](../../acceptance/UAT-CATALOG.md) remains separate and mandatory
for task usefulness, continuity and understandable recovery at the actual surfaces.
