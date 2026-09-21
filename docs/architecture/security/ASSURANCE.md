# Security and data-integrity assurance

Revision: 2. Profile: `bz-restricted-2026-09/v1`. Status: proposed controls and proof definitions.
No runtime, security, performance or human acceptance result exists for the new profile.
Enforcing components own controls; this is not a competing task tracker or review committee.

## Risk and control inventory

Source qualification is in the [source register](../../discovery/SOURCE-REGISTER.md).
[The initial profile](../../bootstrap/INITIAL-PROFILE.md) and
[wire definitions](../contracts/WIRE-PROFILE.md) bind actual mechanisms, not advisory promises.

| Risk | Scenario / consequence | Control / enforcing component | Technical profile |
| --- | --- | --- | --- |
| BZ-RSK01 | Wrong issuer, native key, intended subject, consumer or resource reaches another scope. | BZ-CTL01: native resource verification plus ES256 exact-intent evidence, two-sided enrollment and current epochs; identity/tool gateways. | BZ-PF01 |
| BZ-RSK02 | Inherited or ACP-carried secret, arbitrary tool, egress or host mount bypasses admission. | BZ-CTL02: trusted ACP/launch boundary separated from restricted agent; closed declarations and network/process permissions. | BZ-PF02 |
| BZ-RSK03 | Old context or a changed audience leaks restricted content through ordinary native output or media. | BZ-CTL03: domain-bound context retirement and publisher/native gateway release on replies, previews, bytes, observations and diagnostics. | BZ-PF03 |
| BZ-RSK04 | Model-supplied actor/approval, auto-allow or advisory hook becomes business authority. | BZ-CTL04: registered typed tools and verified exact intent/revision/verdicts; consumer rechecks commit authority. | BZ-PF01/02 |
| BZ-RSK05 | Crash, reordered events or a lost ACK repeats an effect or skips accepted work. | BZ-CTL05: PostgreSQL attempts, unique fingerprints, fenced generations, contiguous observations and original-owner recovery. | BZ-PF04 |
| BZ-RSK06 | Child/restart/steering renews budget or stale access survives offboarding. | BZ-CTL06: original absolute expiry, root reservations, finite restarts and bounded authority leases. | BZ-PF05 |
| BZ-RSK07 | Malformed/oversize content, unsafe media URL or prompt injection causes fetch, execution or disclosure. | BZ-CTL07: bounded typed parsing and digest-scoped authenticated media, SSRF controls and content-as-data. | BZ-PF06 |
| BZ-RSK08 | Stale, fabricated or incomplete report/closure falsely certifies a profile. | BZ-CTL08: exact subject, sources, checker, build/configuration and applicability; original license decision remains visible. | BZ-PF07 |

## Required proof profiles

Every profile includes valid permitted completion and denial/fault cases. The oracle observes the
actual resource/effect, not a mocked verifier response. Use synthetic principals, keys and content.
Read-only research and document parsing do not execute any of these proof profiles.

| Profile | Real boundary / oracle | Required initial-profile cases |
| --- | --- | --- |
| BZ-PF01 | NIP-98/native verifier, ES256 policy verifier, enrollment and scoped effect gate. | Valid service and human binding; wrong issuer/audience/typ/algorithm/key/consumer; duplicate claims and unregistered key URLs; intended-key race; challenge reuse/expiry; independent module recovery; changed action/revision/digest/verdict; expired/revoked or unavailable authority; unchanged-intent fresh evidence succeeds. |
| BZ-PF02 | Trusted ACP/wrapper and actual restricted child plus stdio MCP, model proxy and consumer tool boundary. | Canary signing/vendor/SSH keys absent from agent/env/wire/logs; arbitrary server/executable/mount/egress denied; forged task handle denied; approved typed write succeeds; hook timeout or automatic reply cannot authorize publication; supported ACP v2 and model request shape. |
| BZ-PF03 | Actual native gateway, publisher, media paths and context caches at audience/epoch change. | Restricted canary absent from ordinary reply, notification, preview, thumbnail, attachment, error and observer output; permitted summary/link and explicit copy succeed; direct relay/object origin inaccessible; native reads stop within lease; affected warm contexts retire; consumer Web Push remains separately owned. |
| BZ-PF04 | PostgreSQL ledger, relay/consumer effect boundary and observer cursor. | Crash before/after reservation/effect/result/ACK; duplicate/reordered native events; committed lower sequence cannot arrive behind a cursor; concurrent claims fence; exact event-ID retry; unknown effect uses original owner; restore epoch and expired cursor produce explicit recovery, not silent gap or repeated effect. |
| BZ-PF05 | Concurrent reservations, supervisor and live authority lifecycle. | Eight-model/32-tool/input/output/USD admission limits across children/retries/steering; outstanding and unknown reservations counted; original ten-minute expiry; three-restart bound; clock skew cannot renew lease/root; offline worker revoked; unchanged allowed task completes within limits; model accounting uncertainty is retained, not refunded. |
| BZ-PF06 | Actual request/parser/fetch/Blossom/media intake and evidence registration. | Duplicate keys, malformed numbers/UTF-8, 1 MiB control and 25 MiB artifact limits, redirect/private-address/metadata denial, digest mismatch and prompt injection; valid evidence survives interrupted registration; native key/member checks do not substitute for artifact release. |
| BZ-PF07 | Build/profile and evidence producer/applicability boundary. | Wrong source/client/image/config/schema digest; missing/skipped cases; altered report; unadmitted executable; malformed or self-referential validation subject; revoked recovery epoch; affected technical/human case versions cannot inherit a pass. |

## Capability applicability

| Capability | Components / required technical profiles | Human applicability |
| --- | --- | --- |
| BZ-C01 | owned.contract-ports; BZ-PF01/07 | BZ-UAT02 |
| BZ-C02 | owned.identity-binding, upstream.buzz-auth; BZ-PF01/05 | BZ-UAT02 |
| BZ-C03 | owned.delivery-ledger, owned.publisher; BZ-PF01/04/06 | BZ-UAT03 |
| BZ-C04 | owned.launch-protocol, owned.tool-gateway, owned.task-supervisor; BZ-PF01/02/04/05 | BZ-UAT01/05 |
| BZ-C05 | owned.task-supervisor, owned.delivery-ledger; BZ-PF04/05 | BZ-UAT05 |
| BZ-C06 | owned.publisher; BZ-PF01/03/04 | BZ-UAT01/04 |
| BZ-C07 | owned.publisher, service.media; BZ-PF01/06 | BZ-UAT03/04 |
| BZ-C08 | owned.delivery-ledger; BZ-PF01/04/07 | BZ-UAT05 |

## Evidence and change applicability

Record claim/control/profile/case versions; source and artifact digests; actual components and
effective configuration; fixture, environment and provider mode; expected/discovered/executed/
skipped cases; result hashes and attributable producer. Verify applicability independently at
review. A signature identifies a report producer, not test sufficiency or a standards certification.

A new safeguard needs a failing-before/fixed-after technical test; an existing safeguard needs a
baseline plus sensitivity check, not invented historical failures. Real crypto, persistence, process
and native-media boundaries require real tests. Simulations state their limits. Live provider access
requires separate authorization and is not performed by this bootstrap session.

The concrete profile changes applicability of BZ-PF01..07 and versions BZ-UAT01..05 to 2.
No earlier evidence automatically certifies the new composition. [Human UAT](../../acceptance/UAT-CATALOG.md)
remains distinct: actual people judge usefulness, continuity and understandable recovery. The sole
designated PR reviewer assesses the submitted author work; the author does not approve or merge.
