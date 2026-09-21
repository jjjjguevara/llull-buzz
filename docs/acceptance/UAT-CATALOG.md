# Human acceptance catalog

Catalog version: 2. Profile: `bz-restricted-2026-09/v1`. Every case is proposed, version 2 and
not-run. No build, named tester, evidence or human verdict is assigned by this document.

## Positive capability criteria

| AC | Required user outcome | Human cases |
| --- | --- | --- |
| AC-BZ01 | Retain correct conversation/resource context across communication and consumer applications. | BZ-UAT01, BZ-UAT03 |
| AC-BZ02 | Complete a permitted delegated task and distinguish pending human decisions from committed work. | BZ-UAT01, BZ-UAT05 |
| AC-BZ03 | Share useful audience-authorized summaries/links and permitted copies without exposing restricted evidence. | BZ-UAT04 |
| AC-BZ04 | Upload evidence, recover interruption and find the retained reference without duplicate work. | BZ-UAT03 |
| AC-BZ05 | Enroll/change access without another password or unrelated membership loss. | BZ-UAT02 |
| AC-BZ06 | Understand restart, cancellation, unknown delivery and accountable recovery. | BZ-UAT05 |

## Execution contract

An identified human performs and judges the task on the actual adopted native client and consumer
surface. Bind case version, builds, component/configuration/policy/contract revisions, fixture,
device/network/language, tester, acceptance owner and date. Record pass/fail/blocked and immutable
observations. No agent or CI supplies a human verdict. Technical proof is linked separately.

## BZ-UAT01

Version: 2. Roles: requester and authorized approver where consumer policy requires one. Fixture:
a synthetic writable resource, two revisions and an admitted typed task within the selected finite
budgets. Request useful work in a native thread, open the consumer view, change the target, approve
the current exact intent and return to the thread. Complete the authorized write, not merely a
proposal. Confirm the old approval cannot commit the changed intent, the actual result remains
findable and chat acknowledgment is not shown as business completion. AC-BZ01/02. Technical:
BZ-PF01/02/04/05. No blanket approval is added to otherwise permitted routine work.

## BZ-UAT02

Version: 2. Roles: enrolled user and module administrator. Fixture: two independent enrollments,
a browser-fixed intended native key, a wrong-key race, a lost-key recovery and an active task.
Authenticate through the existing consumer identity, prove the intended key in the native client,
remove one enrollment and replace the lost key with fresh proof. Use the unaffected module.
Expected: clear propagation/recovery state, preserved historical actor identity, no additional human
password and no unrelated loss. Explain that old encrypted private-message history needs the old
key/backup; required operational history uses retained governed records. Technical BZ-PF01/05 proves
bounded revocation/crypto; the human judges continuity and clarity, not those primitives. AC-BZ05.

## BZ-UAT03

Version: 2. Role: evidence submitter. Fixture: a synthetic native attachment and interruption between
byte retention and consumer registration. Upload, interrupt/reconnect, follow the original source and
consumer evidence link and return to the thread. Expected: original bytes/digest retained, readiness
states distinguish upload from registration, correct audience access and no duplicate filing. A failed
notification does not erase the retained evidence. AC-BZ01/04. Technical: BZ-PF04/06.

## BZ-UAT04

Version: 2. Roles: shared-channel participant and authorized restricted reviewer. Fixture: mixed-
audience evidence, a default summary/link, one explicitly permitted copy and a later audience change.
Request a summary, open the permitted link, attempt an unauthorized copy and approve a valid exact
copy. Inspect ordinary reply, preview and attachment behavior on the native client. Expected: useful
output and understandable denials without restricted disclosure. Consumer operational Web Push is
judged in its consumer surface, not assumed to be native Buzz push. AC-BZ03. Technical: BZ-PF03/06.

## BZ-UAT05

Version: 2. Role: task requester. Fixture: committed business result with delayed publication, a
runtime restart, an unknown-effect cancellation and an expired observation cursor. Reconnect,
inspect task/result, request cancellation and follow recovery. Expected: one original committed
effect, no renewed task budget, explicit remaining uncertainty and an accountable next action;
no false success from end_turn or rollback because a later message failed. A permitted publication
can complete after recovery using its original identity. AC-BZ02/06. Technical: BZ-PF04/05/07.

## Growth and ownership

Changed surfaces, authority, status, context or recovery semantics version affected cases. Each
consumer maps applicable provider cases to its own domain UATs and supplies its own human result.
Provider tests do not pass consumer UAT, and a headless provider does not need a separate UI merely
to execute these scenarios. Case version 1 is preserved in Git history; its evidence is not inherited
as a pass for this new profile. The designated reviewer alone assesses the proposed correction.
