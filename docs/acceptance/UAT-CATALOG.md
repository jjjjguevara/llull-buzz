# Human acceptance catalog

Version: 1. Status: proposed definitions. Execution: not-run for every case.
No build, named tester, evidence or human verdict is assigned by this document.

## Positive capability criteria

| AC | Required user outcome | Human cases |
| --- | --- | --- |
| AC-BZ01 | Retain the correct conversation/resource context across communication and consumer applications. | BZ-UAT01, BZ-UAT03 |
| AC-BZ02 | Complete a permitted delegated task and distinguish a pending human decision from committed work. | BZ-UAT01, BZ-UAT05 |
| AC-BZ03 | Share useful audience-authorized summaries/links and permitted copies without exposing restricted evidence. | BZ-UAT04 |
| AC-BZ04 | Upload evidence, recover interruption and find the correct retained reference without duplicate work. | BZ-UAT03 |
| AC-BZ05 | Enroll/change access without another password or unrelated membership loss. | BZ-UAT02 |
| AC-BZ06 | Understand restart, cancellation, unknown delivery and recovery outcomes. | BZ-UAT05 |

## Execution contract

An identified human in the relevant role performs and judges the task on a specific
adopted client and consumer surface. Bind case version, application/provider builds,
component/configuration/policy/contract revisions, fixture, device/network/language,
named tester/acceptance owner and date. Verdicts are pass, fail or blocked, not an
agent/CI assertion. Preserve immutable run records; changes can require a new run.
Technical authentication/fault/containment profiles are linked separately.

## BZ-UAT01

Version: 1. Roles: requester and authorized approver. Fixture: synthetic request with
two revisions and one required approval. Steps: request permitted preparation in a
thread; open the consumer view; edit the target revision; approve the current intent;
return to the original thread. Expected: context retained, stale intent not committed,
actual business result distinct from chat acknowledgement. AC-BZ01/02. Technical:
BZ-PF01/02/04. No new blanket approval is introduced for otherwise permitted tasks.

## BZ-UAT02

Version: 1. Roles: enrolled user and module administrator. Fixture: two independent
module memberships, synthetic identity/key and an active task. Steps: sign in, use an
assigned module, remove one membership, retry the old link/task and use the unaffected
module. Expected: clear access state, correct propagation/recovery, retained history,
no unrelated access loss. AC-BZ05. Technical: BZ-PF01/05; the human does not certify crypto.

## BZ-UAT03

Version: 1. Role: evidence submitter. Fixture: synthetic attachment and interrupted
upload/consumer-registration stages. Steps: upload, interrupt, reconnect, follow the
resource link and return to the thread. Expected: bytes/registration readiness are
understandable, source retained and no duplicate business filing. AC-BZ01/04.
Technical: BZ-PF04/06.

## BZ-UAT04

Version: 1. Roles: shared-channel participant and authorized restricted reviewer.
Fixture: mixed-audience evidence with default links and one explicitly allowed copy.
Steps: ask for a summary, open an authorized link, try an unauthorized copy and permit
a policy-compliant copy. Expected: useful summary, intelligible access outcome and no
restricted disclosure; evidence intake still works. AC-BZ03. Technical: BZ-PF03/06.

## BZ-UAT05

Version: 1. Role: task requester. Fixture: completed domain command with delayed
publication, runtime restart, and another task canceled while an effect is uncertain.
Steps: observe progress, reconnect, request cancellation and inspect recovery. Expected:
completed work remains, uncertainty has an accountable next action, no repeated effect,
and no false success from end_turn. AC-BZ02/06. Technical: BZ-PF04/05/07.

## Growth and ownership

New surfaces/roles/permissions or changed operation/recovery semantics version affected
cases. Each consumer maps applicable scenarios to its domain UATs and records its own
human result. Provider test success does not pass consumer UAT. A headless provider is
not required to build a standalone UI merely to run these scenarios.
