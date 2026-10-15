# Trusted model-gateway accounting

Task [04.3](../../.scratch/llull-buzz/issues/04-provider-completion.md) adds
reservation-to-dispatch accounting to the ordinary provider router. Migration
`0006_model_dispatch.sql` upgrades existing databases without rewriting their
immutable reservation rows. This is a journal for an independently installed
trusted gateway; it performs no vendor request, input counting or ACP launch.
`model_dispatch` health and restricted-profile activation remain false.

The existing consumer invocation verifier authenticates both new operations.
The operator must admit `begin-model-dispatch` and `settle-model-dispatch` in
the applicable registration module's action set. The trusted gateway's fixed
broker signs these commands after independently constructing/counting the
vendor request. Agents must never receive that signer or a generic endpoint
that signs caller-supplied counts, model identity, price, receipt or outcomes.
The provider checks the signed count against its reserved ceiling; the
signature is an accountable gateway assertion, not independent token-counting
evidence. Gateway installation and negative tests remain prerequisites to
using these endpoints for real execution.

## Required proxy call order

1. Construct the complete normalized vendor request in the trusted gateway,
   including model, context, tool schemas and output limit. Independently
   establish the input bound and enforce the selected endpoint/model profile.
   Reserve the cumulative maximum through the existing `reserve-model-budget`
   operation, using SHA-256 of the canonical complete request for
   `prompt_sha256`. The older reservation API remains budget-only; an ACP
   text-content digest by itself is insufficient for this extension.
2. Immediately before the existing vendor send, POST a fresh signed
   `Command` with operation `begin-model-dispatch` to
   `/integration/foundation/v1/model-dispatches`. Its resource is the exact
   task ID and generation; its closed payload is `budget::BeginModelDispatch`:
   `reservation_id`, `task_id`, `expected_generation`, `worker_id`,
   `model_owner`, `request_sha256`, `counted_input_tokens`, and
   `output_upper_bound`. The original reservation fixes the worker, full
   request digest and output ceiling. Registration fixes pricing/model profile.
3. Only `result.dispatch_permitted == true` in the first authenticated response
   permits one send of those exact bytes. Recheck live gateway scope before
   sending and cap the request by `result.dispatch.dispatch_deadline`, which
   cannot exceed the original task, current lease or invocation expiry.
   Persist the gateway's own sent marker before calling its transport.
   Timeout, missing response, crash or repeated begin call must never resend.
   Every successful retry returns `dispatch_permitted: false`, even with a
   fresh command intent. The immutable deadline is not renewed by a retry.
4. When the original gateway has the actual response and complete usage, POST
   a fresh signed `settle-model-dispatch` command to
   `/integration/foundation/v1/model-settlements`. Its resource remains the
   original task/generation; `budget::SettleModelDispatch` contains
   `reservation_id`, `task_id`, `expected_generation`, `model_owner`,
   `request_sha256`, `outcome_sha256`, and `usage`. Usage has `input_tokens`,
   `output_tokens`, and `observed_usd_micros` from the trusted result/accounting
   boundary. Missing or unverifiable usage stays unknown; do not substitute
   zero. The outcome digest names the exact retained gateway response bytes.
   Late settlement uses fresh recovery authority; it does not revive the task
   or authorize publication. Response bytes remain in their governed owner.

The first begin commits `unknown` before returning. A crash on either side of
that response cannot make an existing reservation reusable. Exact settlement
is idempotent, and a changed owner, request or terminal receipt conflicts.
Replaying the original begin retains its original immutable receipt; current
dispatch state and `dispatch_permitted: false` are returned outside that receipt.
All reserved maxima remain spent even after a smaller known result; unknown
accounting is never refunded. Usage above the input/output/monetary reservation
records `incident`, fences the root and blocks that consumer's subsequent model
reservation/dispatch admission. No operator waiver or automatic incident-clearing
endpoint is provided. Other consumers are not stopped.

Unresolved model dispatches prevent root completion and force an expired worker
replacement through recovery. Cancellation/revocation preserves that uncertainty.
A late exact settlement is retained independently without clearing the root's
stop flag or changing its generation. Explicit task completion still requires
exact completed business-effect references; a model receipt is not business
completion, publication delivery or human acceptance.

## Qualification boundary

The existing disposable PostgreSQL entrypoint includes three new cases in
`crates/buzz-provider/tests/cases/model_dispatch.rs`. They cover concurrent
one-time admission, changed owner/scope/count denial, exact terminal history,
unknown completion denial, cancellation/late settlement, and overrun fencing.
Its restart digest now includes model reservations and dispatches.

Run the existing entrypoint with each fully qualified test case using `--case`,
in an admitted service integration environment. These cases are authored,
not runtime-qualified. Current source compiler/lint results are recorded in
[completion evidence](COMPLETION.md). The consumer proxy must still bind these
operations to its actual transport and retained receipts, and the composed
Docker candidate must exercise real ACP/model/MCP/publication paths. No vendor,
installed migration, restart, composed journey or named-human verdict follows
from a Rust source check.
