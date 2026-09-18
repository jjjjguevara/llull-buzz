# Reusable communication and agent integration

Label: wayfinder:map
Status: open

## Destination

Ratify consumer-neutral contracts and an implementable adapter boundary for useful,
scoped communication and agent work, with explicit recovery and technical/human evidence.

## Notes

The owner requests a reusable configuration/ports/adapters product, not a client fork.
The initial runtime direction is buzz-acp plus buzz-agent with restricted integration.
[Contract review](issues/01-contract-ratification.md) is the first decision frontier.
Use [tracker operations](TRACKER.md) and [methods](../../docs/discovery/METHODS.md).

## Decisions so far

No detailed provider ADR is yet ratified. The owner-directed bootstrap constraints
are recorded in [contract review](issues/01-contract-ratification.md).

## Not yet specified

Exact identity/key custody; adapter implementation language; selected tool SDK and
contract schemas; model/data-processing profile; client builds; persistence, budgets,
operating topology and dependency closure. These do not weaken public guarantees.

## Out of scope

A consumer's business model, a fork of the communication app, a universal plugin host,
production operations and implementation in this documentation-only pass.
