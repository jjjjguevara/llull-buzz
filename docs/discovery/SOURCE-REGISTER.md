# Source register

## Owner mandate

Owner-directed documentation bootstrap, 2026-09-18: a reusable configuration and
ports/adapters repository for communications and agents; no application fork or
customer-specific assumptions. Consumers keep business policy and data authority.
Public interfaces, containment and test-driven evidence must make reciprocal duties
explicit. buzz-acp plus buzz-agent is the initial runtime direction; no model or
exact deployable release is selected. This is a requirement source, not runtime proof.

## Pinned primary source

Upstream: block/buzz at `01b6174a1cbad249e93f31df97d4b2ed1d0e8638`. Source qualification was performed in the
preceding consumer charting; this bootstrap carries those pins rather than claiming
a new exhaustive upstream audit or current installed version.

| Source | Use and evidence boundary |
| --- | --- |
| [ACP configuration and setup](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-acp/src/lib.rs) | Supplied MCP command and protocol-carried environment; authenticate task binding and isolate signing credentials. |
| [Agent session implementation](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/lib.rs) | Supplied server list and ephemeral sessions; not durable business-task ownership. |
| [Runtime tools and process environment](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/mcp.rs) | Reuse registered tools; qualify every executable, credential and alternate route. |
| [MCP-driven hooks](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/docs/MCP_DRIVEN_HOOKS.md) | Hooks are advisory; they are not authority or guaranteed delivery. |
| [NIP-FI](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/docs/nips/NIP-FI.md) | Identity/key assertion contract; its draft status and local enrollment responsibilities remain explicit. |
| [Kubernetes launch defaults](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-backend-kubernetes/src/env.rs) | Native launcher forces developer MCP; not the admitted operational profile unchanged. |
| [Wayfinder method](https://github.com/mattpocock/skills/blob/959a8e9f1edc3adbe2f7e3054bb6fbefa6696260/skills/engineering/wayfinder/SKILL.md) | Local decision map and source-backed frontier; not runtime execution permission. |

The owner-supplied portable ADR template supplies context, options, costs, quality
scenarios, source basis, review triggers, implementation bindings and architecture
relations. The local adaptation omits the external organizational overlay and private
index links. It is not an inherited standards certification or governance ratification.

No private consumer source, operational data, credentials or copied upstream runtime
code is included. Third-party reuse must retain exact file/commit/license pedigree.
