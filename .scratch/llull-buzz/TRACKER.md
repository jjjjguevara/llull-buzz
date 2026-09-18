# Local-Markdown Wayfinder tracker

The canonical map is [map.md](map.md). No native tracker is configured by this
documentation bootstrap. This uses the local-Markdown method in
[the source register](../../docs/discovery/SOURCE-REGISTER.md).

Tickets live in issues/NN-title.md. Use Type: grilling|research|prototype|task,
Status: open|claimed|resolved, and Blocked by: none or existing local ticket numbers.
The frontier consists of open unclaimed tickets with resolved blockers. Claim with a
named driver before work. Create a ticket before any dependency points to it.

Append source-backed findings and attributed owner answers under Comments. Resolve
only on the ticket's stated criterion; a human decision requires the actual owner
answer. Record Answer, rationale, provenance and affected contract links, then index
its title in the map. Publication and code-suite success are not ratification.
The map indexes; it does not duplicate contract or decision history. Preserve refs
and concurrent changes, use non-forced branch updates, and keep PR review state.
