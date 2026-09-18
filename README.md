# llull-buzz

Reusable communication and agent-integration configuration, ports and adapters.

The product connects communication applications and agent runtimes to consumer-owned
business capabilities. It supplies identity bindings, conversation intake, bounded
execution, governed publication and recoverable handoffs. It owns neither a consumer's
business model nor the upstream Buzz application. It is not a chat-client fork.

## Review entry

Read [AGENTS.md](AGENTS.md), the [bootstrap contract](docs/architecture/BOOTSTRAP-CONTRACT.md),
[provided and required interfaces](docs/architecture/contracts/PROVIDED-REQUIRED.md),
[ADR proposals](docs/architecture/decisions/README.md),
[component inventory](docs/architecture/components/REGISTRY.yaml),
[security assurance](docs/architecture/security/ASSURANCE.md) and
[human acceptance](docs/acceptance/UAT-CATALOG.md).

The [Wayfinder map](.scratch/llull-buzz/map.md) indexes decisions; its
[tracker procedure](.scratch/llull-buzz/TRACKER.md) controls claims and resolution.
The [source register](docs/discovery/SOURCE-REGISTER.md) separates owner requirements,
upstream source findings and proposed realization. No implementation is included.

## Boundary

Consumers provide domain commands/queries, scoped authority, task definitions,
publication policy, evidence access and durable result acceptance through neutral
ports. The initial runtime direction reuses buzz-acp and buzz-agent with restricted
adapters. Exact releases, model, language, storage, deployment and tool SDK are
planning choices, not implied dependencies. A logical component need not be a service.

Consumers can use their own frontend alongside Buzz. No universal application shell,
shared database, compulsory domain root, additional password system or synchronized
consumer release is required. API-only integrations need not register every end user
as a direct provider customer. Enrollment and delegated attribution remain explicit.

## Status and license

Documentation-only bootstrap, under review. Proposed ADRs are not accepted by
publication. No runtime, tests, deployment, security attestation or human UAT has run.
License selection is pending; public source visibility is not a license grant.
Third-party components retain their own licenses and admission requirements.
