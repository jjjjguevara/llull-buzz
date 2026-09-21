# llull-buzz

Reusable communication and agent-integration configuration, ports and adapters.

The provider supplies identity bindings, conversation intake, bounded delegated execution,
audience-controlled publication and recoverable handoffs. Consumers retain business state,
policy and their own frontend. Buzz remains a separate application; this is not a client fork.

## Review entry

Read [AGENTS.md](AGENTS.md), the [bootstrap contract](docs/architecture/BOOTSTRAP-CONTRACT.md),
[provided/required interfaces](docs/architecture/contracts/PROVIDED-REQUIRED.md),
[initial profile](docs/bootstrap/INITIAL-PROFILE.md),
[wire definitions](docs/architecture/contracts/WIRE-PROFILE.md),
[ADR proposals](docs/architecture/decisions/README.md),
[component selections](docs/architecture/components/REGISTRY.yaml),
[technical assurance](docs/architecture/security/ASSURANCE.md) and
[human acceptance](docs/acceptance/UAT-CATALOG.md).

The [Wayfinder map](.scratch/llull-buzz/map.md) and existing
[local tracker](.scratch/llull-buzz/TRACKER.md) retain planning history. The
[source register](docs/discovery/SOURCE-REGISTER.md) distinguishes inspected source,
engineering selections and actual validation. No downstream implementation graph is created.

## Initial realization

`bz-restricted-2026-09/v1` selects Rust adapters around pinned `buzz-acp` and `buzz-agent`,
a governed stdio MCP boundary, separate credential-bearing gateways, PostgreSQL task/delivery
persistence and persistent Linux containers. Native clients retain their supported key and
protocol flows. The profile fixes finite cumulative budgets, authority freshness, audience
release, observation and unknown-effect recovery. It permits useful authorized completion.

These are concrete engineering selections for this initial profile, not compulsory language,
identity provider, model, hosting or release choices for every future consumer. There is no
shared consumer database, universal role model, extra employee password directory or synchronized
release requirement. Consumer-owned operational Web Push is not native Buzz push.

## Status and license

Documentation/schema/example consolidation for PC-BZ-01; proposed ADRs remain proposed.
Author document checks are not runtime tests, independent review, security certification,
performance evidence or human UAT. The designated reviewer alone resolves the finding.

The original project license/distribution choice remains unanswered: Apache-2.0 for original
reusable work is recommended; proprietary commercial distribution is the alternative. No grant
is inferred from public visibility or upstream's Apache license. This is an explicit remaining
owner decision and prevents a claim of distribution-ready bootstrap completion. Third-party
components retain their own licenses. No implementation, deployment or merge is authorized here.
