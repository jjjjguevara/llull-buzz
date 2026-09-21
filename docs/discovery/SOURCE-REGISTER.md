# Source register

## Owner mandate

The 2026-09-18 bootstrap mandate establishes a reusable configuration/ports/adapters product,
separate from upstream Buzz and consumer business state. The 2026-09-20 execution mandate requires
concrete initial realization and revision-bound documentary evidence for PC-BZ-01, not another
architecture-delegation plan. It authorizes documents and proportionate checks, not runtime, live
provider access, deployment, acceptance or merge. The designated reviewer remains the sole reviewer.

The initial `buzz-acp` plus `buzz-agent` foundation is preserved. Rust, SDKs, model, persistence,
identity/release/budget mechanisms and topology are now proposed engineering selections recorded
in the [initial profile](../bootstrap/INITIAL-PROFILE.md) and
[register](../architecture/components/REGISTRY.yaml). They are not universal consumer requirements.
The original project license remains an unanswered owner decision; no rights are inferred.

## Pinned primary source

Upstream source: `block/buzz@01b6174a1cbad249e93f31df97d4b2ed1d0e8638`, Apache-2.0.
Direct source inspection qualifies the following seams; it is not an exhaustive upstream security
audit, installed dependency inventory, binary build or runtime/native-client conformance result.

| Inspected source / identity | Architectural consequence |
| --- | --- |
| [Workspace Cargo](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/Cargo.toml), blob `3e47708e3756857a0229c0bc112131deb0c1c8d0` | Native Rust package version 0.1.0, edition 2021, MSRV 1.88; declares MCP, auth, HTTP and PostgreSQL stack reused by the profile. |
| [ACP](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-acp/src/lib.rs), blob `3ff1dc3989896e1794d4ff275fad4efa0d7f7156` | Use executable/agent-command seam; private orchestration modules are not a public embeddable harness API. |
| [Agent configuration](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/config.rs), blob `5b2f1d659d2c54a6a6c122a8c8c7f7c6ff4ccf2d` | ACP v2, model/base-URL and parameter seams exist; process defaults are not durable cumulative task budgets. |
| [Agent MCP](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/mcp.rs), blob `a848557ae2fca85dd12a323d7e36e184c63a1887` | Signing/SSH/proxy environment and wire declarations require a closed wrapper; local restarts are not durable task ownership. |
| [Agent sessions](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/lib.rs), blob `01ee90a1d98a279833d88adb828a345e8377670b` | Ephemeral sessions and connection cancellation require provider-owned result/attempt recovery. |
| [Native auth](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-auth/src/lib.rs), blob `c21872351f1de818fa3bbe58363efa9eb6bfe48d` | Reuse native NIP-42/NIP-98 verification and atomic replay seam; principal enrollment and exact consumer authority remain additional responsibilities. |
| [Blossom auth](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-media/src/auth.rs), blob `c6fff2be473be22defe0fafe1dc8997db1d1f473` | Native signed method/host/hash and expiry checks are available; they do not by themselves implement artifact release policy. |
| [Actual media routes](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-relay/src/api/media.rs), blob `780532ec5d00189bb1fc3c17570c5a67f6de08bc` | Preserve native upload/GET/HEAD, tenant host and relay membership; add digest-specific release in a private-origin gateway, not a client fork. |
| [Advisory hooks](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/docs/MCP_DRIVEN_HOOKS.md) | Hooks cannot be substituted for enforced authority, release or durable delivery. |
| [Draft NIP-FI](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/docs/nips/NIP-FI.md) | Reference only; no draft federation-client feature is required for initial native enrollment. |
| [Kubernetes launch defaults](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-backend-kubernetes/src/env.rs) | A developer-MCP launcher is not admitted unchanged; Kubernetes is not the selected initial topology. |

## Selected release and license evidence

| Selection | Inspected release/source and purpose | Rights / compatibility boundary |
| --- | --- | --- |
| Rust 1.98.1 | [Official release](https://github.com/rust-lang/rust/releases/tag/1.98.1), release 382035148 | MIT OR Apache-2.0; meets selected MSRVs. Build result is later evidence. |
| rmcp 1.1.0 | [Cargo at commit](https://github.com/modelcontextprotocol/rust-sdk/blob/53c86d5d9d2f323b5f8044cdf2e575404aff6a6b/Cargo.toml); annotated tag `8f743d60012237ec257d87c01a609095f8960484` dereferenced to that commit | Apache-2.0; official typed stdio MCP SDK; no arbitrary tool authority. |
| jsonwebtoken 10.4.0 | [Cargo](https://github.com/Keats/jsonwebtoken/blob/69a8fbf40a83c3d87301e75148e02b2090e4feed/Cargo.toml), blob `6c53c464297b9e5fdae99e429d27c9dcd2c9d8e3` | MIT; ES256 via aws_lc_rs; Rust 1.88 minimum. Library verification is supplemented by strict registered policy. |
| serde_jcs 0.2.0 | [Release Cargo](https://github.com/l1h3r/serde_jcs/blob/v0.2.0/Cargo.toml), blob `e98b5d8a3551c0ead1b3ca9203ca31a98e3e27bd` | MIT OR Apache-2.0; Rust 1.85; RFC 8785 canonical intent encoding, not custom signatures. |
| SQLx 0.9.0 | [Versioned crate documentation](https://docs.rs/crate/sqlx/0.9.0) | MIT OR Apache-2.0; PostgreSQL/Tokio transactions and pools; no consumer ORM. |
| Axum 0.8.8 | [Versioned crate documentation](https://docs.rs/crate/axum/0.8.8) and the pinned Buzz workspace's Tokio/Serde declarations | Axum/Tokio MIT; Serde MIT OR Apache-2.0; HTTP/WebSocket/typed envelope stack. |
| PostgreSQL 16 | [Versioned manual](https://www.postgresql.org/docs/16/index.html) and [license](https://www.postgresql.org/about/licence/) | PostgreSQL License; managed Cloud SQL terms and operator custody remain separate. |
| Docker Engine 29.8.1 | [Official release notes](https://docs.docker.com/engine/release-notes/29/) dated 2026-09-15 | Engine Apache-2.0; Ubuntu/distribution packages retain their individual licenses; observed images follow the build. |
| SeaweedFS 4.47 | [Official release](https://github.com/seaweedfs/seaweedfs/releases/tag/4.47), release 388099073, published 2026-09-14 | Apache-2.0; private S3 media/filer role, not public unrestricted evidence links. |
| Valkey 8.1.10 | [Official release](https://github.com/valkey-io/valkey/releases/tag/8.1.10) | BSD-3-Clause; expendable presence/cache only. |
| Anthropic Sonnet 5 | [Official compatibility/pricing](https://platform.claude.com/docs/en/models/sonnet-5/whats-new-sonnet-5), reviewed 2026-09-20 | Commercial hosted API terms; adaptive thinking; no weight-distribution or zero-retention/residency promise. |

These are deliberate architecture/source selections. Ordinary resolved leaves, platform images,
installed inventories, actual SBOM/license closure and digests are later release evidence. Source
compatibility is not executable conformance. No selected product dependency was installed here.

## Methods and publication boundary

[Wayfinder](https://github.com/mattpocock/skills/blob/959a8e9f1edc3adbe2f7e3054bb6fbefa6696260/skills/engineering/wayfinder/SKILL.md)
and [local methods](METHODS.md) govern source-backed decisions and the existing Markdown tracker,
not new product execution or a review committee. The portable ADR template keeps owner-required
context, alternatives, commitments, consequences, sources, applicability and implementation binding.

No private consumer source, operational data, credentials or internal-only references are published.
No upstream runtime code is copied by these documents. Access to a repository is not permission to
disclose it, and public visibility is not the missing original-project license decision.
