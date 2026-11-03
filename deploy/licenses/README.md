# Selected dependency license texts

The locked provider target includes three registry packages whose published
crate archives do not carry a local license file. These texts come from their
upstream repositories at the matching release source, with exact file hashes
checked by `scripts/distribution-inventory.py`:

| Crate | Upstream source | File SHA-256 |
| --- | --- | --- |
| `bitcoin-io 0.1.101`, `bitcoin_hashes 0.14.101` | [`rust-bitcoin` CC0-1.0 at the two release tags' common commit](https://github.com/rust-bitcoin/rust-bitcoin/blob/a010f1e9fd7752ee5e7ca60a909d32a58e0d3297/LICENSE) | `7179683e8000e6bdc9bbc60d85edf0a4ac8e76f951857f54fcb775d5886f1309` |
| `nostr 0.44.8` | [`nostr` MIT at its packaged source commit](https://github.com/nostrdevkit/nostr/blob/a86ce27c3b4d0dcab186a707336237653a01b114/LICENSE) | `a333d394b9f31b6ca64d08f3048a8a38125c181d68d3d376c4ddf988cffd12d2` |

The unmodified pinned Buzz executables have another 18 selected packages whose
crate archives omit a local license text. The
[inventory script](../../scripts/distribution-inventory.py) maps each locked
name/version to an exact file hash and source URL. Its upstream texts come
from the relevant repository commits for rust-s3, rust-bitcoin, Iroh,
Nostr, OpenTelemetry, the Rust MCP SDK and Tonic. Where the same full text
appears at multiple commits, one vendored file serves those packages.

Two provenance limits remain explicit. `aws-creds 0.39.1` has no packaged VCS
commit, so its MIT text is the `rust-s3` repository license at the locked
`rust-s3 0.37.2` source commit; the script records that source rather than
claiming a missing crate-specific file. `enum-assoc 1.3.0` declares
`MIT OR Apache-2.0` but carries no license text in its archive or at its
packaged repository commit. This bundle selects its Apache-2.0 option and
includes the standard Apache text with the exact file hash. These are
declared-license choices, not evidence of a separate legal review.

All of these are third-party terms, separate from the original-work Apache-2.0
license. A target or dependency update must re-evaluate their applicability.
