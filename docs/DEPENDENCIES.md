# Third-Party Dependencies and Licenses

Generated 2026-09-18 from `Cargo.lock` as committed on branch `main`.

Regenerate with, from the repository root:

```bash
# cargo install cargo-license
cargo license --json --all-features   # whole workspace
cargo license --all-features          # whole-workspace license distribution with counts

# on-chain program only
cargo license --json --all-features --manifest-path programs/proof-of-reserves/Cargo.toml
```

The plain-text distribution labels crates without a `license` field `N/A` and counts the 2 workspace-internal crates among them; the tables below call them `NOT DECLARED` and exclude the internal crates.

`--all-features` is required: `anchor build` enables the `idl-build` feature, which pulls in 4 crates (`cargo_toml`, `serde_spanned`, `toml`, `toml_write`, all `Apache-2.0 OR MIT`) that a default-feature run omits. With it, the reported graph matches `Cargo.lock` exactly. No workspace crate declares dev-dependencies, so `--avoid-dev-deps` changes nothing here.

## Summary

| Scope | Packages | Notes |
| --- | --- | --- |
| Whole workspace (transitive graph) | 765 | 22 declared directly by the 2 workspace crates |
| `programs/proof-of-reserves` (transitive graph) | 406 | 13 declared directly; a subset of the 765 above |
| npm | 0 | `Anchor.toml` names `yarn` and `migrations/deploy.ts` exists, but there is no `package.json` or lockfile, so no npm dependency is tracked |

`Cargo.lock` holds 767 entries: the 2 workspace-internal crates and the 765 third-party packages counted above. The workspace has 2 members: `programs/proof-of-reserves` (the on-chain program) and `tests` (`proof-of-reserves-tests`, the integration test harness, which is never deployed). Every package outside the program's 406 is reached only through `tests`, mainly via `solana-program-test`, `solana-client` and `anchor-client`.

The program graph is not filtered by target: it includes build scripts, proc-macros, the `idl-build` path and crates for every platform (Windows, WASM, UEFI), so the deployed SBF binary links a strict subset of those 406 packages.

Every declared license in the graph is permissive or weak file-level copyleft (MPL-2.0); the 3 `NOT DECLARED` crates are MIT by their repository `LICENSE` (see Items needing attention). The permissive identifiers that appear, alone or inside `OR`/`AND` expressions, are: MIT, MIT-0, Apache-2.0 (including `WITH LLVM-exception`), BSD-1-Clause, BSD-2-Clause, BSD-3-Clause, 0BSD, ISC, Unicode-3.0, Unlicense, Zlib, BSL-1.0, CC0-1.0 and CDLA-Permissive-2.0. Apart from MPL-2.0, the only copyleft identifier is `LGPL-2.1-or-later`, and it appears solely as one of three options on `r-efi` (see Items needing attention). No GPL, LGPL-only, AGPL, SSPL, or BUSL package is present. All MPL-2.0 crates are reached only through `tests`; none is in the program graph.

### Whole-workspace license distribution

Counts cover the 765 third-party packages; the 2 workspace-internal crates are not included.

| License (SPDX, normalized by cargo-license) | Crates |
| --- | --- |
| Apache-2.0 OR MIT | 358 |
| Apache-2.0 | 226 |
| MIT | 90 |
| Unicode-3.0 | 19 |
| Apache-2.0 OR MIT OR Zlib | 9 |
| BSD-3-Clause | 7 |
| MIT OR Unlicense | 7 |
| Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT | 6 |
| Apache-2.0 OR ISC OR MIT | 6 |
| Apache-2.0 OR BSD-2-Clause OR MIT | 4 |
| ISC | 3 |
| MPL-2.0 | 3 |
| MPL-2.0+ | 3 |
| NOT DECLARED | 3 |
| Apache-2.0 OR BSD-3-Clause OR MIT | 2 |
| BSD-2-Clause | 2 |
| CDLA-Permissive-2.0 | 2 |
| Zlib | 2 |
| (Apache-2.0 OR MIT) AND BSD-3-Clause | 1 |
| (Apache-2.0 OR MIT) AND Unicode-3.0 | 1 |
| 0BSD | 1 |
| 0BSD OR Apache-2.0 OR MIT | 1 |
| Apache-2.0 AND ISC | 1 |
| Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR CC0-1.0 | 1 |
| Apache-2.0 OR BSD-1-Clause OR MIT | 1 |
| Apache-2.0 OR BSL-1.0 | 1 |
| Apache-2.0 OR CC0-1.0 OR MIT-0 | 1 |
| Apache-2.0 OR LGPL-2.1-or-later OR MIT | 1 |
| BSD-3-Clause AND MIT | 1 |
| BSD-3-Clause OR MIT | 1 |
| CC0-1.0 | 1 |

### On-chain program license distribution

Counts cover the 406 third-party packages in the `programs/proof-of-reserves` graph.

| License (SPDX, normalized by cargo-license) | Crates |
| --- | --- |
| Apache-2.0 OR MIT | 191 |
| Apache-2.0 | 150 |
| MIT | 27 |
| Apache-2.0 OR MIT OR Zlib | 5 |
| BSD-3-Clause | 5 |
| MIT OR Unlicense | 5 |
| Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT | 4 |
| Apache-2.0 OR BSD-2-Clause OR MIT | 4 |
| NOT DECLARED | 3 |
| Apache-2.0 OR BSD-3-Clause OR MIT | 2 |
| Zlib | 2 |
| (Apache-2.0 OR MIT) AND Unicode-3.0 | 1 |
| Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR CC0-1.0 | 1 |
| Apache-2.0 OR BSD-1-Clause OR MIT | 1 |
| Apache-2.0 OR BSL-1.0 | 1 |
| Apache-2.0 OR CC0-1.0 OR MIT-0 | 1 |
| Apache-2.0 OR LGPL-2.1-or-later OR MIT | 1 |
| BSD-2-Clause | 1 |
| CC0-1.0 | 1 |

## Items needing attention

| Crate | Version | Issue |
| --- | --- | --- |
| verifier, access-controller, arrayvec | 0.4.0, 1.0.1, 1.0.1 | The 3 `NOT DECLARED` entries. All come from the git fork `github.com/Uranium-Digi/chainlink-data-streams-solana` at commit `2926dfb` and declare neither `license` nor `license-file`. The repository root `LICENSE` is MIT, "Copyright (c) 2025 SmartContract", identical to the upstream `smartcontractkit/chainlink-data-streams-solana`. `arrayvec` 1.0.1 is a crate vendored inside that repository (`crates/arrayvec`), not the crates.io `arrayvec`. `verifier` is a direct dependency of the program and of `tests`; `access-controller` is a direct dependency of `tests` and reaches the program through `verifier`. |
| chainlink_solana_data_streams | 1.1.0 | Git dependency on `smartcontractkit/chainlink-data-streams-solana` tag `v1.1.0` rather than crates.io. Declares MIT. Direct dependency of the program. |
| deps/verifier.so, deps/access_controller.so | - | Prebuilt program binaries committed to the repository and loaded into the local test validator through `[[test.genesis]]` in `Anchor.toml`. Not in `Cargo.lock`, not deployed by this repository. Their genesis addresses match the `declare_id!` of the `verifier` and `access-controller` programs in the fork above, which indicates they are builds of those programs and fall under the same MIT license; the binaries themselves carry no license or build-provenance metadata. |
| im, bitmaps, sized-chunks | 15.1.0, 2.1.0, 0.6.5 | `MPL-2.0+` (MPL-2.0 or later). Reached only through `tests` (`solana-program-test` -> `solana-runtime`). File-level copyleft only: modified versions of those files must be made available to recipients of a distributed binary. The test harness is not distributed. |
| index_list, webpki-roots (0.24.0, 0.25.4) | - | MPL-2.0, same terms as above. Reached only through `tests` (`solana-runtime`, `solana-client`). |
| webpki-root-certs | 0.26.11, 1.0.0 | CDLA-Permissive-2.0, the data license for the Mozilla CA bundle. Permissive. Reached only through `tests`. |
| r-efi | 5.2.0 | Triple-licensed `Apache-2.0 OR LGPL-2.1-or-later OR MIT`. Take the MIT or Apache-2.0 option; the LGPL option carries no obligation here. Pulled in by `getrandom` 0.3 on UEFI targets only, so it is never compiled for this project. |

Workspace-internal crates (`proof-of-reserves`, `proof-of-reserves-tests`) declare no license, which is expected for a private codebase.

## Direct Rust dependencies

`Declared` is the version requirement in `Cargo.toml` (`git` for git dependencies); `Resolved` is what `Cargo.lock` pins today. Where workspace members pin the same crate differently, both requirements are listed. `tests` is the `proof-of-reserves-tests` crate.

| Crate | Declared | Resolved | License | Used by |
| --- | --- | --- | --- | --- |
| access-controller | git | 1.0.1 | NOT DECLARED (MIT, see above) | tests |
| anchor-client | 0.31.1 | 0.31.1 | Apache-2.0 | tests |
| anchor-lang | 0.31.1 | 0.31.1 | Apache-2.0 | programs/proof-of-reserves, tests |
| anchor-spl | 0.31.1 | 0.31.1 | Apache-2.0 | programs/proof-of-reserves, tests |
| anyhow | 1.0.0 | 1.0.98 | Apache-2.0 OR MIT | tests |
| bytemuck | 1.22.0 | 1.23.0 | Apache-2.0 OR MIT OR Zlib | programs/proof-of-reserves |
| chainlink-data-streams-report | 1.0.3 | 1.0.3 | MIT | programs/proof-of-reserves |
| chainlink_solana_data_streams | git | 1.1.0 | MIT | programs/proof-of-reserves |
| hex | 0.4, 0.4.3 | 0.4.3 | Apache-2.0 OR MIT | programs/proof-of-reserves, tests |
| hex-literal | 0.4.1 | 0.4.1 | Apache-2.0 OR MIT | tests |
| num-bigint | 0.4 | 0.4.6 | Apache-2.0 OR MIT | programs/proof-of-reserves |
| num-traits | 0.2 | 0.2.19 | Apache-2.0 OR MIT | programs/proof-of-reserves |
| snap | 1 | 1.1.1 | BSD-3-Clause | tests |
| solana-client | 2.1.0 | 2.2.7 | Apache-2.0 | tests |
| solana-program-test | 2.1.0 | 2.2.7 | Apache-2.0 | tests |
| solana-sdk | 2.1.0 | 2.2.2 | Apache-2.0 | tests |
| spl-pod | 0.5.0 | 0.5.1 | Apache-2.0 | programs/proof-of-reserves |
| spl-tlv-account-resolution | 0.10.0 | 0.10.0 | Apache-2.0 | programs/proof-of-reserves |
| spl-transfer-hook-interface | 0.10.0 | 0.10.0 | Apache-2.0 | programs/proof-of-reserves |
| spl-type-length-value | 0.8.0 | 0.8.0 | Apache-2.0 | programs/proof-of-reserves |
| tokio | 1 | 1.45.0 | MIT | tests |
| verifier | git | 0.4.0 | NOT DECLARED (MIT, see above) | programs/proof-of-reserves, tests |
