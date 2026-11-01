# Rust implementation plan

Decisions for the next implementation. Nothing here is built yet; this file
records the toolchain choices and the exact configuration so the scaffold starts
from a known state.

## Status on this machine

| Tool | State |
| ---- | ----- |
| rustc / cargo | 1.99.1 (installed via rustup at `~/.cargo/bin`) |
| clang | 23.1.4 (`/usr/bin/clang`) |
| gcc | 16.2.1 |
| sccache | 0.19.0 (`/usr/bin/sccache`) |
| mold | 3.0.0 (`/usr/bin/mold`) |

### Verified on this machine

A scratch package with the configuration below was built, cleaned, and rebuilt:

- `cargo build --release` linked through clang with `-fuse-ld=mold`; clang
errors out if `mold` is missing, so a successful link confirms it is used.
- The second clean build reported **1 cache hit** from sccache. The library crate
was cached; the binary crate was not (`crate-type (bin)` is listed as a
non-cacheable reason).

That last point matters for the workspace shape: sccache pays off on library
crates and dependencies, not on the final binaries. A workspace split into
`crypto`, `tx`, `validator` and one thin `cmd/karsa` CLI is exactly the shape
where it helps.

## Cache: sccache

Put this in `.cargo/config.toml` at the Rust project root, not in a global file:

```toml
[build]
rustc-wrapper = "sccache"
```

and disable incremental compilation, which sccache cannot cache usefully:

```bash
export CARGO_INCREMENTAL=0
```

Keep the cache off the project tree so it does not pollute backups or diffs:

```bash
export SCCACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/karsa-sccache"
```

Check it is working:

```bash
sccache --show-stats
# after a clean rebuild: "compile requests" > 0, "cache hits" > 0
```

`sccache` hashes the compiler flags, so changing `RUSTFLAGS` invalidates the
cache. Set flags once, in config, and leave them alone.

## Linker: mold

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

Equivalent without changing the linker:

```bash
RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build
```

Mold is the `ld` replacement; it matters most for large binaries and test
executables, which is exactly where a crypto + consensus workspace spends link
time. It does not change runtime behavior.

Do not also set `RUSTFLAGS` in the environment when it is in config: the
environment wins and the two silently diverge, which also thrashes the sccache
entries.

## Suggested full config

`.cargo/config.toml`:

```toml
[build]
rustc-wrapper = "sccache"

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

`.cargo/config.toml` is per-user and per-project; commit it, because every
contributor benefits and a divergent flag set invalidates shared caches.

## Verifying the setup

```bash
cargo build --release
sccache --show-stats | grep -E "compile requests|cache hits"
cargo clean && time cargo build --release   # cold, should be faster with warm sccache
```

## Current scaffold

```text
karsa-new/                 # workspace root
├── Cargo.toml
├── .cargo/config.toml
├── crates/
│   ├── crypto/      # error, encoding, registry, domain, scheme, ml_dsa
│   ├── tx/          # envelope, policy
│   └── validator/   # epoch-bound key schedule
├── cmd/karsa/       # one CLI: node, sample-tx, demo, acvp, dagbench, loadtest
└── scripts/{rust-check.sh, acvp-rust.sh, loadtest-rust.sh}
```

Status of the first stage:

- `crypto` implements the closed error taxonomy, the canonical codec, the
  algorithm registry (same frozen IDs and sizes as V), domain-separated
  payloads, and the `SignatureScheme` trait with Ed25519, ML-DSA-65, and
  SLH-DSA-SHA2-128s implementations.
- 120 tests pass in the workspace default build (121 with `--all-features`), 30
  of them in `crypto` alone without PQ backends: RFC 8032 vectors, ML-DSA and
  SLH-DSA roundtrip and context binding, deterministic signing, key generation,
  envelope and policy behaviour, validator rotation and quorum-safe counting,
  validator key registration and epoch advance over HTTP, certificate encoding
  and quorum rejection, batch-vs-individual equality, the dissemination model's
  formulas, in-process HTTP tests, plus byte-for-byte parity checks for the
  signing payloads and a complete signed envelope.
- `karsa acvp` matches 15/15 NIST ML-DSA-65 and 14/14 SLH-DSA-SHA2-128s sigVer
  vectors.
- `karsa node` produces the same transaction id as the V node for the same demo
  envelope, which is expected because the encoded bytes are identical. It also
  exposes the validator schedule: registration is authorized by an existing
  active key, and `POST /epoch` refuses to advance past a schedule that would
  leave a validator without an active key.
- `karsa dagbench` reproduces the V certificate sizes exactly (331,403 B at 100
  validators) and the 10.2× / 1.6× dense-vs-sparse header ratios.
- `karsa certify` encodes and verifies a real certificate against the schedule:
  batch verification cuts Ed25519 certificate verification by 1.3–2× (2,630 µs
  instead of 4,108 µs at 100 validators), and below-quorum, tampered,
  retired-key, and shape-mismatch cases are all rejected with protocol codes.
- `karsa bandwidth` re-derives the dissemination arithmetic: per-node egress is
  `(n-1)/n` of the originator total for any fanout, so batching and certificate
  size move the number and fanout does not. It also prices three consensus
  metadata styles per round: an `n`-signature certificate (10,000 signatures at
  n=100), and block-per-validator DAGs with one signature each (100), which is
  where a 30–95× metadata difference comes from.
- `karsa loadtest` measures ~50–57k accepted tx/s on this machine, against
  ~25–33k for the V node.
- The V prototype's rule that activation requires an implementation is
  preserved: `pq-testnet` without at least one of `pq-openssl` or `pq-slh` is a
  compile error.

Port order and the normative spec live in `docs/crypto-registry.md`;
the measured V numbers to beat are in the root `README.md`.

## Crate choices to evaluate

| Need | Candidate | Note |
| ---- | --------- | ---- |
| Ed25519 | `ed25519-dalek` | audited, constant-time, fast; `batch` feature for multi-scalar verification, `curve25519-dalek` used directly to reject a small-order `R`, which the batch equation does not test |
| ML-DSA-65 | RustCrypto `ml-dsa`, or OpenSSL via `openssl` crate | RustCrypto's is a pre-release and not independently audited; the V prototype used OpenSSL 3.6.5 and passed ACVP sigVer |
| SLH-DSA-128s | RustCrypto `slh-dsa` (pure Rust) or OpenSSL 3.5+ EVP | chosen `slh-dsa` 0.2.0-rc.5 so the hash-based fallback needs no system library; also a pre-release, so it still needs an audit |
| Hashing | `sha2` | matches `SHA-256` in the spec |
| Encoding | hand-written, as in V | the canonical encoding is normative; do not let `serde` choose bytes |
| Benchmarking | `criterion` | plus `dhat` or a counting allocator if allocation matters |
| HTTP | `axum` or `hyper` | the V node used viltrum; keep the transport at the edge |
| Concurrency | `rayon` for verification, `tokio` for the node | verification is CPU-bound, so `rayon` is the natural fit |

Keep the OpenSSL path as the reference implementation: it is what passed the
NIST vectors, and a second backend lets the Rust version cross-check itself
against the V results.
