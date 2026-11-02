# Karsa

A post-quantum, crypto-agile blockchain experiment. The implementation is a Rust
workspace. The reference design is kept locally in `docs/` and is deliberately
not part of this repository.

## Layout

| Path | Contents |
| ---- | -------- |
| `crates/crypto/` | Rust: registry, canonical encoding, domain separation, schemes |
| `crates/tx/` | Rust: transaction envelope, authorization policy, batches |
| `crates/exec/` | Rust: deterministic account state machine over committed batches |
| `crates/validator/` | Rust: epoch-bound validator key schedule, DAG, pacemaker, headers |
| `crates/net/` | Rust: vertex dissemination between nodes, deterministic scheduling |
| `crates/store/` | Rust: append-only on-disk vertices, batches, and roots |
| `cmd/karsa/` | Rust: single CLI with `node`, `sample-tx`, `demo`, `acvp`, `dagbench`, `loadtest`, `dagsim`, `chain`, `net`, `persist` |
| `.cargo/config.toml` | sccache as rustc wrapper, mold as linker |
| `scripts/rust-check.sh` | Rust gate: fmt, clippy, tests |
| `scripts/acvp-rust.sh` | Downloads the ACVP vectors and runs the checker |
| `scripts/loadtest-rust.sh` | Starts the node, drives it, prints tx/s |
| `RUST.md` | Toolchain decisions and crate choices |

The design notes (`docs/architecture.md`, `docs/crypto-registry.md`,
`docs/consensus-notes.md`) are unpublished and git-ignored; the spec they
contain is still normative for this code.

## Rust port

Done:

- Workspace with `sccache` and `mold` (see `RUST.md`).
- `crypto`: closed error taxonomy, deterministic codec, algorithm
  registry with the same frozen IDs and sizes as V, domain-separated payloads.
- `crypto::merkle`: the Merkle tree and leaf commitment shared by the state root
  and the DAG commit root. Two layers of domain separation (structural tags, then a
  caller tag), odd nodes promoted rather than duplicated, and proofs that carry
  each sibling's side so verification is a fold.
- `crypto::scheme`: the `SignatureScheme` trait, Ed25519 via
  `ed25519-dalek`, static-dispatch `verify_signature`, and key generation.
- `crypto::ml_dsa` (feature `pq-openssl`): ML-DSA-65 via the `openssl`
  crate, including the FIPS 204 context string and seed-based key derivation.
  Requires OpenSSL 3.5 or newer.
- `crypto::slh_dsa` (feature `pq-slh`): SLH-DSA-SHA2-128s via the pure-Rust
  `slh-dsa` crate, including the FIPS 205 context string. No system library.
- `tx`: transaction envelope (canonical encode/decode, payload hash,
  authorization-list limit) and authorization policy (`single`, `all`,
  `threshold`, no OR).
- `validator`: epoch-bound validator key schedule, quorum-safe signature
  counting (one vote per validator even if two keys sign), and the 3×/2×
  supermajority rule.
- `validator::certificate`: canonical DAG-BFT certificate encode/decode and
  verification against the schedule at the certificate epoch. The certificate
  carries a signer bitmap and one signature per signer, never key ids: the
  active key is resolved from the schedule, so a retired key cannot certify.
  Ed25519 signers are batch-verified when there are four or more.
- `validator::vertex`: the uncertified alternative — one signature per block with
  votes expressed as references, a content-addressed id, and `tally_votes` with
  one count per author. `karsa certify` runs both styles on the same round.
- `validator::dag`: vertices keyed by `(round, author)`, a shape rule that
  requires every non-genesis vertex to reference a quorum of distinct
  previous-round authors, deterministic leader election, and the direct commit
  rule — commit on a vote supermajority, skip on an observed non-vote
  supermajority, otherwise undecided — plus the indirect rule that resolves an
  earlier slot through a committed anchor.
- `validator::pacemaker`: drives the decision cursor forward one round at a time.
  Ticks are logical events, never wall-clock, so the same DAG plus the same tick
  order always produces the same output. A timeout is reported, not acted on: it
  means "request the vertices I am missing", never "decide without them". The
  cursor can overtake a leader whose vertex never arrived by earning an anchor
  from a later round, which is what makes an absent leader provably skippable.
- `tx::batch`: the data plane unit. A vertex names a batch by SHA-256 digest and
  never carries payload, so consensus messages stay at their measured size.
- `exec`: a deterministic account state machine over committed batches. Balances
  and per-sender sequences live in `BTreeMap`s, rejections are values rather than
  errors, and `state_root` is a Merkle root over one leaf per account. Inclusion
  proofs let a client holding only the root read one balance without trusting the
  node that served it; odd nodes are promoted rather than duplicated, so two
  account sets cannot share a root.
- `validator::header`: committed-state headers and the finality certificate that
  names them. The header id is a domain-separated hash, and the certificate is the
  existing vote payload over that id — `n` signatures once per **commit**, not once
  per round, which is what makes it affordable where a per-round certificate was
  not. `HeaderChain` is the verifier a light client runs: it needs no DAG, no
  transactions, and no account state.
- `validator::dag` commit root: `dag_root` in a header is a Merkle root over the
  committed vertices in commit order, and `CommitProof` proves one vertex was part
  of the commit a header names. The proof is taken against the commit prefix at
  that height, so it does not verify against a later header.
- `net`: `n` nodes that each own a DAG and exchange only vertices, with delivery
  latency derived from a seeded hash so a run is reproducible. It caught a real
  ordering bug: probing for an anchor by *committing* out of cursor order made two
  nodes with the same DAG commit different sequences. The anchor is now
  quorum-backed rather than committed, and emission stays ordered.
- `store`: append-only logs of `u32 len || payload` records for vertices and
  batches, plus atomically replaced snapshot and roots files. A torn tail from a
  crash is ignored; a complete record that does not decode is an error. Pruning
  drops everything at or below a state snapshot, so restart replays only the tail.
  `karsa persist` saves, prunes, drops the simulation, reopens, replays, and fails
  unless the state root comes back identical.
- `karsa chain`: order and execute a small chain end to end — sign, batch, name by
  vertex, commit through the DAG and the pacemaker, apply, certify one header per
  committed round, verify the header chain the way a light client would, and check
  an account proof against the certified `state_root` and a commit proof against
  the certified `dag_root`. The conservation invariant and the determinism of the
  state root are checked on every run.
- `karsa node`: the same HTTP pipeline as the V node (decode, policy lookup,
  signature verification, per-sender replay protection) on axum, plus the
  validator schedule: `GET /validators`, `POST /validators/{id}/keys`
  (authorized by an existing active key), and `POST /epoch`.
- `karsa dagbench` and `karsa loadtest`: the same measurements as the V tools, so
  the numbers are directly comparable.
- 219 tests in the default workspace build, including RFC 8032 vectors, ML-DSA-65
  and SLH-DSA roundtrip and context binding, deterministic signing, envelope and
  policy behaviour, validator rotation, validator key registration over HTTP,
  certificate encoding and quorum rejection, vertex encoding and vote tallying,
  the DAG direct and indirect commit rules, the deterministic pacemaker, batch
  encoding, the account state machine, Merkle inclusion, promotion and
  multi-domain leaf properties, commit-proof membership and prefix binding, header
  finality and replay refusal, cross-node convergence with and without a crashed
  validator, store round-trips, torn-tail tolerance, pruning, replay-to-the-same-
  roots, in-process HTTP tests, and
  **byte-for-byte parity checks** against V for the signing payloads and for a
  complete signed envelope.
- `karsa acvp` passes **15/15** NIST ML-DSA-65 sigVer vectors (the same result as
  the V prototype) and **14/14** NIST SLH-DSA-SHA2-128s sigVer vectors.

Not yet: nothing in the port plan below is missing.

Measured on this machine, one core for the crypto figures:

| Measurement | V | Rust |
| --- | ---: | ---: |
| Ed25519 verify | ~63 µs/sig | ~40 µs/sig |
| ML-DSA-65 verify | ~189 µs/sig | ~193 µs/sig |
| 100-validator certificate | 331,403 B | 331,403 B (identical) |
| Certificate verify, ML-DSA-65, n=100 | 18.9 ms | 19.3 ms |
| Dense vs sparse headers, n=100 | 10.2× / 1.6× | 10.2× / 1.6× |
| Demo node throughput | ~25–33k tx/s | ~50–57k tx/s |

The Rust node is roughly twice as fast: axum/tokio spread work across threads and
`ed25519-dalek` verifies faster than libsodium's Ed25519 here. ML-DSA-65 is the
same OpenSSL engine, so those numbers match within run-to-run noise.

SLH-DSA-SHA2-128s has no V counterpart. Measured the same way: ~905 µs to verify
one signature, ~626 ms to sign one, and a 100-validator certificate of 786,103 B
(projected). It is registered for agility, not as a default.

Certificates are no longer only a cost model: `karsa certify 10` encodes a real
certificate and verifies it against the epoch-bound schedule. 771 bytes at 10
validators, 296 µs to verify plus check the quorum on one core (3,376/s) when the
signers are Ed25519, against 589 µs per signature-at-a-time — a 1.3–2× gain that
stops well short of 5–10× because every signature still needs its own SHA-512.
The four rejection paths (below quorum, tampered signature, retired signer key,
bitmap/signature mismatch) each report a frozen protocol code.

Batching changes CPU only: the certificate bytes are identical, so it does not
move the bandwidth conclusions.

```bash
cargo build
cargo test
cargo run -p karsa -- demo
cargo run -p karsa -- node          # HTTP node on 127.0.0.1:8099
cargo run -p karsa -- acvp testdata/acvp/sigver.json
cargo run -p karsa -- register-demo 1   # signed validator key rotation body
cargo run -p karsa -- certify 10        # encode, verify, and reject certificates
cargo run -p karsa -- dagsim            # DAG commit rule on fixed scenarios
cargo run -p karsa -- bandwidth         # per-node dissemination model
cargo run -p karsa -- dagbench
cargo run -p karsa -- loadtest 20000 16
./scripts/rust-check.sh
./scripts/acvp-rust.sh       # downloads vectors on first use
```

Rotating a consensus key against a running node:

```bash
karsa register-demo 1 > /tmp/rot.json
curl -s -X POST -H 'content-type: application/json' \
     --data @/tmp/rot.json http://127.0.0.1:8099/validators/val-1/keys
curl -s -X POST -H 'content-type: application/json' \
     -d '{"epoch":1}' http://127.0.0.1:8099/epoch
curl -s http://127.0.0.1:8099/validators   # genesis retired, val-1-next active
```

`pq-testnet` requires at least one PQ backend to be compiled; with neither
`pq-openssl` nor `pq-slh` it is a compile error. The two backends activate
independently, so `--features pq-slh,pq-testnet` enables SLH-DSA-SHA2-128s while
leaving ML-DSA-65 gated. The CLI always compiles both backends so `karsa acvp`
can check either vector set.

## Design findings

These were established with the V prototype, which has since been removed; the
Rust port reproduces its measurements.

1. **A crypto-agile registry works.** Algorithm IDs, statuses, canonical
   encodings, domain separation, and a closed error taxonomy are enough to swap
   signature schemes without touching consensus rules.
2. **Implementation and activation must be separate.** ML-DSA-65 compiles under
   `pq-openssl` but stays gated unless `pq-testnet` is also passed.
3. **The PQ cost is size, not arithmetic.** ML-DSA-65 signatures are 3,309 B
   against Ed25519's 64 B.
4. **Certificates, not transactions, bound a node.** At 100 validators an
   ML-DSA-65 certificate is 331 KB and takes 18.9 ms to verify on one core.
5. **100k TPS is a cluster problem.** Classical signatures need ~11 cores and
   18 MB/s; hybrid PQ needs ~30 cores on 2014-class hardware and ~2.8 Gbps,
   before fanout, plus mandatory batching.
6. **Sparse DAGs help, but less under PQ.** Bluestreak-style headers are 10.2×
   smaller per round with Ed25519 and only 1.6× with ML-DSA-65 at 100 validators.
7. **The demo node does ~25–33k tx/s on the development machine** for the full
   HTTP + verification path, with no execution or persistence.
8. **Fanout does not reduce dissemination bytes.** When every validator needs
   every certificate, per-node egress is `(n-1)/n` of the originator total no
   matter the topology; a tree changes connections (99 → 4) and hops (1 → 4) only.
   Batching, certificate size, and sending to fewer peers are the real levers.
9. **Batch verification is not aggregation.** It cut certificate verification by
   1.3–2× on this CPU, not 5–10×, and left every byte in place.
10. **Certificates cost `n²` signatures per round; uncertified DAGs cost `n`.**
    One artifact per validator per round means our certificate model produces
    10,000 signatures at 100 validators while a block-per-validator DAG produces
    100. `karsa bandwidth` puts that at 32.8 MB vs 343 kB of per-node egress with
    ML-DSA-65; the trade is that a certificate is verifiable offline and a DAG
    claim is not.

## Port plan

| Stage | Crate | State |
| ----- | ----- | ----- |
| Registry, encoding, domain | `crypto` | done |
| Ed25519 scheme + backend | `crypto` | done |
| ML-DSA-65 scheme + ACVP vectors | `crypto`, `karsa acvp` | done |
| Envelope + authorization policy | `tx` | done |
| Validator key schedule | `validator` | done |
| HTTP node | `karsa node` | done |
| DAG and throughput benchmarks | `karsa dagbench`, `karsa certify`, `karsa bandwidth`, `karsa loadtest` | done |

The normative spec is `docs/crypto-registry.md` (local, unpublished); the V
numbers to beat are above. Where the Rust code and the spec disagree, the spec
wins.
