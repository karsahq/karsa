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
| `crates/net/` | Rust: vertex dissemination between nodes, deterministic scheduling, and the wire framing for real sockets |
| `crates/store/` | Rust: append-only on-disk vertices, batches, and roots |
| `crates/erasure/` | Rust: Reed-Solomon over GF(2^8) for sharded storage |
| `cmd/karsa/` | Rust: single CLI with `genesis`, `config`, `node`, `sample-tx`, `demo`, `acvp`, `dagbench`, `loadtest`, `live`, `finality`, `dagsim`, `chain`, `net`, `persist`, `audit`, `migrate`, `sigbench`, `sweep`, `shards` |
| `bench/crypto-verify/` | Rust: standalone crypto benchmark target; its BLS dependency is outside the workspace |
| `.cargo/config.toml` | sccache as rustc wrapper, mold as linker |
| `scripts/rust-check.sh` | Rust gate: fmt, clippy, tests |
| `scripts/acvp-rust.sh` | Downloads the ACVP vectors and runs the checker |
| `scripts/loadtest-rust.sh` | Starts the node, drives it, prints tx/s |
| `RUST.md` | Toolchain decisions and crate choices |
| `node.toml.example` | The node configuration an operator starts from |
| `genesis.json.example` | The genesis a chain starts from |

The design notes (`docs/architecture.md`, `docs/crypto-registry.md`,
`docs/consensus-notes.md`, `docs/decisions.md`) are unpublished and git-ignored;
the spec they contain is still normative for this code. `decisions.md` records the
choices that would be expensive to reverse, and says which ones are decided and
which are still open.

## Implementation

- Workspace with `sccache` and `mold` (see `RUST.md`).
- `crypto`: closed error taxonomy, deterministic codec, algorithm
  registry with frozen IDs and sizes, domain-separated payloads.
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
- `validator::EpochSchedule`: maps rounds to epochs as a pure function of the
  round, which is what lets a key rotation cross a boundary without a restart.
  `karsa migrate`, `karsa chain`, and `karsa live` run it end to end, and the
  header chain now verifies across the boundary instead of refusing a new epoch.
  The generated devnet uses 26,000 rounds (about a minute at the measured local
  round time); a production genesis starts from 86,400 (24 hours at one second
  per round) and is calibrated against measured round time. PQ is registered but
  not active: the default chain is classical, and switching a validator to ML-DSA
  is a change to one `ValidatorKey`. Overlapping keys are not supported yet — a
  vertex carries one signature.
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
  drops everything at or below a state snapshot, so restart replays only the tail,
  and it will only drop a payload this node cannot lose: a batch is deletable when
  nothing in the retained tail names it **and** a shard of it is already on disk.
  The retention path (`karsa prune`) keeps every payload on a node holding no
  shards and says so. A live checkpoint (`--checkpoint-every`) applies the same
  vertex and payload rule at its DAG floor (whole-payload nodes pass
  `min_shards = 0`, `--shard` nodes pass 1) and also drops certified headers
  below the anchor height; the anchor header itself stays, so a restart and an
  audit still start where they resume. `live.snapshot` version 2 stores the state,
  the peaks of the committed prefix below the floor, and only the tail above it;
  version 1 is still read as an empty prefix with the full order. The frontier and
  the header root are described in finding 39.
  `karsa persist` saves, prunes, drops the simulation, reopens, replays, and fails
  unless the state root comes back identical. It also records the chain the
  directory belongs to, and refuses to open against another genesis.
- `erasure`: Reed-Solomon over GF(2^8), non-systematic Vandermonde, any `data` of
  `total` shards reconstruct. `karsa shards` shows the storage it buys (302 GB/day
  down to 9.45 at 1k TPS), the CPU it costs (~36 MB/s scalar, 10% of a core at 1k
  TPS, 98% at 10k), and a round trip through the real store: sixteen directories
  with one shard each, six discarded, payload rebuilt intact. `karsa persist` writes
  a shard per batch before pruning, so the demo of the retention rule runs against
  real files rather than a model.
- `karsa loadtest`: the node's admission path. ~55k accepted tx/s at 16
  connections, which is 64% of the verification ceiling; the rest is HTTP and
  serialisation, not crypto.
- `karsa sweep`: the network simulation across committee sizes, with fault
  tolerance and quorum printed next to each row. Below n=4 the quorum is everyone,
  so those rows show the floor rather than recommend it.
- `karsa sigbench`: the TPS ceiling. Measures transaction verification through the
  full policy path and how it scales across threads: 22.5k tx/s on one core,
  90k on eight hardware threads of a 2014 quad-core. Release builds only — a debug
  build reports ~130 tx/s and means nothing.
- `karsa chain`: order and execute a small chain end to end — sign, batch, name by
  vertex, commit through the DAG and the pacemaker, apply, certify one header per
  committed round, verify the header chain the way a light client would, and check
  an account proof against the certified `state_root` and a commit proof against
  the certified `dag_root`. The conservation invariant and the determinism of the
  state root are checked on every run.
- `karsa audit`: the link between the two committed roots. It verifies every
  certificate in the stored header chain, re-inserts the stored vertices (verifying
  every consensus signature), lets the pacemaker reproduce the commit order,
  recomputes `dag_root` per height, applies the batches and compares `state_root`.
  A full-history store is re-derived from genesis — 7 of 7 heights matched on both
  roots — while a pruned store is audited only above its snapshot (4 of 4 state
  roots, `dag_root` unchecked), and it prints which of the two it did. A test
  covers a quorum certifying a wrong state root: the certificate is valid, and only
  re-deriving the state catches it.
- `net::wire`: the framing a byte stream needs. `u32 body length || u64 sent-at
  nanos || canonical vertex bytes`, parsed from an accumulator so a frame split
  across two reads is "not yet" rather than an error, with a 16 MB cap so one peer
  cannot make a node allocate a number it chose. Four tests: round trip, a partial
  frame left untouched, an oversized length refused before allocating, and a body
  shorter than its own header refused.
- `karsa live`: the DAG on real loopback sockets, full mesh, one listener per
  node. Verified at n = 2, 4, 6, 8, 10, and 20 for 21 rounds: every size
  converged on the same commit root. On an AMD Ryzen 7 6800U (8 cores / 16
  threads), n = 10
  authoring ran at 5.5–8.7 ms/round with p99 37–50 ms; n = 20 at 23.5–31.6
  ms/round with p99 81–97 ms. Delivery order is not the simulator's: a vertex can
  arrive before the round it references, which is why the node defers it and
  retries after the next successful insert. The per-peer queue is bounded and
  awaited, so backpressure replaces a drop policy; `--slow-ms 5` on one validator
  slows authoring by 7–9× and pushes p99 to ~0.8–1.0 s while the commit root stays
  identical and the deferral count stays at zero. Getting that last sentence to
  hold required two fixes: a `missing_reference` during commit is now a retry, not
  a node failure, and an indirect commit no longer mutates history before the
  direct non-vote rule has been ruled out (see design finding 15). With `--txs N`
  each vertex names a real batch of signed transfers and the batch travels on the
  same link, so bytes per transaction are measured rather than modelled (finding
  17). `--execute` applies the committed batches into an account state, so the run
  ends on a state root rather than on a commit root alone, and it waits for the
  applied cursor to catch up with the commit cursor before reporting. `--store DIR`
  persists every vertex and batch through `crates/store`, so the bytes-per-day
  figure is measured from files rather than modelled. `--archives N` adds archive
  nodes: they receive everything, store everything, and never sign. `--profile`
  prints the time each validator spent per named stage of the node loop — sign
  batch, author vertex, commit tick, verify tx, apply state, frame payload, store
  write — as a share of the named total. `--pre-sign` (with `--txs`) signs every
  batch before the measured window, so client signing is not charged to chain
  throughput. `--verify-threads N` (with `--execute`) splits one batch across N
  verifier threads; the default 1 keeps the serial path, and batches under 64
  transactions stay serial either way. `--node-index N` instead runs exactly one
  validator in this process: it binds `port_base + N`, requires `--archives 0`, and
  treats `--timeout` as a shared lifetime, so the process keeps serving peers after
  its own rounds are authored. `scripts/live-multiprocess.sh` starts the committee,
  divides the logical CPUs between processes, compares every process's commit and
  state roots, and reports throughput over the union authoring window. Its
  `VERIFY_THREADS` default follows the per-process CPU slice, because verifier
  threads are the leverage, not the process boundary (finding 26); set
  `VERIFY_THREADS=1` only to reproduce the old serial configuration.
  `--snapshot-port N` serves a state snapshot plus the DAG tail above a floor over
  TCP, and `--sync-from-peers` fetches one from a peer above the stored certified
  head instead of replaying history it does not have. The snapshot carries the
  committed order as a Merkle frontier plus the tail above the floor, not the full
  order (finding 39), and `--checkpoint-every N` writes that same compact form to
  `live.snapshot` every N certified heights while pruning vertices, payloads, and
  headers below its floor; it needs `--execute` and `--store` (findings 36–37,
  39). `scripts/devnet.sh` brings up four such processes from one home.
- `karsa finality`: the client-side metric `live` cannot produce. A closed-loop
  client submits a signed batch to validator 0; a vertex names it, the same
  pacemaker decides it, and the commit is written into a header that the
  certificate keys sign. The mesh runs over `mpsc` links with an injected one-way
  delay and jitter, so the same code can be measured at loopback and at a delay
  comparable to a wide-area network. It reports submit → commit and submit →
  certified header as p50/p95/p99, the commit → certificate gap, and rounds to
  finality as a separate protocol metric: a leader vertex finalizes in one round,
  a non-leader in two, and wall-clock latency is a multiple of the one-way delay
  because a round is an out-and-back. Headers are built one decision at a time
  (`Node::commit_once`), so every node signs the same prefix header regardless of
  how many decisions one tick happened to contain.
- `karsa peers`: the network half, in `peers.json` beside the other two. Genesis says
  who the validators *are*; an address is operational data that changes when a
  machine moves, so it never goes in the file every node must agree on. `--add
  id@host:port` and `--remove id` grow and shrink the list, and the listing marks
  each entry as a founding validator (present in genesis) or known-only, which is
  a legitimate state for an RPC or sentry.
- `karsa genesis`: the file every node must agree on, in JSON because it is a
  generated consensus artifact rather than a hand-edited preference. Validators,
  their keys, the founding accounts with their policies, and the key-epoch length
  are all explicit; `--init --epoch-rounds 86400` writes a genesis whose key
  epoch is 24 hours at one second per round, while the generated devnet keeps
  its short default. Unknown fields, duplicate ids, unknown algorithms, wrong
  key lengths, and a threshold above the key count are each refused with a
  sentence. It prints the **genesis hash over the canonical encoding, not over the
  file**, so reformatting the JSON or reordering validators does not change the
  chain's identity, and a field change always does.
- Home directory: `karsa config`, `karsa genesis`, `karsa node`, `karsa chain`,
  and `karsa live` all take `--home DIR` (default `$HOME/.karsa`) and read the
  files that describe one chain membership from the same place — `node.toml`,
  `genesis.json`, `keys.json`, and `peers.json` — writing any missing one with a
  documented default. The private half lives in `keys.json` (`0600`, never hashed)
  and is validated against the genesis public keys: an address the genesis does not
  list, a key id the policy does not have, or a public half that disagrees with its
  seed is refused before a signature exists. A fresh home is a four-validator,
  four-account devnet; `genesis.json` and `keys.json` are generated together from
  the demo seeds, so `karsa chain 4 --rounds 4 --home DIR`, `karsa live
  --validators 4 --home DIR`, `karsa persist --home DIR 4 --rounds 4`, and `karsa
  audit --home DIR` run without extra setup. A store remembers the genesis it was
  written under; auditing it with another home is refused by that binding before
  any signature work. The node keeps **no chain identity of its own**: the genesis
  beside it is the only one, so there is nothing to drift from it.
- `karsa config`: per-node settings in a `node.toml`, the way an operator expects.
  Roles (validator, rpc, archive), retention (days and a hard disk cap), snapshot
  cadence, and listen addresses. The file is validated rather than trusted — an
  archive node that also prunes, a pruning node with zero retention, a node with no
  role, or an RPC role with no address are all refused with a sentence each — and
  the command prints what the retention setting costs at 10/100/1k/10k TPS for both
  a 169 B and a 3.5 kB transaction, because the number that matters is the disk, not
  the days.
- `karsa prune`: applies that policy to a store. Both bounds become one round
  cutoff — "whichever comes first" is the one that leaves less history — and the
  cutoff never crosses the newest snapshot, because that snapshot is what the tail
  is replayed onto. A store with no snapshot is left alone rather than made
  unreplayable. When the cap cannot be met (headers and shards are kept forever, and
  an unsharded payload is never dropped) the report carries the shortfall instead of
  claiming the disk fits. `--dry-run` prints the cutoffs without deleting.
- `karsa node`: an HTTP pipeline (decode, policy lookup, signature verification,
  per-sender replay protection) on axum, plus the validator schedule:
  `GET /validators`, `POST /validators/{id}/keys` (authorized by an existing active
  key), and `POST /epoch`. With `--config node.toml` it binds to
  `network.rpc_listen` and writes the file with defaults first if it is missing,
  instead of refusing its own first run.
- 385 tests in the default workspace build, including RFC 8032 vectors, ML-DSA-65
  and SLH-DSA roundtrip and context binding, deterministic signing, envelope and
  policy behaviour, validator rotation, validator key registration over HTTP,
  certificate encoding and quorum rejection, vertex encoding and vote tallying,
  the DAG direct and indirect commit rules, the deterministic pacemaker, batch
  encoding, the account state machine, Merkle inclusion, promotion and
  multi-domain leaf properties, commit-proof membership and prefix binding, header
  finality and replay refusal, cross-node convergence with and without a crashed
  validator, store round-trips, torn-tail tolerance, pruning, the retention rule
  (a sharded payload is dropped, an unsharded one is held, an in-window one stays),
  certified-header round-trips and their truncation, replay-to-the-same-
  roots, auditing a full-history store from genesis, auditing a pruned store above
  its snapshot, catching a quorum that certified a wrong state root, the
  pacemaker refusing to emit history for an indirect commit it defers, in-process
  HTTP tests, and
  **fixed vectors** for the signing payloads and for a complete signed envelope.
- `karsa acvp` passes **15/15** NIST ML-DSA-65 sigVer vectors and **14/14** NIST
  SLH-DSA-SHA2-128s sigVer vectors.

Nothing in the build order below is missing.

Measured on this machine, one core for the crypto figures:

| Measurement | Result |
| --- | ---: |
| Ed25519 verify | ~40 µs/sig |
| ML-DSA-65 verify | ~193 µs/sig |
| 100-validator certificate | 331,403 B |
| Certificate verify, ML-DSA-65, n=100 | 19.3 ms |
| Dense vs sparse headers, n=100 | 10.2× / 1.6× |
| Demo node throughput | ~50–57k tx/s |

Run-to-run noise is ±25%; ratios are stable and single numbers are not.

SLH-DSA-SHA2-128s, measured the same way: ~905 µs to verify one signature,
~626 ms to sign one, and a 100-validator certificate of 786,103 B (projected). It
is registered for agility, not as a default.

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
cargo run -p karsa -- persist --keep-history 4 --rounds 6
cargo run -p karsa -- audit 4               # re-derive both committed roots
cargo run -p karsa -- live --validators 5 --rounds 20
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

Established by measurement on the development machine; the numbers are in the
tables above.

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
11. **A committee buys safety, not throughput.** `karsa sweep` over n = 2…100 at
    32 ticks: deliveries are exactly `held × (n−1)`, quadratic in total and linear
    per node, while commits per tick flatten from n=40 (437 at n=40, 471 at n=60,
    both at 32 ticks). Every size agreed on the DAG and the order. Above the quorum
    floor, more validators only raise `f`.
12. **The retention window, not the shard, decides storage.** Sharding is a 32× cut
    that is permanent; the full-payload window is a duration and does not scale with
    it. At 1k TPS a 1-hour window costs 12.6 GB against a 9.45 GB/day shard (22 GB
    total), while a 1-day window costs 302 GB and erases the saving (311 GB total).
    So the window has to be hours, and its purpose is serving a peer that is behind,
    not serving history.
13. **The two committed roots are linked by replay, and pruning weakens it.**
    `karsa audit` re-derives `dag_root` and `state_root` from the stored data and
    checks both against the certified header: 7 of 7 heights on a full-history
    store. A pruned store can only be audited above its snapshot (4 of 4 state
    roots, `dag_root` unchecked), so the retention window is also the audit window.
    This is checkable, not small: a light client still cannot verify it, which is
    the case a zk or fraud proof would cover.
14. **A real transport changes the order, not the rules.** On loopback sockets at
    n = 2…20 every committee converged on the same commit root, but delivery order
    is no longer the simulator's: a vertex can arrive before the round it
    references. Insertion tolerates that — the shape rule needs a quorum of distinct
    authors, not every edge — so a missing neighbour stays invisible until a walk
    needs it. That is why repair scans the held DAG instead of reacting to a
    rejected insert, which never happens for this reason.
15. **Backpressure is a latency cost; it also exposed a convergence bug.** With
    one validator delayed by 5 ms per frame, authoring fell from 5.5–8.7 to
    54.5–57.0 ms/round and p99 rose from 37–50 ms to 0.8–1.0 s, while the commit
    root stayed identical and nothing was deferred. The first version of that run
    was not trustworthy: a `missing_reference` during commit killed a node, and an
    indirect commit could beat a direct non-vote skip, so two nodes with the same
    final DAG committed the same vertices in different orders. Both are fixed —
    commit now waits for the referenced vertex, and an indirect commit is only
    taken when more than `f` voters are held, before any history is emitted — and
    30/30 slow runs, 30/30 n = 10, 10/10 n = 20, and 5/5 n = 20 with `--slow-ms`
    converged. The transport still blocks rather than drops; repair is the next
    step, not a property this run has.

The fix is a rule, not a patch: the anchor is **derived** from the DAG on every
    tick instead of cached, an indirect commit requires more than `f` held voters,
    and a round whose leader the anchored history proves absent is the only kind an
    anchor may skip. Two consequences worth naming. First, a walk this node cannot
    finish now *waits* instead of returning an error through `Pacemaker::tick` — a
    partial history proves nothing, and letting that error escape would have made
    `karsa persist` treat a delivery gap as corruption. Second, there is no cached
    anchor left to disagree with the derived one, so the commit order is a function
    of the DAG and not of when data arrived. Reverting only `pacemaker.rs` makes the
    regression test fail with "a deferred indirect commit must not leave history
    behind", which is the check that the test is not passing by accident.
16. **A drop is safe when the reference rule can see it.** Each peer has a bounded
    queue and `try_send`, so one slow validator no longer blocks the node loop: at
    n=4 over 100 rounds with a 2 kB socket buffer and 5 ms/frame on one node, 19
    frames were dropped and 28 `Want`s repaired them — **0 abandoned**, commit root
    unchanged, authoring at 29 ms/round. Two things had to be true for that. Repair
    must be driven by the DAG — dangling references *plus* the vertex blocking the
    commit walk, because the reference rule needs a quorum and not every edge — and
    control traffic must not share a queue with broadcasts. Under the same load with
    one shared queue, 39 of 84 wants were abandoned while the final root still
    matched, which is precisely the failure a convergence-only test would miss.
17. **Bytes per transaction are measured, not modelled.** `karsa live --txs 8`
    signs a batch of transfers per round, names it in the vertex, and sends the
    batch along the same link. At n=4 a node received 171 B per transaction: about
    120 B of envelope, the rest batch and frame overhead. 3,968 unique transactions
    were carried with **0 named batches missing**, including a run where a slow node
    forced vertex drops and repair — because payload waits for a queue slot instead
    of being dropped (D22). The number is per receiving node, so total wire cost is
    that times the committee size.
18. **Consensus, transport, and execution in one run.** At n=4 with 50 rounds of
    100 transactions per batch, every node committed 188 vertices and applied
    **18,800 transactions with 0 rejected**, ending on the same state root
    (`93b9d04a11bd`) and the same commit root — 1.9 s wall clock, so roughly 10k tx/s
    per node and 40k across the four, with execution overlapping consensus rather
    than following it. Getting a number instead of half a number needed two things:
    funded demo accounts (the default 1,000 runs out and turns the run into a
    rejection benchmark) and a run that waits for the applied cursor to reach the
    commit cursor once commits stop arriving.
19. **Storage overhead is ~2%, so the payload is the only lever.** Writing a live
    run through `crates/store` puts 172 B on disk per transaction against 169 B on
    the wire: record headers and duplicate suppression cost 1.8%. Vertices are 1.9%
    of stored bytes (67.9 kB against 3.44 MB of batches at 100 transactions per
    batch). That is D12 measured rather than argued — the append-only format is not
    where storage goes, so the transaction itself is. At 1k TPS this shape costs
    ~14.9 GB/day per node; the 302 GB/day in D15 is the same arithmetic on a 3.5 kB
    hybrid transaction, twenty times larger.
20. **The storage saving is the committee size, not a constant.** With `--shard`
    each node keeps one erasure shard sized by the committee (`data = quorum`,
    `total = n`): 172 → 60 B/tx on disk at n=4, a 2.9× cut, with all 204 batches
    covered by at least three shards across the four nodes. The multiplier is
    `data ≈ 2n/3`, so the "32×" in D15 is a ~48-validator figure; at the launch
    sizes of 10 and 30 validators it is 7× and 21×, and a four-node test committee
    only ever gets 3×.
21. **Pruning plus archive nodes, not sharding, at launch sizes.** A validator that
    keeps a window of payload, a state snapshot, and every certified header forever
    needs no repair protocol and no availability layer, and at n=10–30 it is *more*
    available than one shard per node: any surviving node can serve everything,
    where sharded data needs a quorum alive. The cost is arithmetic — a month of
    payload is 437 GB at 1k TPS with 169 B transactions and 9.1 TB with 3.5 kB PQ
    ones — so the window follows from the disk budget you demand, not from
    preference. Pruning bounds disk only: per-node egress stays `(n-1)/n` of the
    originator total, so if bandwidth becomes the constraint the erasure work
    becomes relevant again. It stays in the tree as a measured result.
22. **Retention is a local decision, so it is a file.** Two validators running the
    same chain do not have to keep the same history: `node.toml` carries the roles
    (validator, rpc, archive), the retention window, a hard disk cap, and the
    snapshot cadence. The cap is the part that matters operationally — retention is
    "this many days **or** this much disk", because a burst is charged in full: one
    hour at 10k TPS is 36 million transactions, which at 3.5 kB is more than a quiet
    month. A config that would delete everything, or an archive node that also
    prunes, is refused before the node starts writing. A node started without a
    file writes one with its comments intact rather than refusing its own first
    run, and an existing file is never overwritten or silently corrected.
23. **Roles are a model, not a comment.** `node.toml` states validator, archive,
    and rpc, and the three compose: a validator signs and prunes, an archive keeps
    everything and signs nothing, and validator + archive does both. `karsa live
    --archives 2` runs the rule rather than describing it — the archive rows show
    `authored 0`, `out 0 B`, `committed 0`, while holding the same bytes on disk as
    a validator (186 B per transaction in a 20-transaction run, identical with and
    without archives). That is what makes "the archive keeps history" a property of
    the code instead of a claim about the operator's intentions.
24. **Chain identity is the genesis hash, and nothing else.** `node.toml` carries
    no chain id at all: every validator loads the same genesis, so a second copy is
    only a place to typo. The human name (`karsa`) lives inside the genesis, where
    it is hashed along with everything else, so renaming a chain is a different
    identity rather than a relabelling. That is the lesson of Ethereum's 2016
    split, where ETH and ETC both kept chain id 1 and transactions replayed across
    them until EIP-155; a hash cannot collide that way. The cost is size — 32 bytes
    in the signing domain instead of a short string — which is ~19 B on a 169 B
    transaction and noise on a 3.5 kB one. Wired end to end: `karsa chain` signs
    over the genesis hash in `--home`, `net`/`live` sign over the same id the other
    commands use, and a store records the chain it was written under — opening a
    directory against another genesis is refused with `store belongs to chain …`
    rather than producing a different root. Still to do: a peer handshake that
    compares hashes between nodes.
25. **Batch verification moves the execution bottleneck, and the best thread count
    moves with it.** Authorization now batch-verifies the single-authorization
    Ed25519 cases with one `verify_ed25519_batch` per verifier chunk and applies
    the authorized transactions by reference instead of cloning them; if the batch
    equation fails it falls back to the per-transaction path, so a bad signature is
    still attributed to its own transaction. On 4 validators, 1,000 tx per batch,
    `--execute --pre-sign`, 20 rounds (84,000 chain-unique transactions), median of
    3 on the same 8C/16T machine: 36.3k tx/s before at 8 verifier threads, 64.9k
    after. After batching, 4 threads gave 73.5k, 8 gave 64.9k, and 16 gave 61.9k —
    four nodes × four threads fill the 16 hardware threads exactly, while 8 and 16
    oversubscribe. Verification is still 94% of the named stages, so the next lever
    is cheaper per-transaction work or fewer nodes doing it, not overlapping it with
    the 6% that remains.
26. **One process per validator is a scheduler boundary, not a throughput lever.**
    `--node-index` puts one validator in each process, which removes the shared
    runtime but not the work: every validator still executes every committed batch.
    On the AMD Ryzen 7 6800U (8 cores / 16 threads), 4 validators, 20 rounds,
    `--execute --pre-sign`, median of 3 on an idle machine, the single-process
    control authored 76.4k tx/s at 1,000 tx/batch with 4 verifier threads and 88.2k
    at 4,000; one process per validator with 4 verifier threads per process authored
    70.9k and 78.3k — 93% and 89% of the control. One verifier thread per process
    authored 29.4k and 37.7k, while the single-process control at one thread
    authored 35.9k and 41.1k. Across the whole matrix one process per validator
    stayed at 82–93% of the single-process control and never above it. Verifier
    threads are a 2.1–2.4× lever; the process boundary is not. Batch 1,000 → 4,000
    adds 10–16% at 4 threads and 14–28% at one. Batch size stops at 4,096
    transactions (`MAX_BATCH_TRANSACTIONS`), so the 1,000 → 4,000 gain is the end of
    that lever. A second session put four workers per process at 64.3k and one
    worker at 62.1k against a 68.9k single-process control in the same session —
    93% and 90%, a 3.5% difference — so worker count does not move the ratio. The
    absolute TPS in that session was 18–22% below the earlier idle matrix for both
    modes; the ratio, not the absolute number, is the stable result, and ratios
    need a same-session control.
    Without `--execute`, four processes finish 21 rounds in 146–159 ms with delivery
    p50 5–9 ms and p99 ≤ 23 ms, so the sockets are healthy; with execution, delivery
    p50 rises to 27–142 ms at 1,000 tx/batch and 198–508 ms at 4,000, depending on
    verifier threads, because `apply_batch_timed` runs inline in the node loop.
    `verify tx` is 89–94% of the named stages. Adding validators does not add unique
    throughput: 10 validators with one worker each authored 24.7k tx/s aggregate and
    each node applied about 22.1k tx/s — the per-node verification ceiling. The
    levers are batch verification (finding 25), verifier threads, and batch size;
    the process boundary is how those are measured, not a lever of its own. Numbers
    must name the verifier-thread count and the load: a first session measured 20.3k
    and 40.6k and one 103.8k run; the idle matrix supersedes those and rejects the
    103.8k as an outlier. The chain spends n× the verification work for one unique
    stream. On the 4C/8T desktop, four validators at 46.9k tx/s each verify 187.5k
    tx/s in total, about twice the machine's raw serial Ed25519 ceiling of 91.7k
    tx/s at eight threads; batch verification is that ~2× factor and it is already
    on, and the curve25519 SIMD backend is selected automatically on x86-64. The
    next lever is therefore not a cheaper verifier but fewer validators verifying
    every transaction — threshold, BLS, or probabilistic verification — which
    changes the trust model and is a protocol decision, not a tuning knob.
27. **Finality is 124–224 ms p50 submit → certified, with a ~1.1–1.3 ms commit →
    certificate gap.** On 4 validators over `mpsc` links with injected one-way
    delay and 0–5 ms jitter, 100 samples, 3 runs (median), at 25 ms one-way delay:
    submit → certified p50 124.1 ms, p95 210.7, p99 218.4, max 242.3; at 50 ms:
    p50 224.3, p95 339.5, p99 394.6, max 446.2. Commit → certificate is p50 1.1 ms
    at 25 ms and 1.3 ms at 50 ms; rounds to finality are p50 2 / p95 3 / p99 3 /
    max 3 at both delays. All 100 samples finalized on every node and certified on
    the submitter in all six runs; order, state, and header agreement held with 0
    conflicts (435/440/436 commits at 25 ms and 413/420/421 at 50 ms). Across
    sessions with load 0.75–4.8, p50 did not move (125.6 → 124.1 ms and 224.6 →
    224.3 ms), so the earlier numbers were within noise; tail latencies vary run to
    run. This is measured on four validators on loopback with injected delay, not a
    WAN and not a large committee. The comparison to Sui (~400–700 ms) and IOTA
    (seconds) is submit → certified, not block time.
28. **Certificate work grows with the committee, before any network delay.**
    Zero-delay controls separate local cost from propagation. At n=10, submit →
    commit p95 is 75.9 ms and commit → certificate p95 15.8 ms, against 18.0 and
    3.4 ms at n=4 — 4.2× and 4.6× before any injected delay; submit → certified
    p95 rises 20.6 → 89.4 ms (4.3×). At 25 ms one-way the same cells are 187.1 →
    228.9, 5.0 → 20.2 and 191.5 → 240.8 ms: delay adds only ~4 ms to the n=10
    certificate tail, so most of its growth is verification and scheduling of
    more quorum signatures and more vertices per round, not waiting for the
    network. With delay, the median moves modestly: submit → certified p50
    125.4 → 139.1 ms (+11.0%) at 25 ms and 224.1 → 244.9 (+9.3%) at 50 ms; p95
    moves 191.5 → 240.8 (+25.7%) at 25 ms but only 391.2 → 402.1 (+2.8%) at
    50 ms, where the n=4 control itself carried a 391 ms p95, so the delayed tail
    is not stable across sessions (an earlier single-run 50 ms control gave
    +26.4%). Rounds stay p50 2 / p95 3–4; leader p50 1, non-leader p50 2. All
    six n=10 runs finalized 100 of 100 samples on every node, certified them on
    the submitter, and agreed with 0 conflicts and 0 rejected. Still one process
    on one 16-thread machine, 1 tx/batch; the n=20/30 extension is finding 29.
29. **The in-process mesh becomes a contention probe at 20–30 validators.**
    Extending the probe to n=20 and n=30 (3 runs at each delay, same session):
    submit → certified p50 rises 139.1 → 255.2 → 585.4 ms at 25 ms and 244.9 →
    350.7 → 583.9 ms at 50 ms; p95 rises 240.8 → 534.3 → 1,876.9 and 402.1 →
    832.7 → 1,862.7. The n=30 medians at the two delays are within 0.3%, but the
    individual p50s span 488.5–631.6 and 510.3–595.9 ms, so that coincidence is
    inside run noise. What is not noise is the load: 3.9 before the n=20 block,
    9.2 after it, and 12.8 after n=30, on 8 cores / 16 threads; the first n=30
    @25 run started at load 9.2 and reached p99 4,253 ms, against 2,530 and
    2,146 ms for the next two. All 30 runs in the session finalized 100 of 100
    samples on every node, certified them on the submitter, and agreed with
    0 conflicts and 0 rejected, so correctness held while latency rose under
    load. It is 20–30 validator tasks sharing one process and 16 hardware threads,
    not 20–30 machines: the numbers are a probe, not a committee-scaling
    prediction, and must not justify a protocol change in either direction.
30. **BLS aggregation fails the measured 2× rule and is not a TPS lever.** The
    pre-registered rule was to pursue BLS only if aggregate verification plus
    failure handling is at least 2× faster than the current Ed25519 batch path
    at 4,096 transactions. A standalone target, `bench/crypto-verify/`, measured
    both on the 4C/8T desktop (Intel i7-4790K), release build, median of three
    runs; blst 0.3.17 is built `no-threads` so the verifier-thread budget is
    explicit, and the BLS dependency is outside the workspace and the default
    build. Ed25519 is the real `verify_ed25519_batch` path (key/signature
    parsing, small-order R guard, batch equation); BLS is `min_pk` and the full
    wire path deserializes, subgroup-checks every signature, aggregates, and
    verifies. At 4,096 distinct 71-byte messages with distinct keys: Ed25519
    96.6 ms on one thread (23.6 µs/signature) and 35.7 ms on four (8.7
    µs/signature); BLS 2,687.5 ms (656.1 µs/signature) and 720.6 ms (175.9
    µs/signature). With one invalid signature, Ed25519's batch-fail-plus-
    fallback path is 265.1 ms against BLS's 4,840.9 ms. BLS is therefore 27.8×
    slower on one thread, 20.2× on four, and 18.3× on the failure path; a third
    session under load kept the direction (33.9×/21.8×/15.4×). Aggregation itself
    is cheap (1.9 µs/signature); the cost is one pairing per distinct message
    (~523 µs/signature) plus the subgroup check (~132 µs/signature). Public keys
    are assumed proof-of-possession-validated at registration, so the BLS
    numbers are lower bounds. Certificate verification at n=10/30: Ed25519
    batch 0.254/0.729 ms versus BLS aggregate 1.460 ms (independent of n), so
    BLS is 5.1–5.7× slower at n=10 and 1.8–2.0× at n=30; n=20 is interpolated.
    A FROST/Schnorr certificate is modeled as one Ed25519 verify (0.040–0.058
    ms), but the measured n=10 commit → certificate p95 is 15.8 ms (finding 28),
    so certificate verification is not the tail. Decision: keep the Ed25519
    batch path; do not adopt BLS transaction aggregation or launch-size BLS
    certificates; defer FROST until the finality tail is a product requirement.
    The n=100 BLS certificate crossover is plausible (existing Ed25519 batch
    report 2.63 ms vs BLS 1.46 ms) but was not measured in one session. Ed25519
    absolute numbers are session-sensitive while the BLS rows stayed within
    0.7%; the ratio is the stable result.
31. **ML-DSA-65 is an experimental fallback, and it costs about 6× the
    verification rate.** ML-DSA-65 stays activation-gated and does not replace
    Ed25519; this measurement only prices a future PQ migration. The same
    standalone target, `bench/crypto-verify/` with `--features pq`, measures the
    real `Transaction::verify` path with a single-authorization ML-DSA-65 policy
    on the 4C/8T desktop, OpenSSL 3.5+, median of three, two sessions. At 4,096
    transactions: raw ML-DSA-65 verification is 188.9 µs/signature on one thread
    (5.29k/s) and 52.7–52.9 µs/signature on four (18.9–19.0k/s); the full
    transaction path is 190.9–195.3 µs/signature on one thread and 50.4–54.0
    µs/signature on four (18.5–19.8k/s). Same-session Ed25519 controls: 41.4 µs
    individual on one thread and 16.9 µs on four; 8.9 µs/signature for the batch
    path on four. ML-DSA raw is therefore 4.6× individual Ed25519 on one thread
    and 3.1× on four, but the current default is batch verification: the full
    ML-DSA path is 5.7–6.1× the Ed25519 batch cost per signature, or a ~6× lower
    per-validator verification ceiling (~18.5–19.8k vs ~112–122k tx/s) before
    the larger wire and state costs. ML-DSA has no batch equation, and
    `batch_candidate` accepts only Ed25519, so the ~2× batch factor disappears.
    Signing is 1.06–1.16 ms/signature, 5.6–6.1× verification; that is a wallet
    cost, not the validator bound. Sizes: public key 1,952 B, private key 4,032
    B, signature 3,309 B, encoded transaction 3,481 B; a 1,000-transaction batch
    carries ~3.3 MB of signatures, and each account key adds ~1.9 kB to state.
    The ~6× chain TPS impact and the wire/state cost are modeled from the
    measured crypto and sizes, not chain-level measurements. No registry
    activation, default change, or consensus change is made; the workspace
    default and gate do not enable `pq-testnet`.

32. **A validator-set change crosses one epoch boundary without breaking
    finality; at four validators its latency cost is inside run noise.** The
    prototype adds or removes exactly one identity per epoch, keeps the new
    set's fault budget at least as large as the old one, and requires any old
    and new quorum to intersect by more than the old fault budget. The old set
    signs the certificate that activates the new set. The finality harness ran
    100 samples, 1 tx/batch, 3 runs per cell, on the AMD Ryzen 7 6800U, 8 cores
    / 16 threads, with a 50-round epoch, so the change lands at round 50. All 30
    runs finalized 100 of 100 samples on every node, with 0 conflicts, 0
    rejected batches, and agreement inside each run; state roots differ across
    runs as expected. At zero delay, submit → certified p50 for add 4→5 was
    15.63 ms against a 15.16 ms control (+3.1%), and remove 5→4 was 14.57 ms
    (−3.9%). At 25 ms one-way delay with 5 ms jitter, the same cells were 126.13
    and 126.46 ms against 125.25 ms (+0.7% / +1.0%). The boundary is visible in
    the small subset of samples whose vertex is before round 50 and whose
    certificate is after it: 17.72 ms against 13.57 ms before at zero delay,
    and 191.73 ms against 123.54 ms in two of three 25 ms runs (the third was
    128.90 ms); one removal run had no boundary sample. That is a one-round
    wait, not a stable percentile. The added validator authored 62–150 vertices
    after the boundary; the removed validator authored exactly 50 (rounds 0–49)
    and stopped, which pins the boundary. At n=10 zero delay, add 10→11 moved
    p50 35.89 → 45.62 ms, p95 84.25 → 180.37 ms, and p99 103.91 → 252.95 ms,
    but one of three runs carried a 484.12 ms p99 and 31 rounds against 11 in
    the other two. At 25 ms the same cell was 145.94 → 133.54 ms p50, 264.88 →
    253.93 ms p95, and 349.63 → 288.84 ms p99, so the zero-delay tail is local
    contention/catch-up, not a network effect. This is not a committee-scaling
    curve and not a TPS lever (findings 28–29); it is the first measured
    evidence that the committee can change without losing finality. The change
    is still a harness parameter, not an authorized on-chain record; the added
    node is online and passive before the boundary, so a cold join/sync is not
    measured, and the prototype holds one transition per schedule. The full
    gate is green on the measured tree (353 tests default, 354 with all
    features).

33. **A validator that was not online from genesis can cold-join at the boundary
    from a peer's committed snapshot, and the aggregate finality p50 does not
    move.** The prototype starts the added validator only when validator 0
    reaches round 50. The snapshot carries the peer's committed order, its last
    built header, the next decision round, and the vertices/batches/headers.
    The joining node verifies every record, adopts the order and pacemaker
    cursor, applies the prefix batches in that order, checks
    dag_root/state_root/applied, and then authors and votes live. The first
    attempt re-decided the prefix from a partially received DAG and missed eight
    empty vertices; adopting the peer's order fixed it. Measured on the AMD
    Ryzen 7 6800U, 8 cores / 16 threads, in-process mesh, 100 samples, 1 tx/batch,
    epoch 50, change at round 50, median of 3 runs: all 12 control/cold runs
    finalized 100 of 100 on every live node, certified 100 of 100 on the
    submitter, and agreed on order, state, and headers with 0 conflicts and 0
    rejected. At zero delay, cold join submit → certified p50 was 15.11 ms
    against 14.92 ms for the control (+1.3%), p95 23.71 vs 22.28 (+6.4%), p99
    28.03 vs 25.89 (+8.3%). At 25 ms one-way delay with 5 ms jitter: p50 125.46
    vs 125.47 (0.0%), p95 191.09 vs 193.50 (−1.2%), p99 213.78 vs 224.65
    (−4.8%). Catch-up, median of three: 36.07 ms and 143,169 serialized bytes at
    zero delay (197 vertices, 45 batches, 44 headers, 189 commits, 49 rounds),
    and 50.04 ms and 138,641 bytes at 25 ms (197 vertices, 50 batches, 43
    headers, 189 commits, 49 rounds). The added validator authored 111–119
    vertices at zero delay and 62–63 at 25 ms; its certified header and head
    matched the existing nodes, while its header count was lower because it
    adopts the prefix instead of rebuilding every prefix header. The history
    handoff is in-process and the byte figure is the serialized size, not a TCP
    transfer; the snapshot still carries the full history, not a state snapshot
    plus tail, and the next milestone is that smaller snapshot over a real
    transport. The harness prints a live-sample count that includes prefix
    samples committed after replay; the claim uses the 100-of-100 line. The full
    gate is green (fmt, clippy, default and all-features tests).

34. **A state snapshot plus the DAG tail cuts cold-join transfer and catch-up
    by about 6× and 14–20×, and finality does not move outside the run spread.**
    The second cold-join milestone replaces the full history with the encoded
    account state at a trusted header, the committed order prefix, and the
    vertices, batches, and certified headers above a DAG floor. The joining
    node decodes the state, checks its root against `state_root`, checks the
    prefix against `dag_root`, seeds the order and pacemaker cursor, prunes at
    the floor, and verifies the tail. Measured on the Intel i7-4790K, 4 cores /
    8 threads, in-process mesh, 100 samples, 1 tx/batch, epoch 50, change at
    round 50, 12 runs with full and snapshot alternated in one session, median
    of 3: at zero delay, snapshot catch-up was 2.13 ms and 22,612 serialized
    bytes against 41.55 ms and 143,041 bytes for the full history (6.3× fewer
    bytes, 19.5× faster); at 25 ms one-way delay with 5 ms jitter, 4.78 ms and
    20,827 bytes against 67.46 ms and 136,667 bytes (6.6×, 14.1×). The state is
    450 bytes; the committed order prefix is 13.3–13.8 KB and is now 60–65% of
    the snapshot; the tail is 6.7–10.9 KB over 13–16 vertices and 1–4 batches.
    The floor was 44–45 in every snapshot run. Submit → certified p50/p95/p99
    moved −5.5%/+11.6%/+7.2% at zero delay and +0.3%/+4.5%/+1.0% at 25 ms; the
    zero tail is inside the run-to-run spread, the 25 ms row is unchanged. All
    12 runs finalized 100 of 100 on every live node, certified 100 of 100 on the
    submitter, agreed on order, state, and headers, with 0 conflicts and 0
    rejected. The handoff is still in-process and the byte figure is the
    serialized size, not a TCP transfer; the anchor is trusted by height and
    hash, with its quorum certificate verified when the peer had it. The order
    prefix is the remaining cost: `dag_root` commits every commit from genesis,
    so a Merkle frontier or a different commitment is the next lever, not a
    larger committee (finding 39 implements the frontier). The floor rule is a
    prototype (two-round margin, round 0 never pruned, whole-DAG fallback when no
    positive floor is safe). The first
    measurement counted queued payloads from genesis (42 batches); filtering to
    the payloads the tail executes changed it to 1–4, so the byte model reflects
    the transfer. The full gate is green on the measured tree (355 tests
    default, 356 with all features).

35. **A restarted validator reconnects and catches up without stalling finality.**
    An outbound link is rebuilt after a drop, the frame that failed mid-write is
    retried on the new socket, and the last 1,024 shares are replayed to a peer
    that returns. A share whose height below it is not certified waits for the gap
    instead of being applied out of order, and shares older than the window are
    dropped. This closed a permanent stall: shares are produced once and were
    never repeated, so one lost share stopped that node's finality. Measured on
    four loopback processes on the Intel i7-4790K (4 cores / 8 threads): a node
    stopped for 10 s resumed with the observer's head 625 → 1,105 and committed
    2,819 → 4,751, 0 conflicts. A full restart from the store put node 2 at head
    1,686 against 1,686 and committed 7,887 against 7,890, 0 conflicts. A signed
    transfer sent after recovery finalized in 106 ms; all four nodes reached
    head 1,898 with state root `86387ef2bd72`, one applied transaction, 0 conflicts,
    and a verified commit proof; `karsa audit` on the recovered store re-derived
    3,053 of 3,053 heights. The replay window is 1,024 shares, about 15 s at this
    machine's certificate rate, so a longer outage needs the snapshot resync in
    finding 36. Recovery is not instant: after a 10 s outage the returning node
    was still at 1,487 against 2,020 after a 35 s run.

36. **A store that already has history moves forward by adopting a peer snapshot.**
    `--sync-from-peers` fetches a snapshot over TCP, verifies the anchor's quorum
    certificate, state root, and `dag_root`, and adopts it only when its height is
    above the stored certified head. The anchor, state, order prefix, floor, and
    tail are written to `live.snapshot`, so the next restart resumes from it
    instead of replaying history the node never had. Measured: a node at stored
    head 552 adopted a peer snapshot at height 1,068 and reached head 1,131 against
    1,130 on node 0, with commit root `2517def7…` and 0 conflicts. The next restart
    on the old store plus `live.snapshot` had all four nodes at head 2,636, commit
    root `c86d8123…`, 0 conflicts. A peer snapshot below the stored head is refused
    after 15 s rather than moving the store backwards. The snapshot carries a
    Merkle frontier for the prefix below its floor and only the tail above it
    (finding 39), so a join no longer transfers the full order. On the
    pruning run, a node that had history to height 1,169 adopted a peer snapshot
    at height 1,862 (floor 1,346), pruned the 24 old vertices and 2 headers it
    still held, and ended on the same commit root `b98f42ae…` as the three nodes
    that stayed up. A restart then restored all four from checkpoints around
    2,487–2,504 and reached head 3,083, commit root `755d22f0…`, 0 conflicts;
    `karsa audit` on the resynced store re-derived 58 of 58 heights on both roots.

37. **A checkpoint bounds the replay tail, and its floor bounds the history files.**
    `--checkpoint-every N` writes `live.snapshot` every N certified heights (it
    needs `--execute` and `--store`); a head whose floor is not safe to prune is
    skipped. Each successful checkpoint also prunes: vertices at or below the
    snapshot floor, payloads no kept vertex names, and certified headers below the
    anchor height. The anchor's own header is kept, so a restart and `karsa audit`
    still see the certified height they resume above. A payload named by a kept
    vertex stays, because that vertex may still be committed after the restart.
    The interval is measured from the checkpoint or head the run resumed at, so a
    large N does not fire a checkpoint immediately after a restart.
    - Single process, 200 rounds, every 64 heights: 8 writes at heights 64–96 and
      155–160; a restart from checkpoint 129 restored order 797 to head 176, with
      all four nodes agreeing.
    - Four-process devnet, every 1,024 heights: a restart resumed from checkpoint
      1,405, wrote 1,934, and all four nodes ended on commit root `28de7f08…`.
    - Pruning run, every 128 heights, 35 s: 13 checkpoints, each dropping about
      700 vertices, 150–175 headers, 0–1 batches, and 400–480 kB; after the last
      checkpoint the logs held 6.5 kB of vertices, 513 B of headers, and 0 batches.
      A restart from checkpoints 2,197–2,310 replayed the tail to head 3,802 on all
      four nodes, commit root `2042ff83…`, state root `20c162bd…`, one applied
      transaction, 0 conflicts.
    - `karsa audit` re-derived 235 of 235 heights on both `state_root` and `dag_root`
      above a checkpoint 235 heights behind the head; a store checkpointed at the
      head reported 0 of 0 heights and verified the anchor certificate instead.
    The checkpoint file is now bounded: `live.snapshot` v2 stores the state, the
    peaks of the prefix below the floor, and only the tail above it (finding 39).
    At head 3,802 the full-order format was 1.36 MB; the compact snapshot was
    1.4 KB at head 3,972. The floor rule is
    the snapshot one (two-round margin, round 0 never pruned, whole-DAG fallback).
    Whole-payload nodes prune with `min_shards = 0`; `--shard` nodes pass 1.
    Restart from checkpoint is now covered by an automated in-process test:
    four nodes author 30 rounds with `checkpoint_every = 2`, drain for two seconds
    so the committed prefix catches up, assert that no vertex below the floor and
    the anchor header survive, restart from the same stores, and audit the pruned
    store. The store prune, the checkpoint cadence, and the two config checks also
    have unit tests.

38. **A four-validator devnet is a script, not an in-process flag.**
    `scripts/devnet.sh` starts one `karsa live --node-index i` process per
    validator from a real home, writes the genesis once (the init path refuses
    when `keys.json` exists), registers each validator in `peers.json`, sets the
    store, RPC, snapshot, and checkpoint paths, and writes one log per node.
    `RESET=1` wipes the directory; the default checkpoint is every 1,024 heights.
    Cold: all four nodes completed, commit root `4d4aec7c…`, state root
    `690cb32b…`; a restart restored all four, commit root `d95a3702…`; `karsa
    send --home` submitted a signed transfer on chain `b920e1221bd1`, finalized
    in 106 ms, and the commit proof verified. This is a devnet, not a deployment:
    every process runs on loopback under one user, and `peers.json` is
    informational because the live mesh still derives endpoints from
    `--port-base`. `WIRE_PROTOCOL` is 5 since finding 41, so an old and a new
    node refuse each other at the handshake. The gate is green on this tree
    (395 tests default, 396 with all features).

39. **A Merkle frontier bounds the checkpoint and the snapshot transfer.**
    A header's `dag_root` commits every entry from genesis, but entries below the
    DAG floor are already applied and never replayed. `CommitFrontier` keeps those
    entries as the perfect-subtree peaks a binary counter would carry; `Dag` holds
    the prefix peaks plus the committed tail above the floor, and
    `Finalizer::build_ready_with_prefix` roots each header at
    `prefix + tail[..len]`. `live.snapshot` v2 and the TCP snapshot carry
    `order_len`, the prefix peaks, and the tail; a v1 snapshot is still read as an
    empty prefix with the full order. A tail leaf's commit proof is built from the
    peaks, so a transaction submitted after a restart still has one; leaves below
    the retained prefix have none, because the node no longer holds them.
    Measured on the four-process devnet, checkpoint every 128: `live.snapshot`
    stayed at 1.3–2.0 KB up to head 1,415 and was 1.4 KB at head 3,972, against
    1.36 MB for the full-order format at head 3,802; per-node disk ended at
    8–104 KB. A restart from the compact checkpoints was 4/4 with the same state
    root and one applied transaction; the transfer sent after the restart
    finalized in 103 ms and its proof (leaf 11,790 of 11,791) verified against
    `dag_root`. `karsa audit` re-derived 111 of 111 heights on both roots. A fresh
    node joined over TCP from a compact snapshot at height 3,986 (floor 4,443, 21
    tail vertices), matched the mesh on commit root `d49f51d7…`, restarted from
    its own compact checkpoint (5,452) with one applied transaction, and audited
    3 of 3 heights. `WIRE_PROTOCOL` is 5 since finding 41, so an older node is
    refused at the handshake. This closes the order-prefix cost that findings 34
    and 37 carried; the audit still starts above the anchor, and an old leaf below
    the floor cannot be proven.

40. **Account state grows with the genesis account set, not with history.**
    The state field of every `live.snapshot` on disk was 212 bytes at four
    accounts, at rounds 147–7,409, in both the v1 full-order files (up to 1.5 MB)
    and the v2 frontier files (1.4–2.3 KB): the order history grew, the state
    field did not. A 32-byte account id encodes to 52 bytes, so 0, 4, 64 and
    1,000 accounts encode to 4, 212, 3,332 and 52,004 bytes. A 16-account state
    applied 3,200 transfers and encoded to the same 836 bytes before and after.
    A transaction changes a balance and a sequence in place and cannot add a map
    entry; `apply_one` rejects an unknown sender and recipient, and only the
    genesis credit adds accounts. The account set is closed, so the state is
    `O(accounts)`, not `O(history)`. The remaining per-account costs are the tree
    rebuild at each applied prefix, the 256-entry state windows, and a tree per
    account proof; no sparse or reference-counted state is justified until
    account creation exists. Pinned by
    `the_state_encoding_grows_only_with_the_account_count` and
    `the_state_encoding_does_not_grow_with_history`.

41. **Transactions gossip on the peer link, and status is execution-wide.**
    `Message::Tx` carries one canonical envelope; a local `POST /tx` queues the
    transaction locally and puts the envelope in a gossip outbox that the node
    loop drains to every peer each tick. A receiver re-runs the submission checks
    (chain, policy, signature, replay, slot reservation) before admitting it to
    its mempool, and never re-gossips a received envelope. Executing the committed
    order updates records for transactions the node did not author: the id is
    derived from the batch, the outcome and vertex are recorded, and an applied
    copy wins over a later duplicate the sequence rule rejects. Finality uses the
    same pending-order queue, so every node reports the same finalized height and
    commit proof. `WIRE_PROTOCOL` is 5.
    - Four-process devnet: a transfer submitted to node 0 finalized in 114 ms; all
      four nodes reported `finalized` at height 1,293 with the same state root and
      a verified proof (leaf 5,817 of 5,820). A second transfer submitted to node
      2 finalized in 180 ms; all four nodes reported height 2,394 with a verified
      proof. At shutdown: commit root `973718f3…`, state root `2456fc21…`, 2
      applied, 6 rejected, 0 missing payloads, equal balances and sequences.
    - The 6 rejects are the duplicate cost: every node authoring from its own
      mempool can include the same transaction in the same round. The batch digest
      is content-addressed, so it is one payload, but every vertex naming that
      digest executes it again and the sequence rule refuses the copy. The applied
      copy is the one reported and proved.
    - Restart from checkpoints 2,592–2,692 restored 1 applied transaction and order
      12,152 with 0 tracked records (they are in memory only); a transfer submitted
      to node 1 after the restart finalized in 110 ms, all four nodes reported
      height 4,256 with a proof, and the mesh ended on commit root `42726e73…`,
      state root `7f33d240…`, applied 2, rejected 3, 0 missing payloads. Gossip is
      best-effort (no repair for a dropped `Tx`), and a late envelope cannot create
      a record after its sequence advanced. Pinned by the wire round-trip, the
      duplicate/foreign-chain gossip tests, the remote-batch finality test, the
      later-duplicate-keeps-applied test, and the stale-rejection test.

42. **A finalized transaction carries its commit proof across the pruned prefix.**
    When a certified header finalizes a tracked transaction, `RpcCore` captures
    the commit proof while the leaf is still inside the retained order: the
    vertex, the Merkle path, and the header's `state_root` and `dag_root`.
    `/tx/{id}?proof=1` returns that witness when the live order can no longer
    build the proof, so a checkpoint pruning the leaf leaves status, roots, and
    proof intact. A later applied copy clears the witness because it may point at
    a different order position.
    - Four-process devnet, checkpoint every 64: a transfer finalized at height
      1,389, vertex round 1,560, leaf 6,239 of 6,240, proof verified at finality.
      After checkpoint round 2,387 (floor 2,385, prefix length 9,542), the leaf and
      its vertex were below the retained prefix. The same request still returned
      the 8-step proof, and recomputing the root from the returned vertex and
      siblings gave `73d1c93b0739…`, equal to `dag_root`. The four nodes ended on
      commit root `64d1fc13…`, state root `20c162bd…`, 1 applied, 3 rejected.
    - The witness is memory-only and belongs to the record: a restart loses it with
      `/tx` history, and it covers transactions this process tracked, not every old
      leaf. Pinned by `a_finalized_proof_survives_the_order_prefix`, which clears
      the retained order, the prefix, and the certified-header window before asking
      for the proof.

43. **The devnet is an automated integration test.**
    `cmd/karsa/tests/devnet.rs` generates a home with `karsa genesis --init`,
    starts four `karsa live --node-index i` processes over a free loopback port
    block with `--execute`, `--checkpoint-every 16`, and a 25 s lifetime, and
    waits until every node has certified two heights before submitting.
    `karsa send --wait` then submits a signed transfer through node 0, and the
    test reads `/tx/{id}?proof=1` on each node, requiring `finalized` and a commit
    proof, plus `/status` with `applied_txs >= 1`, `tracked_transactions >= 1`, and
    0 conflicts. All four must agree on the finalized height and state root.
    `Devnet` kills and reaps its children on drop, and a failure prints each node's
    log.
    - Passed three runs in a row standalone in 1.35–1.90 s, and the full gate
      passed twice (default and all-features); no child process or temp directory
      survives. The readiness gate requires two certified heights per node; the
      earlier version checked only node 0's round and timed out on node 2 in the
      gate. Head roots are not compared because nodes certify at their own pace;
      the test compares the header that finalized the transaction instead.
    - Port discovery binds a contiguous block, drops it, and starts the processes,
      so a port stolen in that window fails the test. This is the cold devnet;
      fault and restart probes remain manual, while the in-process restart test
      covers the checkpoint path.

44. **One validator authors each transaction, with a fallback lease.**
    `RpcCore` maps a content id to an owner by reading its first eight bytes as a
    little-endian `u64` modulo the validator count. `take_batch` selects only the
    transactions this node owns; every node computes the same owner, so a gossiped
    transaction gets one normal author and the duplicate batches of finding 41
    disappear. If the owner has not authored within 2 s
    (`OWNER_FALLBACK`), any node may take the transaction, so a dead owner cannot
    strand it; a returned batch restarts the clock, and each mempool copy carries
    its own `queued_at`.
    - Four-process devnet, checkpoint every 64, two transfers submitted to nodes 0
      and 2: both finalized (100 ms and 180 ms), and the owner was node 3 for both.
      At shutdown all four nodes ended on commit root `f0fe5fa8…`, state root
      `2456fc21…`, applied 2, **0 rejected**, 0 missing payloads. The same two
      transfers under finding 41 cost 3 rejected each.
    - The fallback is covered by
      `only_the_owner_authors_a_transaction_before_the_fallback`. A live attempt
      that killed node 0 before submitting (the transaction owner was node 3)
      never certified a new height after the kill: head stayed at 1,559, because
      the dead node's last vertices were missing from the survivors and no new
      share reached a quorum. That is a vertex-delivery gap, not ownership; testing
      the takeover live needs a kill that leaves the mesh certifying.

## Build order

| Stage | Crate | State |
| ----- | ----- | ----- |
| Registry, encoding, domain | `crypto` | done |
| Ed25519 scheme + backend | `crypto` | done |
| ML-DSA-65 scheme + ACVP vectors | `crypto`, `karsa acvp` | done |
| Envelope + authorization policy | `tx` | done |
| Validator key schedule | `validator` | done |
| HTTP node | `karsa node` | done |
| DAG and throughput benchmarks | `karsa dagbench`, `karsa certify`, `karsa bandwidth`, `karsa loadtest` | done |

The normative spec is `docs/crypto-registry.md` (local, unpublished). Where the
code and the spec disagree, the spec wins.
