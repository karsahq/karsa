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
| `cmd/karsa/` | Rust: single CLI with `genesis`, `config`, `node`, `sample-tx`, `demo`, `acvp`, `dagbench`, `loadtest`, `live`, `dagsim`, `chain`, `net`, `persist`, `audit`, `migrate`, `sigbench`, `sweep`, `shards` |
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
  `karsa migrate` runs it end to end. PQ is registered but not active: the default
  chain is classical, and switching a validator to ML-DSA is a change to one
  `ValidatorKey`. Overlapping keys are not supported yet — a vertex carries one
  signature.
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
  A node holding no shards keeps every payload, and the report says so.
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
  nodes: they receive everything, store everything, and never sign.
- `karsa peers`: the network half, in `peers.json` beside the other two. Genesis says
  who the validators *are*; an address is operational data that changes when a
  machine moves, so it never goes in the file every node must agree on. `--add
  id@host:port` and `--remove id` grow and shrink the list, and the listing marks
  each entry as a founding validator (present in genesis) or known-only, which is
  a legitimate state for an RPC or sentry.
- `karsa genesis`: the file every node must agree on, in JSON because it is a
  generated consensus artifact rather than a hand-edited preference. Validators,
  their keys, the founding accounts with their policies, and the key-epoch length
  are all explicit; unknown fields, duplicate ids, unknown algorithms, wrong
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
  the demo seeds, so `karsa chain 4 --rounds 4 --home DIR` and `karsa live
  --validators 4 --home DIR` run without extra setup. The node keeps **no chain
  identity of its own**: the genesis beside it is the only one, so there is nothing
  to drift from it.
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
- 278 tests in the default workspace build, including RFC 8032 vectors, ML-DSA-65
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
