# Decision log

Every entry is a decision that would be expensive to reverse, written down when it
was made rather than reconstructed later. "Status" is honest: *decided* means the
code follows it, *proposed* means it does not yet.

The normative spec is still `crypto-registry.md`; where this file and the code
disagree, whichever is newer wins and the other is the bug.

## D1 — Implementation is not activation

**Decided.** PQ algorithms are registered and compiled, but a chain is classical
unless `pq-testnet` is on. Compiling a backend must never silently change what the
protocol accepts.

*Why:* a build flag that changes consensus is a fork waiting to happen.

## D2 — The default chain is classical; PQ is a planned migration

**Decided.** No PQ by default. The design must make the later switch cheap, and
that is measured by whether a rotation crosses an epoch boundary without a restart.

*Why:* PQ signatures cost 3.3 KB and 193 µs per verification against 64 B and
40 µs. Paying that before the algorithms are settled buys nothing.

## D3 — Key rotation is atomic at an epoch boundary

**Decided.** Exactly one key is active per validator per epoch. No overlap window.

*Why:* a vertex carries one signature. A hybrid window would need every active key
to sign, which means multi-signature vertices — a wire-format change. Pretending to
overlap while accepting one key would make the chain only as strong as the weakest
active key, which is worse than an honest atomic switch.

*Revisit when:* multi-signature vertices exist.

## D4 — Consensus objects carry no key ids

**Decided.** A vertex and a certificate name no key; the key is resolved from the
schedule at the epoch.

*Why:* it makes rotation invisible to the wire format, and removes a whole class of
"which key signed this" ambiguity.

## D5 — Uncertified DAG: one signature per vertex

**Decided.** Votes are references. No per-round certificate object.

*Why:* measured at n=100, a per-round certificate costs ~331 KB under ML-DSA
against ~3.5 KB for a vertex — 33× for the same ordering guarantee. This is the
Bluestreak/SSFS principle, adopted early.

## D6 — Absence is not evidence

**Decided.** A leader is skipped only on an *observed* supermajority of non-votes,
never because votes have not arrived.

*Why:* a partitioned node must not finalise a different slot than the majority.

## D7 — Indirect skip requires the reference rule

**Decided.** Shipped together, and the rule is enforced by `Dag::insert`.

*Why:* "not reachable from a committed anchor" only implies "never committable" if
every vertex references a quorum of the previous round.

## D8 — The pacemaker has no clock

**Decided.** Ticks are logical events injected by the driver. A timeout is a
signal to request missing data, never a decision.

*Why:* reproducibility. A wall clock would make every simulated run different and
every bug unreproducible.

## D9 — Anchors are quorum-backed, not committed

**Decided.** Emission happens only in cursor order.

*Why:* the first version earned anchors by committing later leaders ahead of the
cursor, and two nodes with the same final DAG committed different sequences.
`crates/net` caught it; the fix is that probing records an anchor without emitting.

*Cost:* the pacemaker is slightly more complex, and `EpochSchedule`-style helper
types appear where a bare number would do.

## D10 — Finality is one certified header per commit

**Decided.** Not per round.

*Why:* the same certificate problem, at a frequency a small constant lower. Under
PQ the number to watch is commits per second, not rounds per second.

## D11 — Pruning is snapshot-plus-floor, and it costs two properties

**Decided.** `Dag::set_floor` drops everything at or below a snapshot; the
pacemaker restarts above it.

*Cost, stated:* a pruned node cannot re-validate the reference rule across the
boundary, and cannot reproduce a historical `dag_root`.

*Why we accept it:* retention policy moves node storage by 8,700× between "1 hour"
and "forever". Leaving it out was a worse bug than either limitation.

## D12 — Storage work targets the payload, not the metadata

**Decided.** Bluestreak-style reference compression is **not** the next storage
project.

*Why:* measured at n=100 with ML-DSA, consensus metadata is 552 KB/round dense
against 350 MB/s of payload at one round per second — 0.1%. And compressing
references buys 1.6× under PQ, not the 10.2× it buys under Ed25519, because the
signature dominates.

*Where it does matter:* bandwidth and DAG memory when the round rate is high, and
any classical chain.

## D13 — Parallelism is the first speed lever

**Decided.** Transaction verification is parallelised in the node before anything
subtler is attempted.

*Why:* measured 22.5k tx/s on one core and 90.5k on eight hardware threads — 4×
for no protocol change. No encoding or consensus change can match that per unit of
risk.

## D14 — Committee size is a sweep parameter, not a constant

**Decided.** Defaults drop from 100. Benchmarks run 2, 4, 6, 8, 10 first, then 20,
40, 100.

*Why:* node count is a security and latency decision, not a throughput one. A
committee of 60 and a committee of 100 differ by 1.68× in metadata and by nothing
in payload.

*Caveat:* below n=4 the quorum is everyone, so `f = 0`. Those rows exist to show
the floor, not to recommend it.

## D16 — Launch assumes 10, 20, or 30 validators

**Decided.** Defaults and benchmarks assume a launch committee in the tens. A
hundred is a stress case, not a plan. Hundreds may never happen, and if the
economics of the chain do not form, they certainly will not.

*Why:* a committee size follows how many independent operators are willing to hold
stake and run infrastructure, not the other way around. Setting n=100 on paper when
three entities would run ninety of those nodes is worse than n=10 honest ones.

*Consequence:* metadata at n=30 is 100 kB/round against 343 kB at n=100 — 3.4×
cheaper, and the `O(n²)` term is not yet the problem. Design work that only pays
off above n=100 is deprioritised, which is most of what a large-committee design
buys.

## D15 — Erasure-coded storage, model B: shard forever, payload for a window

**Decided.** A node keeps the erasure-coded shard permanently and the full batch
payload for a window. `Store::prune_below(round, min_shards)` is the closing edge,
and it checks one safety rule before deleting anything:

> a payload is dropped only when nothing in the retained tail names it **and** this
> node already holds at least `min_shards` shards of it.

A node that holds no shards therefore keeps every payload it sees. Deleting data
it alone holds would be silent loss, not pruning; `min_shards = 0` is only correct
for a node outside the erasure set.

*Measured:* `karsa persist` now writes one shard per batch, prunes, and replays to
the same state root — 25 batches in, 12 payloads dropped behind the window, 0 held
back, 9.2 kB freed, shard log intact afterwards. Three store tests cover the rule:
dropped when sharded, held when not, held while its vertex is still in the tail.

*The number that decides the window.* Sharding cuts storage 32×; the window is a
duration, so it does not scale with sharding:

| Window at 1k TPS (3.5 kB/tx) | Full payload cost | Total with a 32/48 shard (9.45 GB/day) |
| --- | --- | --- |
| 1 hour | 12.6 GB | 22.1 GB/day |
| 1 day | 302 GB | 311 GB/day |

*Consequence:* a day-long payload window erases the benefit of sharding — the
window, not the shard, dominates. The window is measured in hours, because it
exists to serve a peer that is behind, not to serve history. History is served from
shards plus peers, which is the data-availability path this decision deliberately
does not invent.

*Why it cannot outlive the vertex window.* Once vertices are pruned, nothing on
disk records which round a batch belonged to, so payload cannot be aged out later
than metadata. That is a property of the append-only log, not of the policy;
keeping payload longer would need a digest→round index.

Alternatives considered: *A* shard-only (cheapest storage, no history to serve) and
*C* erasure-coded history (cheapest, most complex). B is the one that is measurable
without inventing a new data-availability protocol.

## D17 — Node parallelism is not the TPS lever

**Decided.** The node is not optimised further for admission throughput.

*Why:* measured with `karsa loadtest` at 16 connections: 55,073 tx/s, and raising
concurrency to 32 moves it to 58,290 — the async runtime already spreads
verification across cores. Moving verification to `spawn_blocking` made it
**worse** (49,045), because the blocking pool adds a hop and oversubscribes four
physical cores.

*Consequence:* admission at ~55k tx/s is already 2–50× above a realistic chain
target of 1–10k TPS, so it is not the bottleneck for anything the chain will do
soon. The remaining gap to the 90k verification ceiling is HTTP, hex, and JSON, and
buying it back would not move a single block.

## D18 — Measured committee scaling, n = 2…100

**Recorded.** `karsa sweep --sizes 2,4,6,8,10,20,30,40,60,100 --ticks 32`, one
seed, 32 ticks, no crashes, link latency 1 + 0..=2:

| n | f | quorum | held | delivered | committed | same DAG | same order |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 0 | 2 | 31 | 31 | 27 | yes | yes |
| 4 | 1 | 3 | 66 | 198 | 56 | yes | yes |
| 6 | 1 | 5 | 76 | 380 | 60 | yes | yes |
| 8 | 2 | 6 | 109 | 763 | 88 | yes | yes |
| 10 | 3 | 7 | 140 | 1,260 | 119 | yes | yes |
| 20 | 6 | 14 | 262 | 4,978 | 217 | yes | yes |
| 30 | 9 | 21 | 390 | 11,310 | 325 | yes | yes |
| 40 | 13 | 27 | 529 | 20,631 | 437 | yes | yes |
| 60 | 19 | 41 | 780 | 46,020 | 471 | yes | yes |
| 100 | 33 | 67 | 1,300 | 128,700 | 1,068 | yes | yes |

*Deliveries are exactly `held × (n−1)`:* quadratic in total, linear per node — the
same `(n−1)/n` result `karsa bandwidth` derives, now confirmed by simulation.

*Commit progress saturates before agreement breaks.* Commits per tick roughly
double from n=4 to n=10, keep rising to n=40, then flatten (n=60 committed 471
against n=40's 437 at the same tick count) while deliveries more than double. A
bigger committee buys safety margin (`f`) and nothing else, which is exactly D16.

*Runtime:* 1.5 s for n≤10, 9.5 s for 20+40, 60 s for n=100 alone. The simulation
does ~79,200 signature verifications at n=100; that cost is the finding, not a
reason to shrink the test.

## D19 — Auditability is a replay, and pruning narrows it

**Decided.** `state_root` and `dag_root` are linked by a replay verifier, not by a
proof. `karsa audit` re-derives both from the stored data and compares them with
the certified header.

*What it establishes:* for each audited height, the vertex set whose Merkle root is
`dag_root` is exactly the set that, applied in the commit order the DAG reproduces,
produces `state_root`. That is the gap D15 and the header design left open.

*What it does not establish:* anything a light client can use. The verifier needs
the vertices and the batches and pays the cost of producing the chain, so the claim
is checkable but not small. A zk or fraud proof is the other half, and D19 does not
claim it.

*The consequence worth recording:* pruning and auditability trade directly. A
full-history store is re-derived from genesis — `karsa persist --keep-history`
produces one, and the audit reports 7 of 7 heights matched on both roots. A pruned
store is audited only above its snapshot: 4 of 4 state roots matched, `dag_root`
unchecked, and the command says so instead of claiming the prefix it no longer
holds. So the retention window from D15 is also the audit window, and lowering it
to save disk lowers what a node can prove about its own history.

*Measured:* certificates for every stored height verify without payload (so header
finality survives pruning), a quorum that certifies a wrong state root is caught by
re-derivation, and the audit of a tampered store fails on the roots rather than on
the certificate — that distinction is a test.

## D20 — The transport is real, bounded, and has no drop policy

**Decided.** Vertices travel over TCP on loopback in the frame
`u32 body length || u64 sent-at nanos || canonical vertex bytes`, with one
listener per node and a full mesh. Each peer gets a bounded queue that the writer
**awaits**: when a reader cannot keep up, its sender slows down instead of losing a
vertex.

*Why no drop policy yet:* a vertex that is dropped is not retransmitted, so the
receiving node can never satisfy the reference rule for the next round and the
committee stalls — the failure is silent and permanent. Backpressure fails loudly
and costs throughput instead of safety. A real drop policy needs a repair path
(anti-entropy or periodic retransmission), which does not exist yet, so the honest
choice is the one that cannot lose data.

**Superseded by D22.** That reasoning held while there was no repair path. With
demand-driven repair the drop is a latency cost, not a loss, and vertices now drop
while payload still applies backpressure.

*The cost of that choice, recorded rather than hidden:* head-of-line blocking.
`karsa live --slow-ms 5` is the demonstration — one slow validator slows everyone,
which is exactly the problem payload sharding does **not** solve, because consensus
vertices are small and every node needs all of them.

*Measured,* loopback, one process, 4 cores / 8 threads, 21 rounds:

| n | links | frames | wire in | p50 | p90 | p99 | same commit root |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 1 | 42 | 11.0 kB | 0.20 ms | 0.30 ms | 0.35 ms | yes |
| 4 | 6 | 252 | 87.1 kB | 0.61 ms | 1.42 ms | 10.25 ms | yes |
| 6 | 15 | 630 | 284.6 kB | 0.81 ms | 2.12 ms | 10.14 ms | yes |
| 8 | 28 | 1,176 | 626.1 kB | 1.11 ms | 1.98 ms | 2.82 ms | yes |
| 10 | 45 | 1,890 | 1.2 MB | 1.70 ms | 7.40 ms | 40.36 ms | yes |

`frames = n (n − 1) · (rounds + 1)`, because every vertex reaches every node.
p99 at n=10 is 40 ms on a machine with four physical cores shared by ten
validators, so it measures the CPU, not the wire.

*Out-of-order arrival is a transport property, not a bug.* The simulator delivers
in a fixed order; a socket does not. A vertex can arrive before the round it
references. The DAG's shape rule only requires a quorum of distinct previous-round
authors, so in these runs nothing was deferred — the quorum absorbed the
reordering. The defer-and-retry buffer exists for when it does not, and its high
water mark is printed rather than hidden.

*What this does not prove:* independent machines, encryption, handshake, peer
discovery, or retransmission. All nodes share one process here.

## D21 — Commit order is a function of the DAG, not of arrival order

**Decided.** The pacemaker derives its anchor from the DAG on every tick instead
of caching one, and takes an indirect decision only when that decision is already
forced by the data it holds:

1. **Lowest stable anchor.** An anchor may skip an intermediate round only when its
   own history *proves* that round's leader absent. A higher anchor that reaches a
   leader the lower one does not is never used, because it would make the sequence
   depend on which anchor a node happened to see first.
2. **No skip may race a commit.** `try_indirect_decide` commits the leader's
   history as a side effect, so it is called only when either the leader is not
   reachable from the anchor, or more than `f` voters are held. `max_faulty = n −
   quorum`, so holding more than that rules out a non-vote quorum by counting
   alone: non-votes would be at most `quorum − 1`.
3. **An unprovable walk waits.** If the ancestry check reaches a vertex this node
   does not hold, nothing is proved and no decision is taken. Previously that
   `MissingReference` escaped `Pacemaker::tick`, where `chain::settle` (used by
   `persist` replay and `audit`) treats it as fatal — a delivery gap would have
   looked like corruption.
4. **No second anchor.** The cached `anchor` field is gone. All decisions use the
   derived one, so the two cannot disagree; the only bookkeeping left is "a round
   ahead already has quorum support", which keeps the stall counter from firing
   while the DAG is still growing.

*Why this was needed:* on loopback with one node delayed by 5 ms per frame, two
nodes with the same final DAG committed the same vertices in different orders. The
same bug also killed nodes outright, because `live` treated a `missing_reference`
from commit as fatal — while the pacemaker's own documentation says that condition
means "the referenced vertex has not arrived".

*Evidence:* the regression test fails with the old `pacemaker.rs` and the new test
kept — `"a deferred indirect commit must not leave history behind"` — so the test
catches the bug rather than passing by construction. The deterministic paths are
unchanged after the fix: `karsa persist 4 --rounds 6` still produces state root
`16ac36b02532` and tail commit `e118cbed63f0`, the same values as before the
change, and `chain`, `net`, and `sweep` agree.

*Not proved:* the argument is that each decision is forced by the held DAG; it is
not a formal proof of convergence. Evidence is empirical (30/30 slow runs, n = 10
and n = 20) plus the rule above. A model check over small DAGs with adversarial
delivery is the next thing that would raise confidence.

## D22 — Drops are allowed, repair is demand-driven

**Decided.** The transport drops instead of blocking, and repairs from the DAG.

- Each peer has a bounded queue per direction. `try_send` never waits, so a node
  that cannot keep up loses frames instead of stalling its sender — and stops being
  everyone else's head-of-line problem.
- Repair does not retransmit blindly and is not anti-entropy. Two signals, both
  read from data the node already holds:
  1. **Dangling references.** A held vertex names a vertex this node lacks. The
     reference rule required a *quorum* of authors, not every edge, so some gaps are
     visible this way and some are not.
  2. **The blocking vertex.** When the commit walk stalls, `Dag::missing_history`
     returns the exact id it could not resolve. This catches the gaps that no held
     vertex points at.
- A want is an id, not a range: nothing is requested that a decision does not need,
  and a vertex nobody references is never fetched.
- **Control traffic has its own queue.** Wants and their answers go ahead of
  broadcasts. Sharing one queue is what made 39 of 84 wants time out under load
  while the messages they needed were stuck behind vertex spam.

*Why this replaces D20's "no drop policy yet":* D20 said a dropped vertex is never
retransmitted, so the committee would stall silently. That was true before there was
a repair path; now a drop is a latency cost rather than a loss. Backpressure is
still the right default for **payload** (a batch is large and every node must
execute it), but not for consensus vertices, where one slow peer should cost
throughput and not liveness.

*Measured,* n=4, 100 rounds, 2 kB socket buffer, one node delayed 5 ms per frame:

| queueing | dropped | wants | repaired | abandoned | authoring | same root |
| --- | --- | --- | --- | --- | --- | --- |
| shared control + data | 1,460 | 84 | 45 | **39** | 75.7 ms/round | yes |
| separate control queue | 19 | 28 | 28 | **0** | 28.9 ms/round | yes |

The shared-queue row is the important one: the root still matched, so a
convergence-only test would have called it a success while a third of the repair
traffic was silently giving up.

*Known limits:* `missing_references` scans every held vertex, so repair costs
`O(edges)` per sweep; a production node would keep a reverse index. A want that is
abandoned after eight retries is counted, not hidden, and there is no anti-entropy
pass to catch anything the two signals miss. Payload still has no repair path, which
is the next gap worth closing.

## D23 — The data plane rides the same link, and payload blocks

**Decided.** A vertex names a batch by digest, and the batch travels on the same
TCP link as a third frame kind. There is no separate data channel and no
certificate step: a vertex and its payload are two frames, and the receiver can
check the digest against what the vertex signed.

- **Payload is sent with backpressure, not dropped.** D22 drops consensus vertices
  because a missing vertex is visible to the reference rule and repairable by id.
  A batch is different: it is large, every node must execute it, and there is no
  payload-repair path yet. Losing one is expensive; waiting for a queue slot costs
  throughput, which is the cheaper failure.
- **The consequence is head-of-line blocking for payload**, deliberately: a peer
  that cannot keep up slows its senders. That is the trade D22 named, now
  observable in the same run that drops vertices.
- **Missing payload is detectable without trusting the sender.** At the end of a
  run every held vertex with a non-zero `payload_hash` is looked up in the store of
  batches; the count is printed and a non-zero value fails the run.

*Measured,* n=4, 30 rounds, 8 transactions per batch, no faults: 3,968 unique
transactions held per node set, 171 B per transaction received per node (a ~120 B
Ed25519 envelope plus batch and frame overhead), 508.5 kB of payload on the wire,
0 named batches missing. With a slow node forcing 9 vertex drops and 10 repairs in
the same mode: 2,624 deliveries, 130 B/tx, 0 missing, same commit root.

*Known limits:* execution is not run, so the numbers are transport cost and not
state cost. Payload has no repair path, so a payload lost by a crash is lost; the
only protection today is that it is never dropped on purpose. Batches are kept in
memory, not through `crates/store`, so on-disk bytes per transaction are still a
model rather than a measurement.

## D24 — A live run ends on a state root, not on a commit root

**Decided.** `karsa live --execute` applies the committed batches into an account
state and reports the state root alongside the commit root. Three rules make that
number mean something:

1. **Demo accounts are funded.** The chain demo starts every account at 1,000
   units, which is right for a handful of transactions and wrong for a throughput
   run: at 100 transactions per batch the fee alone exhausts it in a few rounds. The
   run credits a large balance first, so a rejection count is a signal about the
   code rather than about the fixture.
2. **The run waits for execution, not for a timer.** Applying costs a real signature
   verification per transaction, so the applied cursor lags the commit cursor by
   seconds at this volume. A fixed drain stopped halfway and reported "applied
   24,000" against a much larger committed set. The run now reports caught-up only
   when the commit cursor has been still for 50 ticks *and* the applied cursor has
   reached it.
3. **Agreement is checked on both roots.** A divergent state root fails the run even
   when the commit root matches, because applied order is the part execution sees.

*Measured,* n=4, 50 rounds, 100 transactions per batch, one process, 8 threads:

| Quantity | Value |
| --- | --- |
| Committed vertices per node | 188 |
| Transactions applied per node | 18,800 |
| Rejected | 0 |
| Payload on the wire | 169 B per transaction received, 10.3 MB total |
| State root | identical on all four nodes |
| Wall clock | 1.9 s (~10k tx/s per node, ~40k across four) |

*Known limits:* execution shares the process with the transport, so the four nodes
compete for the same eight threads; the per-node figure is therefore a floor, not a
capacity claim. Nothing is persisted, so these are memory numbers. Batches are
never pruned or sharded here — the storage model in D15 remains a model.

## D25 — Storage figures come from the store, not from a model

**Decided.** `karsa live --store DIR` writes every vertex and every batch it accepts
through `crates/store`, one directory per node, and reports the bytes that actually
landed on disk. A duplicate — a repaired or re-broadcast frame — is recognised
before the write, so retransmission does not inflate the measurement.

*Measured,* n=4, 50 rounds, 100 transactions per batch: **172 B on disk per
transaction against 169 B on the wire**, so record headers and duplicate
suppression cost 1.8%. 14.0 MB across four nodes; per node the split is 3.44 MB of
batches against 67.9 kB of vertices, which makes consensus metadata 1.9% of stored
bytes. At 1k TPS this transaction shape is ~14.9 GB/day per node.

*Why it matters:* D12 said storage work belongs on the payload rather than on
metadata or the record format. This is that claim measured: the append-only format
costs almost nothing on top of the payload, so the only remaining lever is the
payload itself. It also calibrates D15 — 302 GB/day is not a storage-format
problem, it is a 3.5 kB hybrid transaction times 1k TPS times 86,400.

*Known limits:* no shards and no pruning on this path, so it measures full
replication only. Batches are never read back or executed from the store, and the
run does not replay it; `karsa persist` owns that check.

## D26 — Sharding scales with the committee, not with a constant

**Decided.** `karsa live --store DIR --shard` keeps one erasure shard per node,
sized from the committee: `data = quorum_size`, `total = n`, so any `quorum` shards
reconstruct and the code tolerates `n - quorum` missing nodes. Each node stores
`payload / data`.

*Measured,* n=4, 50 rounds, 100 transactions per batch, same workload in both modes:

| Mode | Disk per transaction | Per node per day at 1k TPS |
| --- | --- | --- |
| Full replication | 172 B | 14.9 GB |
| One shard per node (3/4) | 60 B | 5.2 GB |

Payload alone goes 168.8 → 56.3 B, exactly the 3× that `data = 3` predicts; the
total is 2.9× because vertices are not sharded. Coverage was complete: 204 of 204
batches had at least three shards across the four nodes.

*The correction this makes to D15:* sharding reduces storage by roughly
`data = quorum_size ≈ 2n/3`, not by a fixed 32×. The 32/48 example in D15
corresponds to a committee near 48 validators. At the launch sizes D16 assumes, the
figure is 7× at n=10 and 21× at n=30; a four-node test committee only ever gets 3×.
A storage plan drawn from a 32× figure at n=10 would overstate the saving by 4.5×.

*Known limit:* the run verifies **coverage**, not reconstruction. `Store::put_shard`
records the digest, the index, and the shard length — not the original payload
length, which `Code::decode` needs. A node reconstructing from shards alone cannot
derive it, so model B needs that length persisted alongside the shard before the
path is usable end to end. `karsa shards` still proves the code itself round-trips.

## D27 — Pruning plus archive nodes, not erasure-coded storage

**Decided.** The storage plan is: a validator keeps a bounded window of full
payload, the current state snapshot, and every certified header forever; archive
nodes keep everything. Erasure-coded sharding (D15 model B, D26) is **not adopted**
for launch.

*Why:* at the committee sizes D16 assumes (10–30), sharding buys 7–21× while
leaving data availability *worse* than full replication. With full replication any
surviving node can serve everything; with one shard per node, data needs a quorum
alive. For a small committee, pruning is the cheaper complexity: no repair
protocol, no availability layer, no payload-length plumbing.

*The arithmetic that sets the window,* using measured bytes per transaction:

| TPS | 169 B transaction | 3.5 kB transaction |
| --- | --- | --- |
| 10 | 4.4 GB/month | 91 GB/month |
| 100 | 44 GB/month | 906 GB/month |
| 1,000 | 437 GB/month | 9.1 TB/month |

So "one month" is comfortable only at low throughput or with small transactions.
The window should be derived from the disk budget the chain is willing to demand:

```
window = disk_budget / (TPS x bytes_per_transaction x 86,400)
```

A 500 GB budget is ~1.6 days at 1k TPS with 3.5 kB transactions, ~16 days at 100
TPS, and ~165 days at 10 TPS.

*What stays forever, and why it is affordable:* certified headers (~200 B per
commit) and the current state snapshot. Vertices and batches are what the window
covers. The store already separates these logs, so bounding disk never requires
dropping headers.

*New load-bearing assumptions:*

1. **Archive nodes must exist and be reachable.** If nobody runs one, history is
   gone. That is a social and economic commitment, not a protocol guarantee.
2. **A new validator bootstraps from a snapshot plus a trusted height and hash,**
   then the tail. It cannot verify history older than the snapshot.
3. **A validator pruned past its window cannot serve history**, including an old
   proof a light client asks for.

*What pruning does not solve:* bandwidth. Every validator still receives and
forwards the whole payload, so per-node egress stays `(n-1)/n` of the originator
total. If throughput rises until the network rather than the disk is the
constraint, erasure-coded dissemination becomes relevant again; for now disk is
what binds.

*Kept as a measured result, not as the plan:* `crates/erasure` and
`karsa live --shard` stay in the tree. They produced the 2.9×/7×/21× numbers, and
the finding that the saving scales with the committee while availability falls at
small n is exactly why this decision went the other way.

## D28 — Retention is per-node configuration, validated

**Decided.** Node settings live in a `node.toml` the operator owns, in the shape
Cosmos operators expect: `[node]`, `[roles]`, `[storage]`, `[network]`.
`karsa config [path]` validates a file and explains it; `karsa config --init`
writes a commented example.

*Why per node:* retention is a local cost, not a chain constant. One validator may
keep a day, another a month, an archive keeps everything, and an RPC node may want
more history than a bare validator. The chain cannot decide that for them.

*What is configurable.* `roles.validator`, `roles.rpc`, `roles.archive`;
`storage.retain_days`, `storage.max_disk_gb`, `storage.snapshot_interval`,
`storage.keep_headers`; both listen addresses.

*What is refused, with one sentence each:*

- an archive node that also sets retention or a cap — the two contradict
- a pruning node with `retain_days = 0` or `max_disk_gb = 0`, which would delete
  everything or leave no usable disk
- a node with no role at all
- an RPC role with an empty address
- `keep_headers = false`, because headers are what a light client verifies and they
  are the cheap part
- an unknown key, rather than silently ignoring a typo

**The two-part retention rule.** Retention is "this many days **or** this much disk,
whichever comes first". The cap exists because bursts are charged in full: one hour
at 10k TPS is 36 million transactions, which at 3.5 kB is more than a quiet month.
A time-only rule lets a single spike fill the volume; a size-only rule makes the
window unpredictably short.

*The command prints the arithmetic,* because the days are not the interesting part:

```text
      TPS            169 B tx           3.5 kB tx
         10     30.0 d / 4.4 GB     30.0 d / 90.7 GB
        100    30.0 d / 43.8 GB    16.5 d / 500.0 GB
       1000   30.0 d / 438.0 GB     1.7 d / 500.0 GB
      10000    3.4 d / 500.0 GB     0.2 d / 500.0 GB
```

**Roles compose, and the composition is executable.** `validator` signs;
`archive` keeps everything and does not sign; `rpc` serves. They are independent
booleans, so validator + archive is a valid and useful node, and the summary prints
what the combination implies: `validator (signs, prunes after the retention
window)`, `archive (does not sign, keeps everything)`, `archive + rpc (does not
sign, keeps everything, serves rpc)`. An archive that also sets retention is
refused, because the two contradict.

`karsa live --archives N` makes the rule runnable rather than documented. An
archive node in that mesh has no DAG, opens no outbound link, and writes every
vertex and batch it receives: its row reads `authored 0`, `out 0 B`, `committed 0`,
while its store holds the same bytes as a validator's. Measured with 4 validators
and 2 archives over 30 rounds: 186 B per transaction on each validator, 186 B on
each archive, and identical validator storage with and without the archives — which
is the point, because archives are a copy that costs the archivist, not the
committee.

**A missing file is generated, not fatal.** `NodeConfig::ensure` writes the
commented default when the path does not exist — creating parent directories — and
then treats the result like any other file: validated, never silently repaired. So
`karsa node --config node.toml` on a fresh machine starts, and the operator edits a
file that already explains itself. An existing file is never overwritten, and a
file with problems stops the node before it writes anything.

*Wired.* `karsa prune` consumes the settings: it reads `node.toml`, turns
`retain_days` and `max_disk_gb` into one round cutoff, and deletes what that cutoff
says. Age needs a round-to-time map, so the store keeps a small `clock` log (about
one sample per second while a node runs, trimmed to the window on every prune). A
vertex carries no timestamp because adding one would reshape every record for a
fact the node observes cheaply anyway. The size half counts bytes with the same
rule pruning frees them: a vertex record goes, and a payload goes only when no kept
vertex names it and a shard backs it.

*Two invariants are enforced, not assumed.* A cutoff never crosses the newest
snapshot's round, because the snapshot is what the retained tail is replayed onto;
with no snapshot the policy prunes nothing rather than making the store
unreplayable. And when the cap is unreachable — headers and shards are kept
forever, and an unsharded payload is the only copy this node knows about — the
report carries the shortfall instead of claiming the disk fits.

*Still to wire.* `karsa live --store` records clock samples, but its short runs are
not where a 30-day window bites; the archive-sync path is still open. `karsa node`
does consume `network.rpc_listen`. Reading a setting the node ignores would be
worse than not having it.

## D29 — One chain identity: the genesis hash

**Decided.** The genesis hash is the chain's identity. `node.toml` carries no chain
id at all, and the human-readable name lives inside `genesis.json` — where it is
hashed with everything else, so renaming a chain changes its identity rather than
relabelling it.

*Why the config does not repeat it:* every validator in a committee loads the same
genesis, so a second copy in `node.toml` is only a place to typo. It adds no
security (the hash already pins the whole file) and it forces the node to carry a
check whose only job is to catch the mistake the duplication created. Cosmos and
Ethereum both do this, and both end up telling operators to keep three copies in
sync by hand.

*Why a hash rather than a name or a number:* a string chain id is a human
assignment, and two chains can be given the same one. Ethereum's 2016 split is the
worked example — ETH and ETC both stayed on chain id 1, and transactions replayed
across the fork until EIP-155 put a chain id inside the signed payload. A hash over
the genesis cannot collide that way, and it is derived rather than agreed.

*Two jobs, one value:*

1. **Replay protection** — the signing domain binds the 32-byte genesis hash, so a
   signature made for one chain cannot be replayed on another that has a different
   genesis. This is what EIP-155's numeric id does, done with a value that cannot
   be reused by accident.
2. **Identity** — two peers compare the hash before exchanging anything else. A
   node pointed at someone else's genesis is on a different chain, and says so
   instead of failing later during verification.

*The cost, stated:* 32 bytes in place of a short string — about +19 B on a 169 B
transaction (~11%), and noise against a 3.5 kB post-quantum one. It buys uniqueness
by construction, which no amount of coordination gives a name.

*Status:* wired, except for the handshake.

1. `karsa chain --home DIR` reads the genesis, takes its hash as the chain id, and
   signs every simulated transaction, vertex, and header over it. Renaming the
   chain inside the genesis changes the chain id, and therefore the signed bytes.
2. `net` no longer carries its own constant: a node is constructed with the chain id
   it signs over, and `karsa live` passes the same demo id the other commands use,
   so the two are no longer on different signing domains.
3. A store records the chain it was written under, in a 32-byte `genesis` file. The
   first write binds it; opening the directory against a different genesis is
   refused with `store belongs to chain … , not …` instead of silently replaying
   another chain's data. A store with no record — one written before this existed —
   is still accepted, because only a positive disagreement is evidence.

Still open: no peer handshake compares hashes, so two nodes on different chains
would only discover it when a signature fails. That is the piece that turns the
identity from a local check into a network one.

## D30 — Identity in genesis, endpoints in peers.json

**Decided.** Genesis holds the validators and their keys. It holds **no network
addresses**; those live in `peers.json` beside it, and that file is expected to
change as peers are learned, retired, or moved.

*Why the split:* an address is operational. A machine moves, a DNS name changes, a
hosting provider migrates — none of that may require every node to adopt a new
genesis, because the genesis is the chain's identity (D29) and changing it changes
the chain. Cosmos separates the same two things: genesis carries validator accounts
(and, in newer versions, gentxs), while `persistent_peers` and `seeds` live in the
node's own config.

*What the file is:* a list of `{address, endpoint}`, where `address` is the
Base58Check validator identity when known and `endpoint` is `host:port`. The two are
deliberately named apart: an address survives a move, and an endpoint does not
belong in genesis. It grows when the node learns a peer and shrinks when one is
retired. An entry whose address appears in genesis is a founding validator; one
that does not is a peer this node can reach but does not count as part of the
committee — a normal state for an RPC, a sentry, or a node whose committee
membership is checked elsewhere. An entry with only an endpoint is a peer whose
identity this node has not learned yet.

*The chain name is `karsa`, not `karsa-1`.* A version suffix in the name invites the
Cosmos habit of bumping it on every hard fork, which is exactly the relabelling
D29 rejected: the genesis hash already changes when the chain does, and a name that
also changes makes two identities for one fact.

*Not automatic yet:* nothing writes the file at runtime. `karsa live` is a fixed
loopback mesh with no discovery, and `karsa node` serves HTTP without peers, so
`--add` and `--remove` are the only writers. The format, the validation, and the
genesis cross-reference exist so the bookkeeping has a home when a transport grows
one; a file that claimed to track connections while nothing updated it would be
worse than an operator's list.

## D31 — A link opens with a hello, before any vertex

**Decided.** Every connection starts with one `Hello` frame carrying the wire
protocol number and the sender's genesis hash. Both sides write first and then
read, so neither waits. A peer whose hash differs is a different chain: the link is
closed without parsing a single vertex, and the accept side logs the refusal. The
reading buffer keeps whatever arrived behind the hello, so the first data frame in
one TCP segment is not lost.

*Why it belongs here:* D29 made the genesis hash the chain's identity and put it in
the signed payload. Without a handshake that identity was only enforced per vertex:
a peer on another chain could connect, send a full round, and every frame would be
rejected after the cost of parsing and signature-verifying it. The handshake moves
the check to the one place where the answer is cheap and the same for every frame.

*What it does not do:* it is not authentication — the hello is unsigned, and a peer
can lie about its hash and still be refused per vertex. It is a filter, not a
membership proof. TLS or a signed challenge belongs above it when links leave
loopback, and the frame has room for that without changing the layout.

*Scope today:* `karsa live` runs one chain id per process, so the mismatch path is
proved by tests over real sockets rather than by a CLI flag. `--home` lets a run
sign over that home's genesis instead of the demo hash. Once peers are learned and
connections cross processes, this is the layer that keeps two chains from wasting
each other's bandwidth.

## D32 — An account address commits to the policy that created it

**Decided.** An account address is 32 bytes:
`SHA-256("KARSA/ADDRESS/v1" || kind || threshold || sorted keys(algorithm, public_key, weight))`.
Keys are sorted by `(algorithm, public_key)`, so their order in a file is not part
of the identity. `key_id`, status, validity window, and `policy_nonce` are
**excluded**: the first is a label, and the rest are mutable state.

*Why the address is a commitment to the creation policy, not the current one:* a
rotation authorized by the old policy must not move a balance to a new address.
The address therefore stays fixed while the stored policy changes, and after a
rotation it can be recomputed only from the policy the account was created with.
That is a deliberate trade: the address is an origin commitment, not a proof of
the current key set.

*Why `key_id` is excluded:* two policies with the same authorization power are the
same account whatever their keys are called. Labels stay labels.

*Consequence for genesis:* two accounts whose creation policies are identical have
the same address, so their balances would merge. Genesis refuses the duplicate
rather than silently combining them; an account is its policy.

*In the runtime.* `Transaction.sender`, `exec::State`, genesis crediting, and the
demo batches all use the address. There is no account id anywhere: a label that is
not read invites the mistake of treating it as an identity. `karsa chain` prints the
full address, which is the value a person pastes into an explorer.

*The text form.* Addresses are Base58Check: two version bytes (`0x02 0x1a`), the
32-byte address, and a four-byte double-SHA-256 checksum, in Bitcoin's base58
alphabet. That pair of version bytes is chosen so every address begins with `K`.
There is deliberately no Cosmos-style word prefix and no `0x`: the first would copy
another chain's convention, and the second means a 20-byte EVM address. The checksum
catches a mistyped copy, and base58 omits `0`, `O`, `I`, and `l`. The text is display
only; the identity is the 32 bytes it decodes to.

*In genesis.* Each account carries that text beside the policy, so the file is
directly useful to a reader, and validation refuses an address the policy does not
derive, a duplicate, a bad checksum, or another chain's version. Accounts are sorted
and hashed by the decoded bytes, so the text form cannot change the genesis hash. The
HTTP demo in `karsa node` keeps its own string senders: it demonstrates the pipeline,
not the chain runtime.

*Still open.* The runtime still derives its accounts, balances, and keys from demo
seeds. Wiring `genesis.json` into `chain`/`live`/`audit` needs a `keys.json` beside
it for the private keys a node signs with; its public key is checked against the
genesis. That is the next slice.

## D33 — A validator's identity is its genesis key schedule

**Decided.** A validator address is 32 bytes:
`SHA-256("KARSA/VALIDATOR/v1" || sorted genesis keys(algorithm, public_key, activation_epoch))`.
It is written as the same Base58Check `K...` form as an account address, and
`ValidatorRecord.validator_id`, a vertex's `author`, and the genesis validator
entry all carry it. `key_id` and `retirement_epoch` are excluded: a label and
mutable schedule state.

*Why the genesis schedule:* a rotation adds a key under the old key's authority.
The validator must keep the same identity across that boundary, or its votes,
history, and peers would split in two. The address therefore commits to creation,
exactly like an account (D32), and after a rotation it is recomputable only from
the keys genesis listed.

*Consequences:* two validators with identical genesis schedules have the same
address and genesis refuses the duplicate. `peers.json` entries that name a
validator use the address; the founding check compares that text to the genesis
address. The local `node.toml` `id` stays a display name for one machine and is not
a consensus identity.

*Scope:* `karsa chain`, `karsa live`, `karsa genesis`, and `karsa peers` use the
address. The pure simulator commands (`dagsim`, `certify`, `net`, `sweep`,
`migrate`) still label positions `val-0..` because they build their own committee
without a genesis; they are experiments, not a chain membership.

## D34 — Genesis drives the runtime, and keys.json is the private half

**Decided.** With `--home`, `karsa chain` and `karsa live` build their committee
and accounts from `genesis.json`, and their opening state from the genesis
balances. The private keys come from `keys.json` in the same directory, written
`0600`, and are never hashed. A key entry names an address and a key id, and is
refused unless its public half matches the genesis key and its address is in
genesis.

*Why a separate file:* genesis is public and must be comparable byte for byte by
every node; private keys must never be part of something copied into a chat or an
explorer. Keeping them beside the genesis makes "which chain does this key sign
for" a validation instead of a convention.

*The fresh-home devnet.* When `genesis.json` or `keys.json` is missing, `karsa
genesis`, `chain --home`, and `live --home` write a four-validator, four-account
devnet from the deterministic demo seeds. The files say so. Replacing the genesis
without replacing the keys fails validation, which is the point; a keystore that
silently signed for a chain it was not made for would be worse than a refusal.

*Ordering is part of consensus.* Validators and accounts are sorted by address
before the runtime uses them, because the genesis hash sorts too. Without that, a
file written in another order would hash to the same chain id but elect a
different leader. `--validators` must equal the genesis committee size.

*Wired through persistence.* `karsa persist --home` writes a store under that
genesis and binds it to the hash, and `karsa audit --home` replays it with the same
membership. An audit without the matching home is refused by the store's genesis
binding before any signature work, rather than after a failed verification. The pure
simulators (`dagsim`, `certify`, `net`, `sweep`, `migrate`) remain position-label
experiments.

## D35 — The process boundary is a measurement tool, not a scaling lever

**Decided.** `--node-index` runs one validator per process so a run can measure a
real scheduler boundary. It is not a promise that more processes or more validators
raise unique throughput: every validator executes every committed batch.

*Measured* (AMD Ryzen 7 6800U, 8 cores / 16 threads; 4 validators, 20 rounds,
`--execute --pre-sign`, median of 3 on an idle machine): at 1,000 tx/batch the
single-process control authored 76.4k tx/s with 4 verifier threads and 35.9k with
one; one process per validator authored 70.9k with 4 verifier threads per process and
29.4k with one. At 4,000 tx/batch the same cells are 88.2k / 41.1k single and
78.3k / 37.7k multi. One process per validator therefore stayed at 82–93% of the
single-process control across the whole matrix and never above it. Verifier threads
are a 2.1–2.4× lever; batch 1,000 → 4,000 adds 10–16% at 4 threads and 14–28% at
one. Batch size stops at 4,096 transactions (`MAX_BATCH_TRANSACTIONS`). A second
session put four workers per process at 64.3k and one worker at 62.1k against a
68.9k single-process control in the same session — 93% and 90%, a 3.5% difference —
so worker count does not move the ratio; the absolute TPS there was 18–22% below the
earlier idle matrix for both modes, so ratios need a same-session control. Without
`--execute`, four processes author 21 rounds in 146–159 ms with delivery
p50 5–9 ms, so the gap is execution, not transport; with execution, delivery p50
rises to 27–142 ms at 1,000 and 198–508 ms at 4,000. `verify tx` is 89–94% of the
named stages. At 10 validators with one worker each, the committee authored 24.7k
tx/s aggregate and each node applied about 22.1k tx/s — the per-node verification
ceiling.

*Why:* D17 said parallelism is not the TPS lever. This measurement extends that to
process boundaries: the levers are batch verification, verifier threads, and batch
size. The boundary is how those are measured; the script now defaults the verifier
threads to the same per-process CPU slice as `WORKERS` (4 on the 16-thread machine,
2 on the 4C/8T desktop), and `VERIFY_THREADS=1` still reproduces the old serial
configuration. The first session's 20.3k/40.6k and a single 103.8k run were taken
under load and are superseded by the idle matrix; the 103.8k is an outlier, not a
result. The chain spends n× the verification work for one unique stream: on the
4C/8T desktop, four validators at 46.9k tx/s each verify 187.5k tx/s in total,
about twice the raw serial Ed25519 ceiling of 91.7k tx/s at eight threads. Batch
verification is that ~2× factor and is already on; curve25519 selects the SIMD
backend automatically on x86-64. The next lever is protocol-level: fewer
validators verifying every transaction (threshold, BLS, probabilistic), which
changes the trust model.

## D36 — Finality is reported as submit → certified header

**Decided.** The headline metric is submit → certified header, not block time and not
commit time. Commit → certificate is reported separately because it is a different
cost.

*Measured* (4 validators, loopback with injected one-way delay and 0–5 ms jitter,
100 samples, 3 runs, median): at 25 ms one-way, submit → certified p50 124.1 ms /
p95 210.7 / p99 218.4; at 50 ms, p50 224.3 / p95 339.5 / p99 394.6. Commit →
certificate is p50 1.1 ms at 25 ms and 1.3 ms at 50 ms; rounds to finality are
p50 2 / p95 3 / p99 3 at both delays. All 100 samples finalized on every node and
certified on the submitter in all six runs; order, state, and header agreement held
with 0 conflicts (435/440/436 commits at 25 ms and 413/420/421 at 50 ms).

*Load:* across sessions with load 0.75–4.8, p50 did not move (125.6 → 124.1 ms and
224.6 → 224.3 ms); tail latencies vary run to run. *Remaining caveat:* it is four
validators on loopback with injected delay, not a WAN and not a large committee.
The comparison to Sui (~400–700 ms) and IOTA (seconds) is submit → certified, not
block time.

## D37 — Certificate work grows with the committee, before any network delay

**Decided.** Finality comparisons name the committee size and use a zero-delay
control to separate local committee work from propagation. At ten validators most
of the certificate tail is local verification and scheduling, not network wait.

*Measured* (AMD Ryzen 7 6800U, 8 cores / 16 threads; in-process `mpsc` mesh, 100
samples, 1 tx/batch, 3 runs median; zero delay 0/0 ms, delayed 25/50 ms with 0–5 ms
jitter): zero delay, n=4 → n=10 moved submit → commit p95 18.0 → 75.9 ms (4.2×),
commit → certificate p95 3.4 → 15.8 ms (4.6×), and submit → certified p95 20.6 →
89.4 ms (4.3×). At 25 ms one-way the same cells are 187.1 → 228.9, 5.0 → 20.2, and
191.5 → 240.8 ms; delay adds only about 4 ms to the n=10 certificate p95, so the
rest is local work. The median moves modestly: submit → certified p50 125.4 →
139.1 ms (+11.0%) at 25 ms and 224.1 → 244.9 (+9.3%) at 50 ms. The tail is not
stable across delays: p95 moves 191.5 → 240.8 (+25.7%) at 25 ms but 391.2 → 402.1
(+2.8%) at 50 ms, where the n=4 control itself carried a 391 ms p95; an earlier
single-run 50 ms control gave +26.4%. Rounds stayed p50 2 / p95 3–4; leader p50 1,
non-leader p50 2. All six n=10 runs finalized 100 of 100 samples on every node,
certified them on the submitter, and agreed with 0 conflicts and 0 rejected.

*Why:* the zero-delay control is the part that replicates: the local cost of
verifying more vertices and more quorum signatures grows 4.2–4.6× from four to ten
validators, while the injected delay adds a few milliseconds. A delayed tail of
three runs is too noisy to carry a scaling claim on its own; report the zero-delay
floor and the median, and treat p95/p99 deltas as conditional. The split between
certificate verification and task scheduling is still not separated. D36's caveat
is narrowed, not removed: one process, one machine, 1 tx/batch, n=10. See D38 for
why the 20–30 extension cannot answer the larger-committee question. An aggregated
certificate signature would remove verification cost and bytes, not the wait for
the last quorum share; either way it is a trust-model decision.

## D38 — In-process finality above ten validators is a contention probe

**Decided.** `karsa finality` runs the whole committee in one process. The 20–30
validator numbers are recorded as a probe of that boundary, not as a
committee-scaling curve; they must not justify a protocol change in either
direction. A real launch-size curve needs one process per validator, or per-node
CPU accounting, which `finality` does not provide (`--node-index` exists for
`live`, not for `finality`).

*Measured* (same session, 3 runs median, 1 tx/batch): submit → certified
p50/p95/p99 at 25 ms one-way, n=4/10/20/30: 125.4/191.5/256.5, 139.1/240.8/291.1,
255.2/534.3/752.5, 585.4/1,876.9/2,530.1 ms; at 50 ms: 224.1/391.2/455.3,
244.9/402.1/458.9, 350.7/832.7/1,004.0, 583.9/1,862.7/2,133.3 ms. At n=30 the
medians at the two delays are within 0.3%, but individual p50s span 488.5–631.6 and
510.3–595.9 ms, so that is run noise rather than a delay-independent law. The load
is not noise: 3.9 before the n=20 block, 9.2 after it, 12.8 after n=30 on 8 cores /
16 threads; the first n=30 @25 run started at load 9.2 and reached p99 4,253 ms,
against 2,530 and 2,146 ms for the next two. All 30 runs finalized 100 of 100
samples on every node, certified them on the submitter, and agreed with 0 conflicts
and 0 rejected, so correctness held while latency rose; the contention reading rests
on the load and the overlapping delay ranges, not on an isolated CPU measurement.

*Why:* the in-process mesh was cheap enough to measure n=4 and n=10 cleanly, but
20–30 node tasks oversubscribe the machine; CPU time, message timers, and the
runtime scheduler all compete. The result is a probe of that limit, not a prediction
of 30 validators on 30 machines. Until a multiprocess finality mode exists, the
defensible claim stops at n=10; the larger sizes stay in the correctness columns
(D18 covers convergence to n=100) and out of the latency headline.

## D39 — BLS aggregation fails the measured performance rule

**Decided (performance criterion).** Do not pursue BLS12-381 transaction
aggregation. Keep the current Ed25519 batch path. Do not adopt BLS aggregate
certificates at launch committees (10/20/30). Defer threshold Schnorr/FROST
until the finality tail becomes a product requirement. Probabilistic
verification stays rejected. The trust-model questions (classical default,
DKG/accountability) remain owner decisions; the performance case is closed.

*Measured* (Intel Core i7-4790K, 4 cores / 8 threads; standalone
`bench/crypto-verify/`, release build, median of 3, three sessions; 1,000 and
4,096 distinct messages, 1 and 4 verifier threads; blst 0.3.17 built with
`no-threads`): at 4,096 transactions the Ed25519 batch path took 96.6 ms on
one thread (23.6 µs/signature) and 35.7 ms on four (8.7 µs/signature); the BLS
full wire path took 2,687.5 ms (656.1 µs/signature) and 720.6 ms (175.9
µs/signature). With one invalid signature, Ed25519's batch-fail-plus-fallback
path took 265.1 ms against BLS's 4,840.9 ms. BLS was 27.8× slower on one
thread, 20.2× slower on four, and 18.3× slower on the failure path; a third
session under load kept the direction (33.9×/21.8×/15.4×). Aggregation itself
is cheap (1.9 µs/signature); the cost is one pairing per distinct message
(~523 µs/signature) plus ~132 µs/signature for the subgroup check. Public keys
are assumed PoP-validated at registration, so the BLS figures are lower bounds.
Certificate verification at n=10/30: Ed25519 batch 0.254/0.729 ms, BLS
aggregate 1.460 ms (independent of n), so BLS is 5.1–5.7× slower at n=10 and
1.8–2.0× slower at n=30; n=20 is interpolated, not measured. A FROST/Schnorr
final verify is modeled at one
Ed25519 verify, 0.040–0.058 ms, but the measured n=10 commit → certificate p95
is 15.8 ms (D37), so certificate verification is not the tail. The n=100 BLS
certificate crossover is plausible (existing Ed25519 batch report 2.63 ms vs
BLS 1.46 ms) but was not measured in one session.

*Why:* the decision rule pre-registered in `docs/protocol-lever.md` required BLS
to be at least 2× faster at 4,096 transactions; it is 18–28× slower. The BLS
dependency stays out of the workspace and the default build, and the validation
gate passes without it. The TPS ceiling stands; the next lever is still a
trust-model change (fewer validators verifying, proofs), not a classical
aggregate signature. The Ed25519 numbers are session-sensitive (the third
session moved them −18%/+37% under load) while the BLS rows stayed within 0.7%,
so the direction is more stable than any single absolute value.

## D40 — ML-DSA-65 stays an experimental contingency

**Decided.** ML-DSA-65 does not replace Ed25519 in the default chain. It remains
an experimental, activation-gated contingency for a future post-quantum
migration. The benchmark prices that migration; it does not propose one, does
not enable the PQ registry entry in the workspace, and changes no consensus or
default.

*Measured* (Intel Core i7-4790K, 4 cores / 8 threads; standalone
`bench/crypto-verify/` with `--features pq`; OpenSSL 3.5+ ML-DSA-65; real
`Transaction::verify` with an ML-DSA policy; median of 3, two sessions; 1,000
and 4,096 distinct messages, 1 and 4 verifier threads): raw ML-DSA-65
verification is 188.9 µs/signature on one thread (5.29k/s) and 52.7–52.9
µs/signature on four (18.9–19.0k/s). The full transaction path is 190.9–195.3
µs/signature on one thread and 50.4–54.0 µs/signature on four (18.5–19.8k/s).
The current Ed25519 batch path at four threads is 8.9 µs/signature (112–122k/s
across sessions), and individual Ed25519 is 41.4 µs on one thread and 16.9 µs
on four. The full ML-DSA path is therefore 5.7–6.1× the current Ed25519 batch
cost per signature, or a ~6× lower per-validator verification ceiling before the
larger wire and state costs. Signing costs 1.06–1.16 ms/signature, 5.6–6.1× the
verification cost; signatures are 3,309 B, public keys 1,952 B, and an encoded
transaction 3,481 B.

*Why:* a PQ migration is a security/product decision, not a TPS lever. ML-DSA
has no batch equation, and the chain's `batch_candidate` is Ed25519-only, so the
current ~2× batch factor disappears. The measured cost should be budgeted if the
migration is chosen: lower verification throughput, ~3.3 kB per signature on the
wire, and ~1.9 kB per account key in state. The benchmark is CPU verification;
bandwidth, consensus, execution, and the actual chain TPS impact are
modeled/outside this harness. The bench feature stays outside the workspace
defaults, and the workspace gate remains green without it. Full detail is in
`docs/pq-fallback.md`.

## D41 — A validator-set change is a checked boundary, not a hot swap

**Decided (prototype).** Keep the conservative transition rule: exactly one
identity is added or removed per epoch, the new set keeps the old fault budget,
and any old/new quorum intersects by more than the old `f`. The old set signs the
certificate that activates the new set; the new set is active at its epoch. The
change is a harness parameter, not an authorized on-chain record; governance
remains open.

*Measured* (AMD Ryzen 7 6800U, 8 cores / 16 threads; in-process mesh, 100
samples, 1 tx/batch, closed loop, epoch 50 rounds, change at round 50, median of
3 runs; release build): all 30 runs finalized 100/100 on every node with 0
conflicts and 0 rejected; the n=10 block certified 100/100 on the submitter. At
n=4 the submit → certified p50 was 15.63 ms for add 4→5 and 14.57 ms for remove
5→4 against a 15.16 ms control at zero delay (+3.1% / −3.9%), and 126.13 / 126.46
ms against 125.25 ms at 25 ms one-way delay with 5 ms jitter (+0.7% / +1.0%). At
n=10 zero delay add 10→11 moved p50 35.89 → 45.62 ms (+27.1%), p95 84.25 →
180.37 ms, and p99 103.91 → 252.95 ms, but one of three runs carried a 484.12 ms
p99 and 31 rounds against 11 in the other two; at 25 ms the same cell was
145.94 → 133.54 ms p50 (−8.5%), 264.88 → 253.93 ms p95, and 349.63 → 288.84 ms
p99. The added validator authored 62–150 vertices across the add runs; the
removed validator authored exactly 50 vertices (rounds 0–49) and stopped at the
boundary in every remove run.

*Why:* the safety/liveness result is binary and clean: every run crossed the
boundary and still finalized every sample with no conflict or rejection. The
latency result is weaker and is reported as such. At n=4 the change is inside
the run-to-run spread; the boundary only delays the small subset of samples that
straddle round 50 (4→5 zero-delay boundary p50 17.72 vs 13.57 ms before; 4→5 at
25 ms 191.73 vs 123.54 ms in two of three runs, the third 128.90 ms). The n=10
zero-delay tail did not reproduce at 25 ms, so it is local contention/catch-up,
not a network cost. This does not make adding validators a TPS lever (D12/D13);
it makes the committee changeable at all.

*Modeled/assumed:* a persistent Byzantine budget `f` (a validator honest in the
old set stays honest in the new one); the harness parameter stands in for the
missing authorization; the new validator is online and passive before the
boundary, so a cold join/sync is not measured; one transition per schedule;
numeric signer indices stay stable because the harness appends or removes the
last validator. `docs/validator-set-change.md` has the full table and caveats.

## D42 — A cold join adopts the peer committed prefix

**Decided (prototype).** A validator that was not online from genesis joins at
the change round from a snapshot: the committed order up to the peer's last
built header, the last built header, the next decision round, and the history
records. The joining node verifies the vertices and batches, seeds the DAG order
and pacemaker cursor, applies the prefix in that order, checks
dag_root/state_root/applied, verifies the certified header chain, and starts
deciding after it. The snapshot still carries the full history;
state-snapshot-plus-tail is the next milestone.

*Measured* (AMD Ryzen 7 6800U, 8 cores / 16 threads; in-process mesh, 100
samples, 1 tx/batch, closed loop, epoch 50, change at round 50, median of 3 runs;
load 3.2–4.7): all 12 cold/control runs finalized 100/100 on every live node,
certified 100/100 on the submitter, with 0 conflicts, 0 rejected, and agreement
true. At zero delay, cold join submit → certified p50 15.11 ms vs 14.92 control
(+1.3%), p95 23.71 vs 22.28 (+6.4%), p99 28.03 vs 25.89 (+8.3%). At 25 ms + 5
jitter: p50 125.46 vs 125.47 (0.0%), p95 191.09 vs 193.50 (−1.2%), p99 213.78 vs
224.65 (−4.8%). Catch-up median at zero: 36.07 ms, 143,169 B, 197 vertices, 45
batches, 44 headers, 189 commits, 49 rounds; at 25 ms: 50.04 ms, 138,641 B, 197
vertices, 50 batches, 43 headers, 189 commits, 49 rounds. The cold validator
authored 111–119 vertices at zero and 62–63 at 25 ms; its certified/head matched,
its header count was lower because it adopted the prefix.

*Why:* the first attempt re-decided the prefix from a partially received DAG and
missed eight empty vertices; seeding the peer's order and cursor fixed it. The
aggregate latency is unchanged within noise; the cold-join cost is the catch-up
before the node starts, not a finality regression. The in-process handoff and
the serialized byte count are a model; the next step is a state snapshot plus
the tail, then a real transport.

*Assumed:* the snapshot peer is honest and reachable; the last built header is
trusted after dag_root/state_root/applied match the replayed prefix; one
transition per schedule; numeric signer indices stay stable. Full detail is in
`docs/cold-join.md`.

## D43 — A cold join adopts a state snapshot plus the tail above a safe floor

**Decided (prototype).** The cold-join path defaults to a snapshot: the encoded
`exec::State` at the peer's last built header, the trusted header and cursor,
the committed order prefix, and the DAG floor. The joining node decodes the
state and checks its root against the header, checks the order prefix against
`dag_root`, seeds the order and pacemaker cursor, prunes at the floor, transfers
only vertices and batches above it, and verifies the tail certified headers
against the trusted anchor. `--cold-full-history` keeps the D42 path as a
control.

The floor is the trusted header round minus two rounds, lowered below any held
vertex outside the committed prefix. Round 0 is never pruned; if no positive
floor is safe, the state is adopted but the DAG travels whole. The order prefix
stays because a header's `dag_root` commits every commit from genesis; a
snapshot without it can verify and vote but cannot build the same headers.

*Measured* (Intel i7-4790K, 4 cores / 8 threads; in-process mesh, 100 samples,
1 tx/batch, closed loop, epoch 50, change at round 50, 12 runs, full and
snapshot alternated in one session, median of 3, load 2.6–3.1): at zero delay,
snapshot catch-up 2.13 ms and 22,612 B against 41.55 ms and 143,041 B for the
full history (6.3× fewer bytes, 19.5× faster); at 25 ms + 5 jitter, 4.78 ms and
20,827 B against 67.46 ms and 136,667 B (6.6×, 14.1×). The state is 450 B, the
order prefix 13.3–13.8 KB, the tail 6.7–10.9 KB. Floor 44–45 in every snapshot
run. All 12 runs finalized 100/100, certified 100/100 on the submitter, agreed
on order/state/headers, with 0 conflicts and 0 rejected. Submit → certified
p50/p95/p99 moved −5.5%/+11.6%/+7.2% at zero and +0.3%/+4.5%/+1.0% at 25 ms;
the zero tail is inside the run spread, the 25 ms row is unchanged.

*Why:* the state snapshot removes replay and most of the transfer, but the
order prefix is now the dominant cost (60–65% of the snapshot bytes). This is
the honest ceiling of the current header format: `dag_root` covers all commits,
so a smaller transfer needs a Merkle frontier or a different commitment, which
is still open at this point in the log (D50 implements the frontier). The
measurement also found that the in-process queue retains
every payload from genesis; counting it inflated the tail (42 batches). The
drain now keeps only payloads the tail executes (1–4 batches).

*Modeled/assumed:* in-process handoff, not TCP; serialized bytes are a model;
the anchor is trusted by height/hash (certificate verified when present); the
floor policy is a prototype (margin 2, round 0 never pruned, whole-DAG
fallback); one transition per schedule and stable signer indices. The next step
is a real transport with archive serving and fail-closed redirects.

*Supersedes the last sentence of D42* ("the snapshot still carries the full
history; state-snapshot-plus-tail is the next milestone").

## D44 — The live TCP node runs the header and certificate pipeline

**Decided (prototype).** The header rules moved into
`validator::finality::Finalizer`, a transport-free module: it turns commit
boundaries into headers, marks the state root at each applied prefix, signs the
headers the node may sign, collects shares, and advances a `HeaderChain` on a
quorum. `karsa live` now uses it. `wire::Message::Share` carries one signature
over one header and the wire protocol is version 2. A live node builds one
header per commit, broadcasts its share, and persists the certified header when
a store is configured. Finality requires `--execute`: a header commits a state
root, and a node that does not apply batches has no state to commit.

*Measured (functional, not a benchmark):* four processes, one validator each
(`--node-index 0..3`), 20 rounds, 1 tx/batch, `--execute`: every node authored
21 vertices, committed 76 entries, applied 76 transactions, certified 18
heights (head 18/19), reported the same commit root and state root, and saw 0
rejected and 0 certificate conflicts. The single-process TCP mesh reported
16/16 common certified heights, agreement true, conflicts 0, and the same state
root on all four nodes. No timeout and no divergent root.

*Open:* persistence/restart, the client RPC, and snapshot sync over TCP. The
in-process finality harness still carries its own copy of the header rules; it
is the measured reference for D42/D43 and moves onto `Finalizer` in a separate
change with a fresh run matrix.

## D45 — A live node restarts by replaying its full store

**Decided (prototype).** The live store keeps every vertex, every batch, every
certified header, the genesis header, and the encoded genesis state. On startup
the node decodes the stored genesis state, inserts the stored vertices, rebuilds
the commit order with the pacemaker from round 1, applies the stored batches in
that order, adopts the stored certified headers into `Finalizer`, and resumes
above the certified head. It sets its authoring round to the highest held round
plus one, so it does not re-sign rounds the store already contains. A pruned
store is refused with a clear error for now: the committed order prefix is not
persisted, and a header's `dag_root` needs it to build the next header.

The genesis header and state are persisted because the live harness credits
balances above the membership's genesis. A root alone cannot rebuild that state,
so audit and restart read the exact bytes instead of guessing the credit policy.

*Measured (functional):* first run on four nodes over TCP: 308 transactions
applied in total (77 per node), 19 certified heights, state root
`a6cdffe15f17`. Second run against the same stores: the replay restored 77
transactions and order 77 per node to the **same state root `a6cdffe15f17`**,
with certified head 19 and all four nodes agreeing; it then authored 20 more
rounds, reached 39 certified heights, applied 624 transactions in total, and
ended on the same state root on all four nodes, with 0 rejected and 0
conflicts.

`karsa audit` on the restarted store re-derives **39 of 39 heights** for both
`state_root` and `dag_root`, with 156 transactions applied and 0 rejected. The
audit matches each header's `dag_root` to its exact order prefix; a round
boundary is not enough, because one commit can include only part of a round.

*Open:* the pruned-store path needs the committed order prefix (or a Merkle
frontier) in the snapshot before pruning can be used with restart. The live
path still writes no state snapshot, so a restart replays every vertex and batch
and its cost grows with history.

*The open paragraph is closed by D47 (snapshot resync) and D48 (checkpoint plus
prune); the remaining order-prefix cost is closed by D50.*

## D46 — A dropped link reconnects, and a restart replays the shares it missed

**Decided (prototype).** An outbound link is rebuilt after a drop, the frame
that failed in the middle of a write is kept and sent on the new socket, and
the last 1,024 shares are replayed to a peer that reconnects. A share whose
height below it is not yet certified waits for the gap; shares older than the
replay window are dropped. This replaces a failure mode where one lost share
stalled finality on that node permanently, because a share is produced once
and never repeated.

*Measured (functional, four loopback processes, Intel i7-4790K, 4 cores /
8 threads).* A node stopped for 10 s: the observer's head rose 625 -> 1,105
and committed 2,819 -> 4,751 with 0 conflicts. A full restart from the store
brought node 2 to head 1,686 against 1,686 and committed 7,887 against 7,890,
0 conflicts. A transfer sent after recovery finalized in 106 ms, all four
nodes reached head 1,898 with state root `86387ef2bd72`, one applied
transaction, 0 conflicts and a verified commit proof; `karsa audit` on the
recovered store re-derived 3,053 of 3,053 heights.

*Cost.* Replay is 1,024 shares, about 15 s of certificates on this machine.
A longer outage needs the snapshot resync in D47; recovery is not instant
(after a 10 s outage the returning node was still 1,487 against 2,020 after
a 35 s run).

## D47 — A store with history resyncs by adopting a peer snapshot above its head

**Decided (prototype).** `--sync-from-peers` fetches a snapshot over TCP,
verifies the anchor's quorum certificate, state root, and `dag_root`, and
adopts it only when its height is above the store's certified head. The
adopted anchor, state, order prefix, floor, and tail are written to
`live.snapshot`; a later restart resumes from it instead of replaying history
the node never had. After the snapshot is written the store is pruned at the
adopted floor, so the directory does not keep both histories. A peer whose
snapshot is below the stored head is refused after 15 s rather than moving the
store backwards.

*Measured (functional).* A node with stored head 552 adopted a peer snapshot
at height 1,068 and reached head 1,131 against 1,130 on node 0, with commit
root `2517def7…` and 0 conflicts. The next restart on the old store plus
`live.snapshot` had all four nodes at head 2,636, commit root `c86d8123…`,
0 conflicts. On the pruning run, a node with history to height 1,169 adopted a
peer snapshot at height 1,862 (floor 1,346), pruned the 24 old vertices and 2
headers it still held, and ended on the same commit root `b98f42ae…` as the
three nodes that stayed up. A restart then restored all four from checkpoints
around 2,487-2,504 and reached head 3,083, commit root `755d22f0…`, 0
conflicts; `karsa audit` on the resynced store re-derived 58 of 58 heights on
both roots.

*Cost.* The snapshot carries a Merkle frontier for the prefix below the floor and
only the tail above it (D50), so its size no longer grows with the whole order.

## D48 — A checkpoint is the live store's prune anchor

**Decided (prototype).** `--checkpoint-every N` writes `live.snapshot` every
N certified heights; it needs `--execute` and `--store`, defaults to 0, and
skips a head whose floor is not safe to prune. Each successful checkpoint
then prunes below the snapshot: vertices at or below its floor, payloads no
kept vertex names, and certified headers below the anchor height. The anchor
header is kept, so restart and `karsa audit` still see the certified height
they resume above. A payload named by a kept vertex is never dropped: the
vertex may still be committed after the restart. The interval is measured
from the resumed checkpoint or head, so a large N does not fire a checkpoint
immediately after a restart.

*Measured (functional).* Single process, 200 rounds, every 64 heights: 8
writes at heights 64-96 and 155-160; a restart from checkpoint 129 restored
order 797 to head 176, with all four nodes agreeing. Four-process devnet,
every 1,024 heights: a restart resumed from checkpoint 1,405, wrote 1,934,
and all four nodes ended on commit root `28de7f08…`. Pruning run, every
128 heights, 35 s: 13 checkpoints, each dropping about 700 vertices, 150-175
headers, 0-1 batches, and 400-480 kB; after the last checkpoint the logs held
6.5 kB of vertices, 513 B of headers, and 0 batches. A restart from
checkpoints 2,197-2,310 replayed the tail to head 3,802 on all four nodes,
commit root `2042ff83…`, state root `20c162bd…`, one applied transaction, 0
conflicts. `karsa audit` re-derived 235 of 235 heights on both roots above a
checkpoint 235 heights behind the head; a store checkpointed at the head
reported 0 of 0 heights and verified the anchor certificate instead. A restart
with N=4096 from checkpoint 4,187 wrote no checkpoint in a 12 s run, where a
process-start throttle would have fired immediately.

*Cost and open.* Pruning bounds the append-only logs, and the checkpoint itself is
bounded by the frontier in D50 (state plus peaks plus the tail above the floor,
not the full order). Whole-payload nodes prune with
`min_shards = 0`; `--shard` nodes pass 1. The floor rule is D43's prototype
(two-round margin, round 0 never pruned, whole-DAG fallback). Restart from
checkpoint is now covered by an automated in-process test: four nodes author
30 rounds with `checkpoint_every = 2`, drain for two seconds so the committed
prefix catches up, assert that no vertex below the floor and the anchor header
survive, restart from the same stores, and audit the pruned store. The store
prune, the checkpoint cadence, and the two config checks also have unit tests.

## D49 — The devnet is a process-per-validator script

**Decided (prototype).** `scripts/devnet.sh` starts one `karsa live
--node-index i` process per validator from a real home, writes the genesis
once (the init path refuses when `keys.json` exists), registers each validator
in `peers.json`, sets the store, RPC, snapshot, and checkpoint paths, and
writes one log per node. `RESET=1` wipes the directory; the default checkpoint
is every 1,024 heights.

*Measured (functional).* Cold: all four nodes complete, commit root
`4d4aec7c…`, state root `690cb32b…`. Restart: all four restored, commit root
`d95a3702…`. `karsa send --home` submitted a signed transfer on chain
`b920e1221bd1`, finalized in 106 ms, and the commit proof verified.

*Cost.* This is a devnet, not a deployment: every process runs on loopback
under one user, and `peers.json` is informational because the live mesh still
derives endpoints from `--port-base`. `WIRE_PROTOCOL` is 4 (D50), so an old and a
new node refuse each other at the handshake.

## D50 — A checkpoint commits the order prefix as a Merkle frontier

**Decided (prototype).** A header's `dag_root` commits every entry from genesis,
so a checkpoint that dropped the order below its floor would lose the ability to
build the next header. The prefix below the floor is already applied and never
replayed, so it only needs to contribute to the root. `CommitFrontier` keeps it
as the perfect-subtree peaks a binary counter would carry; `Dag` holds those
peaks plus the committed tail above the floor, `order_len()` reports the total,
and `Finalizer::build_ready_with_prefix` roots a header at
`prefix + tail[..len]`. `live.snapshot` version 2 and the TCP snapshot carry
`order_len`, the prefix peaks, and the tail; version 1 snapshots are still read
as an empty prefix with the full order. `karsa audit` seeds the same prefix plus
tail, and the RPC builds a tail leaf's commit proof from the peaks. A leaf below
the retained prefix has no proof because the node no longer holds the data.

*Why:* the order prefix was 60-65% of a cold-join snapshot (D43) and the whole
checkpoint file. Bounding the logs without bounding the order would have left the
last unbounded file in the live store.

*Measured (functional).* Four-process devnet, checkpoint every 128:
`live.snapshot` stayed at 1.3-2.0 KB up to head 1,415 and was 1.4 KB at head
3,972, against 1.36 MB for the full-order format at head 3,802; per-node disk
ended at 8-104 KB. A restart from the compact checkpoints was 4/4 with the same
state root and one applied transaction; a transfer sent after the restart
finalized in 103 ms and its proof (leaf 11,790 of 11,791) verified against
`dag_root`; `karsa audit` re-derived 111 of 111 heights on both roots. A fresh
node joined over TCP from a compact snapshot at height 3,986 (floor 4,443, 21
tail vertices), matched the mesh on commit root `d49f51d7…`, restarted from its
own compact checkpoint (5,452) with one applied transaction, and audited 3 of 3
heights. The frontier's root and tail-proof tests cover every split and every
tail leaf for small sequences, and the in-process restart test covers the live
path.

*Cost and open.* `WIRE_PROTOCOL` is 4; an older node is refused at the
handshake, and the wire-protocol version check is the compatibility boundary. An old
leaf below the floor cannot be proven, so `GET /tx/{id}?proof=1` serves proofs
only for transactions this process tracked above the prefix. `Dag::order()`
returns the retained tail after a compact seed; callers that need the full count
use `order_len()`, and `commit_root_at` takes the full index. The state itself
still grows with accounts and touch history; that is a different cost from the
replay log. The order diagnostic in `check` compares retained tails, so on a
genuine root mismatch with different floors it is less precise than the root
the check already prints.

*The state-growth sentence above is corrected by D51: the encoded state grows
with the genesis account set and not with history. The wire protocol was raised
from 4 to 5 by D52 when transaction gossip was added.*

## D51 — Account state grows with the genesis account set, not with history

**Measured (functional).** The state field of every `live.snapshot` on disk was
212 bytes at four accounts, at rounds 147 through 7,409, in both the v1
full-order files (up to 1.5 MB) and the v2 frontier files (1.4-2.3 KB): the
enclosing file grew with the committed order, the state field did not. A
32-byte account id encodes to 52 bytes, so 0, 4, 64 and 1,000 accounts encode
to 4, 212, 3,332 and 52,004 bytes. A 16-account state applied 3,200 transfers
and encoded to the same 836 bytes before and after, with every sender's
sequence advanced.

**Decided (prototype).** No sparse or reference-counted state is added. A
transaction changes a balance and a sequence in place; it cannot add a map
entry. `State::apply_one` rejects an unknown sender and an unknown recipient,
and only `State::credit` adds an account; on the consensus path its callers are
the genesis credit and `credited_genesis` for the live harness. The account set
is therefore closed at genesis, and the state is `O(accounts)`, not `O(history)`
or `O(transactions)`.

*Cost and open.* The per-account costs that remain are not state growth:
`state_root()` rebuilds the Merkle tree over every leaf when an applied prefix
is marked (once per executed batch), `note_state` and `remember_state` clone the
state into 256-entry windows, and `/account` rebuilds a tree per proof. At four
accounts these are below the run's noise; a large genesis would make them
per-commit and per-snapshot costs. If account creation is ever admitted, the
bound is still the account count: a sparse Merkle tree would shorten proofs, and
reference-counted or copy-on-write maps would make the cloned windows cheaper,
but neither would change the encoded bytes. Both properties are pinned by
`the_state_encoding_grows_only_with_the_account_count` and
`the_state_encoding_does_not_grow_with_history`.

*Why:* the open note in D50 projected growth with "touch history". The encoded
state has no per-touch entry, and the measurements above show the field is
constant over the order history that the checkpoint bounds.

## D52 — Transactions gossip on the peer link, and status is execution-wide

**Decided (prototype).** `Message::Tx` carries one canonical envelope, and
`WIRE_PROTOCOL` is 5. A local `POST /tx` queues the transaction and puts the
envelope in a gossip outbox; the node loop drains it every tick and sends it on
the control plane to every peer. A receiver re-runs the submission checks
(chain, account policy, signature, replay, slot reservation) before admitting it
to its own mempool. An envelope received from a peer is never put back in the
outbox, so gossip cannot loop. Every node can author what a client sent to any
node. Executing the committed order is what updates a record for a transaction
the node did not author: `note_applied` derives the transaction id from the
batch itself and sets the outcome, the first order position, and the vertex. An
applied copy wins over a later duplicate the sequence rule rejects, and finality
runs through the same pending-order queue, so a peer's record gets the same
finalized height and commit proof; a queue entry whose order position was
superseded by a later applied copy does not finalize the record.

*Measured (functional, four loopback processes, Intel i7-4790K, 4 cores /
8 threads).* A transfer submitted to node 0 finalized in 114 ms; `GET /tx/{id}`
on all four nodes reported `finalized` at height 1,293 with a commit proof (leaf
5,817 of 5,820) and the same state root. A second transfer submitted to node 2
finalized in 180 ms, and all four nodes reported height 2,394 with a verified
proof. At shutdown all four nodes ended on commit root `973718f3…`, state root
`2456fc21…`, applied 2 transactions, 6 rejected, 0 missing payloads, and equal
account balances and sequences. The 6 rejects are the cost: every node authoring
from its own mempool can include the same transaction in the same round. The
content-addressed batch is one payload, but each vertex that names that digest
executes the batch again and the sequence rule refuses the duplicate. The
applied copy is the one every node reports and proves. A restart from
checkpoints 2,592-2,692 restored 1 applied transaction and order 12,152 with
`tracked_transactions` 0, because records are in memory; a transfer submitted to
node 1 then finalized in 110 ms, and all four nodes reported height 4,256 with a
proof, ending on commit root `42726e73…`, state root `7f33d240…`, applied 2,
rejected 3, and 0 missing payloads.

*Cost and open.* Gossip is best-effort: a dropped `Tx` frame is not repaired,
because only the DAG has a reference rule to drive repair; a client retry or a
second submission reaches the node. Records and the gossip outbox are in memory,
so a restart loses `/tx` history, and a node that receives a late envelope after
the sequence advanced cannot create a record for a transaction it did not see.
The wire protocol is 5; an older node is refused at the handshake. A mempool that
authors a transaction once (by lease or deterministic ownership) would cut the
duplicate executions; the prototype keeps liveness simple and makes the
duplicate visible in the rejected count.

## D53 — A finalized transaction carries its commit proof across the pruned prefix

**Decided (prototype).** When a certified header finalizes a tracked transaction,
`RpcCore` captures the commit proof while the leaf is still inside the retained
order: the vertex, the Merkle path, and the header's `state_root` and `dag_root`.
`/tx/{id}?proof=1` returns that witness when the live order can no longer build
the proof, so a checkpoint that prunes the leaf leaves status, roots, and proof
intact. A later applied copy clears the witness because it may point at a
different order position.

*Measured (functional).* Four-process devnet, checkpoint every 64: a transfer
finalized at height 1,389, vertex round 1,560, leaf 6,239 of 6,240, with the
proof verified at finality. After the run reached checkpoint round 2,387 with
floor 2,385 and prefix length 9,542, the leaf and its vertex were below the
retained prefix. The same `GET /tx/{id}?proof=1` still returned the 8-step
proof, and recomputing the commit root from the returned vertex and siblings
gave `73d1c93b0739…`, equal to `dag_root`. The four nodes ended on commit root
`64d1fc13…`, state root `20c162bd…`, 1 applied, 3 rejected.

*Cost and open.* The witness is held on the record in memory, so a restart loses
it along with `/tx` history; it covers transactions this process tracked, not
arbitrary old leaves. Persisting witnesses or serving them from an archive is
the next step if proofs must outlive the process. The record set is still
unbounded.

## D54 — The devnet is an automated integration test

**Decided (prototype).** `cmd/karsa/tests/devnet.rs` generates a home with
`karsa genesis --init`, starts four `karsa live --node-index i` processes over a
free loopback port block with `--execute`, `--checkpoint-every 0`, and a 25 s
lifetime, and waits until every node has certified two heights before
submitting. `karsa send --wait` then submits a signed transfer through node 0,
and the test reads `/tx/{id}?proof=1` on each node, requiring `finalized` and a
commit proof, plus `/status` with `applied_txs >= 1`, `tracked_transactions >= 1`,
and 0 conflicts. All four must agree on the finalized height and state root.
`Devnet` kills and reaps its children on drop; a failure prints each node's log.

*Measured.* The test passed three runs in a row standalone in 1.35-1.90 s, and
the full gate passed twice (default and all-features). No child process or temp
directory survives the test.

*Cost and open.* Port discovery binds a contiguous block, drops it, and starts
the processes, so a port stolen in that window fails the test. The readiness
gate requires two certified heights per node; the earlier version checked only
node 0's round and timed out waiting for node 2 in the gate. Head roots are not
compared because nodes certify at their own pace; the test compares the header
that finalized the transaction instead. This is the cold devnet; fault and
restart probes remain manual, while the in-process restart test covers the
checkpoint path.

## D55 — One validator authors each transaction, with a fallback lease

**Decided (prototype).** `RpcCore` maps each content id to an owner: the first
eight bytes of the id, read as a little-endian `u64`, modulo the validator
count. `take_batch` selects only transactions this node owns; every node
computes the same owner, so a gossiped transaction has one normal author and
the duplicate batches of D52 disappear. If the owner has not authored within
`OWNER_FALLBACK` (2 s), any node may take the transaction, so a dead owner
cannot strand it. A returned batch restarts the fallback clock, and each
mempool copy carries its own `queued_at`.

*Measured (functional).* Four-process devnet, checkpoint every 64, two transfers
submitted to nodes 0 and 2: both finalized (100 ms and 180 ms), and the
transaction owner was node 3 for both. At shutdown all four nodes ended on
commit root `f0fe5fa8…`, state root `2456fc21…`, applied 2, **0 rejected**, 0
missing payloads. The same two transfers in D52 cost 3 rejected each; the owner
rule removed the duplicate executions.

*Cost and open.* The fallback is covered by
`only_the_owner_authors_a_transaction_before_the_fallback`. A live attempt that
killed node 0 before submitting (the transaction's owner was node 3) never
certified a new height after the kill: head stayed at 1,559, because the dead
node's last vertices were missing from the survivors and no new share reached a
quorum. That is a vertex-delivery gap, not ownership; a want cannot fetch from
a dead node. Testing the takeover live needs a kill that leaves the mesh
certifying. The owner rule also means a node's copy waits for gossip to reach
the owner; the fallback clock starts at each copy's arrival, so a slow link
shifts the takeover time. Records remain in memory.

## D56 — A stalled cursor reports the vertex that blocks it

**Decided (prototype).** The live loop measures how long the commit cursor has
been unchanged. After 1.5 s (`STALL_REPORT_AFTER`) it prints once:
`node i commit stalled at round X (observed Y), missing <digest> at round R by
<author>, votes V of quorum Q, can-anchor B`. The missing id comes from
`Dag::missing_history`; the vote count and the anchor possibility come from
`held_voters` and `can_still_anchor`. Timeouts are not the signal: anchors ahead
keep the pacemaker productive, so `Step::TimedOut` never fires while the DAG
still grows. A healthy 20 s run logs nothing.

*Measured (functional).* A healthy four-process devnet with checkpoint every 64
for 20 s logged no stall lines while its heads advanced from startup. A
probe that killed node 0 at 8.0-9.2 s reproduced the stall twice; both lines
reported `missing none, votes 1 of quorum 3, can-anchor false` at cursors 1,065
and 1,071. That is a missing **vote**, not a missing vertex: the leader and its
history are held, the dead validator's next-round vertex never arrived, and the
no-absence rule refuses either a commit (fewer than two held votes) or a skip
(only two observed non-votes). A synthetic DAG where `val-1` stops authoring at
round 5 and later rounds carry three vertices still passes the cursor through
the missing leader (`a_dead_author_does_not_block_rounds_that_follow_it`), so
the decision logic is not the blocker when the surrounding data is complete.

*Cost and open.* The report costs one history walk plus two tally walks when it
fires and nothing in the normal case. It does not fix the gap; D57 supplies the
missing vote when the node returns. A permanent failure still needs a view
change or a failure detector, which this prototype deliberately does not have.

## D57 — A restart replays its own recent vertices, and a live checkpoint sets the DAG floor

**Decided (prototype).** A node sorts its own held vertices above the DAG floor
and broadcasts the last 1,024 (`RECENT_VERTICES`) once on the first tick after
startup. It also keeps the last 1,024 authored vertex frames in memory, and the
link writer replays them on reconnect. A successful live checkpoint now calls
`Dag::set_floor(floor)` after writing the snapshot, so a vertex that arrives
late at or below the floor is dropped in memory and cannot be written back into
the store the checkpoint just pruned.

*Measured (functional).* Probe with checkpoint every 64, node 0 killed at about
8.4 s: the survivors stalled at cursor 1,065 with
`missing none, votes 1 of quorum 3, can-anchor false`; head 931 and committed
4,254 froze while rounds reached 1,538. Restarting node 0 from its store without
`RESET` made node 1 reach head 1,703 and committed 8,216 within 12 s. The
restarted node itself logged a transient stall at round 1,547 while catching
up, so recovery is not instant. A healthy 20 s run still logged no stall line,
and the checkpoint restart test passes with the store free of below-floor
vertices after `set_floor`.

*Cost and open.* The startup replay sends up to 1,024 frames per peer once, on
the best-effort data queue; duplicates are ignored. It heals a returning node,
not a permanently dead one: an absent vote with no author to replay remains
undecidable under the no-absence rule. The `recent_vertices` ring covers the
same loss on a same-process link break. Recovery from a permanent failure needs
a view change or a failure detector, which is outside the prototype.

## D58 — The failure detector is a local silence report, not a decision

**Decided (prototype).** `validator::FailureDetector` records the last round each
validator was seen at and reports those more than `--failure-rounds` rounds
behind the highest round the node holds. The threshold is in rounds, not wall
time; zero disables it. The detector is seeded from the restored DAG and fed by
every accepted or authored vertex. It is exposed as `/status.silent` (`validator`,
`last_round`) and as one log line per new silence, cleared when the validator
returns. It feeds no commit, skip, or quorum rule: a local view is not shared
evidence, two nodes with different delivery may disagree, and a transition that
acts on a report must be authorized by the set (the checked set-change path in
D41).

*Measured (functional).* Four-process devnet, checkpoints disabled, threshold 50.
Before the kill a survivor's `/status` reported `silent: []`. Node 0 was killed;
after about one second the survivor reported node 0's validator address with
`last_round` 1984 while its highest round was 2035 (51 rounds), and the log line
read `failure detector: 0400601c39bf002c silent (last seen at round 1984, highest
round 2035)`. The other two survivors reported the same author. A healthy run
before the kill reported nothing.

*Cost and open.* The detector stores one last-round entry per validator and
recomputes the silence list per tick, O(n); a delivery gap is reported as quickly
as a dead node, so the threshold trades false positives for speed. It does not by
itself recover the stalled cursor; the restart replay in D57 does that for a
returning node. Permanent failure needs an authorized transition or a view
change, which remains open.

*Revised by D61.* The absolute comparison above was replaced by a
progress-based one: a validator is silent when the highest round advances past
the point at which its own last round last advanced. A node that started a few
rounds late but keeps authoring is therefore not failed forever.

## D59 — A set change is a signed certificate, and activation is deterministic

**Decided (prototype).** A `SetChange` descriptor carries the chain id, the
content ids of the old and new sets, the activation epoch, and a
domain-separated transition hash. `TransitionCertificate` carries that descriptor,
the full new set, and a bitmap of old-set signatures. Nodes merge partial
certificates, verify every signature against the old set, and require a
supermajority before installing anything. `Dag::adopt_set_change` keeps the held
vertices and switches `set_for_epoch` at the boundary;
`Finalizer::adopt_set_change` rebuilds the header chain with the new schedule and
refuses a certificate whose activation epoch is at or below the certified head.
Live nodes build the same descriptor from `--add-validator-at-epoch` or
`--remove-validator-at-epoch`, exchange partial certificates on
`Message::SetChange`, persist the full certificate in `set-change`, and carry it
in `LiveSnapshot` and `wire::Snapshot`. Restart and snapshot join install it
before replay; `karsa audit` verifies it and uses the new set for its header
chain and DAG replay. Wire protocol moved to 7 for the snapshot field.

*Measured (functional).* In-process four-node live test with epoch length 4 and
an addition at epoch 4: all four nodes adopted, 20 of 20 common heights
certified, restart from a checkpoint carrying the transition succeeded, and the
audit printed `set change: epoch 1 -> 4, 4 -> 5 validators`. Four-process devnet,
epoch 32, checkpoints every 64: all four adopted, 927 certified heights, head
927/1147, 0 conflicts; the audit of the checkpoint store verified the anchor
certificate under the new set. The same devnet with checkpoints disabled reached
409 certified heights and the audit re-derived 409/409 state and dag roots above
the boundary.

*Cost and open.* One transition per schedule; the certificate carries a whole
validator set, which is small for Ed25519 and grows with PQ keys. A node that
misses the certificate until after activation rejects it instead of diverging;
repair for that case is view-change work. Who may propose a transition remains a
governance decision; the prototype only checks that the old set authorized it.

## D60 — A quorum fence frees a leader round; local silence is still not evidence

**Decided (prototype).** `Fence` names a validator and the first round it is
failed from; `FenceCertificate` is a supermajority signature over that descriptor
against the set active at the fence round. A DAG accepts at most `f` fences.
After a fence is installed, a new vertex from the fenced author at or after the
fence round is rejected, and authored reference lists omit fenced vertices, so a
delayed leader cannot become a vote. The pacemaker uses two rules after the
direct and indirect rules fail: a missing leader whose author is fenced is
skipped at its own round, and a held leader is skipped when every missing
next-round voter is fenced and at most `f` votes are held. In the second case even a late vote from every fenced validator reaches at
most `2f`, below the `2f + 1` quorum. Live nodes propose a fence only when the
failure detector reports the validator silent, the node has not decided the
fence round, and the validator is the missing leader or a missing voter at the
cursor. Partial fences travel as `Message::Fence`; the full certificate is
stored in `fence` and reloaded before replay. Wire protocol moved to 8.

*Measured (functional).* `a_fenced_leader_is_skipped_without_a_vote_or_anchor`
and `a_fenced_missing_voter_frees_a_live_leaders_round` pin the two rules; the
first also checks that the round is not skipped before the certificate is
applied. The automated four-process devnet test kills validator 0 after twenty
certified heights and requires all three survivors to certify at least five
more, report 0 conflicts, and show `fence_leader > 0` in `/status.skips`; they
do. The skip counters separate the fence rule from the anchor rules, and the
two devnet tests share a lock so their eight processes do not compete for four
cores.

*Cost and open.* The vote-fence rule treats the quorum declaration as
authoritative for the missing voters. It is a liveness/view-change rule, not a
slashing proof: a falsely fenced honest validator that later equivocates remains
outside the crash-fault reading the tests exercise. A store keeps one fence for
the prototype; at larger sets the DAG accepts up to `f`, but the live path
currently proposes only the first. A fully partitioned survivor set beyond the
fault budget is not solved here.


*Multi-fence and audit.* The store keeps a `fences` log instead of a single
`fence` file: each adopted certificate is appended as a record, and `fences()`
reduces the log to the lowest starting round per validator (the promise the DAG
enforces). The legacy single file is still read. The live path holds a map keyed
by validator, proposes a new fence only while fewer than `f` are held, and
rebroadcasts all of them. `karsa audit` applies every stored fence before
replaying vertices, so its replayed order matches the live one. A four-process
devnet with fencing enabled wrote `fences` on each survivor; the audit printed
`fences: 1 (...)` and re-derived every height. A store unit test keeps two
validators' fences and verifies that a lower round replaces the entry while a
higher one is ignored.

## D61 — Silence is lack of progress; a fence skip says which rule proved it

**Decided (prototype).** `FailureDetector` keeps, per validator, the highest
round seen when that validator's last round last advanced. `silent()` reports a
validator when the node's highest round has since advanced by more than the
threshold, not when its absolute round is behind. This removes the constant-offset
false positive: a node that starts a few rounds late but keeps authoring is live.
Live nodes also expose the pacemaker's cumulative skip counters as
`/status.skips` (`direct`, `indirect`, `absent`, `fence_leader`, `fence_voter`),
so a run can say which rule released a stuck cursor. A node never proposes or
signs a fence against itself, and fence proposal is disabled for one wall-clock
second after startup so a tight `--failure-rounds` cannot fence a peer that has
not finished connecting.

*Measured (functional).* `a_constant_lag_is_not_silence` keeps `val-3` five
rounds behind for twenty rounds and the detector stays quiet. The two fence unit
tests now assert the counters: only `fence_leader` or only `fence_voter` moves,
so no other rule can explain the advance. A 20 s release devnet with threshold 50
and validator 0 killed reported `fence_leader: 40` on each survivor while the
chain kept certifying; before the kill the same counter was zero and `silent`
was empty. The automated devnet test starts from twenty agreed heights because an
earlier kill leaves cursors far apart.

*Cost and open.* Counters are cumulative for the process and not persisted. The
fence descriptor still carries a `from_round` that must equal the signer's own
missing-leader or missing-voter round, so survivors with diverged cursors can
propose different rounds and fail to combine a quorum. That happened in one
debug run (rounds 60 and 64); making the failure declaration independent of each
signer's cursor is the next view-change step.

*Resolved by D62.* The fence round no longer depends on the signer's cursor.

## D62 — A fence round comes from the failed validator, not the signer's cursor

**Decided (prototype).** The fence descriptor's `from_round` is the failed
validator's last observed round plus one (raised to the DAG floor), independent
of the proposer's cursor. A signer may sign any fence whose round is above its
own last observation of that validator, provided the validator is in the set at
that round and the fence is above the DAG floor; it no longer has to be stuck on
the same cursor round. A later proposal for the same validator supersedes an
earlier partial, and a completed certificate is applied even when a different
partial is pending. Safety: a signer that has not seen the validator at or after
`from_round` cannot have voted for it there, so the quorum promise that at most
`f` votes exist still holds.

*Measured (functional).* Before this change, debug survivors proposed fences at
rounds 60 and 64 from their own cursors and the shares never combined. With the
new rule, a release devnet with threshold 15 and validator 0 killed had all three
survivors report `last seen at round 1869` and propose round 1870; the
certificate formed, `/status.skips.fence_leader` reached 30 on every survivor,
and the chain kept certifying. The automated devnet test now asserts
`fence_leader > 0` and serializes the two devnet tests so eight processes do not
compete for four cores. `a_signed_fence_share_stops_this_node_referencing_the_author`
pins the local promise: the node's next vertex omits the fenced author, still
meets the reference quorum, and still accepts the author's later vertices.

*Cost and open.* The signed share is now a local fence: the node stops
referencing that author from the fence round on (`Dag::note_local_fence`) while
still accepting the author's vertices, so the promise is enforced immediately
without pruning the DAG. The promise is in memory only, so a restart forgets a
partial certificate that never completed. Fences are still one per store in the
live path, and the failure detector is built from the base set, so a set change
does not yet refresh its author list.

## D63 — The failure detector follows the active validator set

**Decided (prototype).** `FailureDetector::update_set` rebuilds the tracked
author list from a `ValidatorSet`, keeps `last` and `advanced_at` for validators
that remain, and drops entries for validators that left. Live rechecks the active
set each tick with `Dag::set_for_round(node.round())`; when its epoch changes, the
detector is rebuilt. A key rotation keeps every identity, so it leaves the
observations untouched. A removal therefore stops producing silence reports once
the boundary is crossed, and an addition is tracked from the epoch it becomes
active.

*Measured (functional).* `a_removed_validator_is_no_longer_tracked` observes all
four authors, lets `val-3` go silent, then updates to a three-validator set and
requires the report to disappear. A five-validator release devnet with a removal
at epoch 4 and `--fence-silent` adopted 5/5; no removed validator was reported
silent or fenced after the boundary, and the run reached 1,577 certified heights
with 0 conflicts and one commit root across all five stores.

*Cost and open.* The rebuild is O(n) per epoch change, not per tick. A newly
added validator starts unseen, so it can be reported after the threshold if it
does not run; the fence proposal still checks membership at the fence round, so a
fence cannot act before the new set is active. The detector's history for a
returning validator is not reconstructed across a restart beyond the vertices
the store still holds.

## D64 — Fences travel in snapshots, and a fence survives the floor moving past it

**Decided (prototype).** A snapshot carries every quorum fence its sender's DAG
adopted, not only the ones above its floor: a fence at round `R` excludes that
validator from every later round, so dropping it at a checkpoint would let a
joiner wait on a leader the quorum already declared failed. `wire::Snapshot`
gains `fences` (wire protocol 9) and `LiveSnapshot` version 4 adds the same list;
version 3 records still read with an empty list and their transition intact. A
joiner seeds the committed prefix and floor, installs the certificates, then
replays the tail. A tail vertex from a fenced author at or after its round is
skipped: it arrived before the fence, is not a vote, and a fresh DAG would reject
it — so it cannot ride into the join and create a restart the joiner cannot
reproduce. The certificates are persisted with `put_fence`, so a later restart
finds them in `fences` even when it does not use the snapshot.

`Dag::apply_fence` no longer rejects a certificate whose round is at or below the
DAG floor. The rounds below the floor are already decided, but the declaration
governs every later round; rejecting it made a restart fail once a checkpoint
advanced the floor past a fence the store still held. The retained order above
the floor is still checked, and `karsa audit` now replays the stored vertices
before applying the fences, matching a live restart: a vertex held before the
fence stays in the DAG but cannot become a vote.

*Measured (functional).* `a_fence_below_the_floor_still_applies_to_later_rounds`
pins the floor rule,
`a_snapshot_join_installs_fences_and_drops_inert_tail_vertices` adopts a
snapshot whose tail holds both an inert fenced vertex and a live one, and
`a_version_three_live_snapshot_keeps_its_transition_and_has_no_fences` pins the
store compatibility. The wire and store round-trip tests carry a fence.

*Cost and open.* A snapshot repeats the full certificate list (one bitmap and
one signature per signer per fence), bounded by `f`. Cold joins still learn new
fences from the snapshot or rebroadcast, not from a separate fence-sync request.
*Resolved by D65:* a signed share is persisted, so a restart no longer forgets a
proposal that never reached a quorum.

## D65 — A signed fence share is a durable promise

**Decided (prototype).** A node that signs a fence share before the quorum
completes stores it in a `fence-shares` log. The record is the signed
`FenceCertificate` with one signer; the log also carries a tombstone for a
proposal the node abandons. Reading reduces the log per validator to the lowest
starting round, and a later share after a tombstone takes effect again. On
startup the shares are loaded after the set schedule (snapshot transition
included) is installed, checked against the set active at each fence round, noted
as local promises before the loop authors anything, and seeded into the pending
map so the node keeps collecting the same quorum and rebroadcasts the share. The
record is cleared when the full certificate is adopted (the certified fence then
carries the promise) or when the validator is visible again and the partial is
stale.

*Measured (functional).* `a_local_fence_share_round_trips_and_a_clear_removes_it`
keeps the lowest round, ignores a higher one, and re-adds a validator after a
tombstone. `a_restarted_node_reloads_its_signed_fence_promise` signs a share,
drops the node, and requires the reloaded DAG to report the author locally
fenced from the declared round.

*Cost and open.* The share is re-verified with every signature at startup; for a
large set and PQ keys this is bounded by `f` shares. A node that crashes between
adopting a certificate and clearing its share leaves one redundant record, which
the loader skips because the adopted certificate wins.

## D66 — Two fences coexist at seven validators and the budget is enforced

**Decided (prototype).** The fence rules were exercised below the fault budget in
the four-validator mesh; this decision covers `f = 2`. Three deterministic DAG
tests pin the arithmetic: two certificates coexist at seven validators and a
third is refused with `TooMany { count: 3, limit: 2 }`; a held leader whose two
missing voters are both fenced is released with five held vertices; and three
held votes block the same skip even when the missing voters are fenced, because
the held-vote cap is `f`. The live path was then run with seven processes and
validators 0 and 1 killed after 1,317 agreed heights. All five survivors proposed
and adopted both certificates at round 1,523 (the dead validators' last observed
round plus one), continued certifying, and reported 0 conflicts. `karsa audit` on
a survivor printed `fences: 2 (0400601c39bf002c, 097347e2d48326b8)` and re-derived
all 1,604 state and DAG roots.

*Measured (functional).* The predicates are
`two_fences_coexist_at_seven_validators_and_a_third_is_refused`,
`two_fenced_missing_voters_free_a_live_leader_at_two_faults`, and
`three_held_votes_block_a_fence_skip_at_two_faults`. The devnet ran with
`FENCE_SILENT=1 FAILURE_ROUNDS=15 CHECKPOINT_EVERY=0`; no timing was measured.

*Cost and open.* With two of seven validators dead the five survivors still form
a quorum, so the absent-leader rule can often release a missing leader before the
failure detector reaches its threshold; the fence rule runs first when it exists,
but the live evidence only covers this one kill pattern. Two fences can name the
same round when both validators were last seen together; diverged views still
rely on D62's round choice. Fences remain a liveness declaration, not a slashing
proof.

## D67 — A fenced validator can cold-join from a snapshot and stays passive

**Decided (prototype).** A node that a quorum has fenced still follows the chain.
`Node::author_with` now returns `Ok(None)` when the DAG reports this node fenced
at its round, instead of signing a vertex every peer would reject and failing the
live loop with `cannot author`. The round advances to the newest held vertex, so
the next tick evaluates the current set. `a_fenced_node_follows_without_authoring_or_failing`
pins both the `None` and the round advance; the rest of the committee keeps
authoring and the passive node receives their vertices.

The cold-join path was then run end to end. Five validators, fencing enabled,
checkpoints every 64. Validator 0 was killed after roughly 490 certified heights;
the four survivors fenced it at round 523 and kept certifying. Validator 0's store
was deleted and the process restarted with `--sync-from-peers`. It adopted a
peer's snapshot at height 817, round 924, floor 922 — above the fence round — with
25 tail vertices, caught up to the survivors, and continued to a 1,921-height
checkpoint. `karsa audit` on the joined store printed
`fences: 1 (0400601c39bf002c)`, treated the live snapshot certificate as the trust
anchor, and re-derived all 60 heights above it. The fence round being below the
snapshot floor is exactly the case D64 allows; without that change the join would
have rejected the certificate.

*Measured (functional).* The devnet used
`VALIDATORS=5 FENCE_SILENT=1 FAILURE_ROUNDS=15 CHECKPOINT_EVERY=64` and a
180-second lifetime; no timing was measured. The snapshot log line was
`adopted snapshot height 817 round 924, floor Some(922), 25 tail vertices`.

*Cost and open.* The joiner verifies the anchor certificate and every carried
fence, then replays only the tail. A fenced node never authors again under the
prototype's permanent fence; returning it to service needs a later set change or
a view-change rule, neither of which exists. The test wipes the store on purpose,
so it does not cover a store that still holds pre-fence history.

## D68 — Rejected: a complete next round is not enough to skip without an anchor

**Tried (reverted).** When the cursor is stuck, `try_commit` has already found
less than a quorum of votes. If every author of the next round is accounted for
(vertex held or fenced), no further vote for the leader can appear, so the round
looked safe to skip without an anchor: `Dag::round_is_complete` plus
`Dag::skip_complete_round`, called from the pacemaker only when no anchored round
exists ahead. A new `complete` skip counter attributed the decision.

The mesh tests rejected it. `a_small_run_certifies_every_sample_and_agrees`
failed with "every node must credit every sample", and
`a_mesh_authorizes_a_set_change_and_crosses_the_boundary` failed with "nodes did
not converge on the same commit root"; the first order difference was at round 0
or 1 between val-0 and val-2/val-3. The change was reverted.

**Why it diverges.** Completeness is a local view. The node that holds the whole
next round skips immediately; a node that is missing one vertex waits. If the
waiting node later receives the vertex, it still cannot commit the leader by a
vote quorum, but the canonical lowest-anchor rule may commit that leader's
history at a different point in the order. The commit order is a function of the
DAG, and a local completeness proof is not a quorum statement, so two nodes can
pick different orders. The indirect rule deliberately waits for an anchor for
exactly this reason.

**Consequence.** The live stall observed at `cursor 73`, `votes 2 of quorum 4`,
`missing none`, `can-anchor false` with a dead validator whose last observed
round was 75 remains open. A safe fix needs a quorum declaration, not a local
proof: for example, a view-change certificate in which a supermajority attests
it did not vote for the leader of round `r` and will not, so at most `f` votes
can exist and the round can be skipped. That certificate would need the same
dissemination and persistence treatment as a fence, and a safety argument that
covers a node that already voted (it cannot sign the attestation). This is the
next view-change step; the complete-round shortcut must not be reintroduced.

## D69 — A round skip needs evidence that no vote quorum can exist

**Decided (prototype).** `RoundSkip` pins the leader vertex a set of validators
refuses (`round`, `author`, `digest`); `NoVoteAttestation` carries a bitmap and
one signature per signer over a domain-separated payload
(`KARSA/DAG/ROUND-SKIP/v1`). A signer may sign only when it has not voted:
`RoundSkip::may_sign` accepts a missing voting-round vertex (the signature then
promises to abstain) or an authored one that does not reference the leader, and
rejects one that does. `RoundSkipProof` partitions the voter set active at the
voting round into held votes, held non-votes, attested non-voters, absent voters
covered by a quorum fence, and explicit missing voters. Verification requires an
exact partition, verifies every attestation signature against the voter set and
every carried fence against the set at its own round, resolves every listed vote
and non-vote through a caller-supplied lookup, and admits the proof only when
`votes + fenced_absent + missing` plus the fault budget charged for an
attestation stays below the quorum. A listed id this node does not hold is
`MissingEvidence`, so a node with less history waits instead of accepting a
weaker proof.

*Measured (unit).* Fourteen unit tests pin the primitive: a quorum attestation
verifies and a short one is rejected; chain and leader are bound; partial
attestations merge until quorum; a validator that already voted cannot sign; a
held non-vote plus one missing voter bounds two votes at three of four; an
attestation charges the fault budget; an uncovered voter, an overlapping voter,
two votes plus two missing voters, a non-vote listed as a vote, an unheld id, and
a fence starting after the voting round are rejected; the attestation and the
proof round-trip.

*Cost and open.* This decision defines the evidence only. D70 adds the DAG
consumer and the pacemaker rule; nothing is on the wire yet, so the `cursor 73`
stall is not released live. The next stage must decide where the certificate is
recorded: a control frame alone lets a node that misses it diverge, and D68
showed that the skip decision changes the commit order when nodes decide at
different times.

## D70 — The pacemaker consumes a verified round-skip proof

**Decided (prototype).** `Dag::apply_round_skip` verifies a `RoundSkipProof`
against the voter set active at the voting round, the set active at each carried
fence, and the vertices the DAG holds. The named leader
must be the vertex this DAG elected and holds for the round; a proof for another
vertex at the same round is refused. The verified proof is stored by round, and
`Dag::skip_with_attestation` records a skip only when it still matches the held
leader. The pacemaker runs this rule after the two fence rules and before the
anchor rules, and attributes the move to a new `attested` counter.
`/status.skips` exposes it as `attested`.

*Measured (unit).* `a_verified_round_skip_proof_frees_the_stalled_leader`
reproduces the live shape: five validators, `f = 1`, quorum four, cursor 73,
leader `val-3`, round 74 held from `val-1..=val-4` with two votes and two
non-votes, `val-0` missing. `try_commit(73)` is `Undecided`; the proof verifies
`votes = 2`, `non_votes = 2`, `missing = 1`, `possible_votes = 3 < 4`; the
pacemaker moves the cursor to 74, reports `attested = 1`, and records the skip at
round 73. `a_round_skip_proof_for_another_leader_is_refused` pins the leader
binding: a proof with a different digest is refused and is not stored.

*Cost and open.* The proof is built and applied in-process here. D71 adds the
wire message, the store log, and the live builder; the live run shows that a
control frame is not a decision record, so the path stays opt-in until the
certificate is recorded in the DAG.

## D71 — A control-plane round skip is not deterministic enough

**Tried (opt-in).** Wire protocol 10 adds `Message::RoundSkip`; the store keeps
one proof per leader round in a `round-skips` log, restarts apply them before
the replay, and a live node builds a proof from its own DAG, verifies a
received one, persists it, and rebroadcasts it. `--round-skip` enables the local
builder; without the flag the node only adopts proofs it receives, and the
default chain does not use the rule.

*Measured (functional, failing).* A four-validator release devnet with
`ROUND_SKIP=1 FENCE_SILENT=1 FAILURE_ROUNDS=15 CHECKPOINT_EVERY=64` reached
rounds near 2,500 and all four nodes reported the same committed length (9,706
entries) and one certified head, but finality stopped at height 16. The tip
order root was not compared, so this run proves the finality grouping
diverges; it does not prove the committed order is identical. Each node
records one header per local commit decision; a node that adopts a skip proof
first skips a round another node still commits through an anchor, so the same
prefix is split into headers at different heights. The shares then name
different headers and never combine. The rule also fires often on this devnet
(about 200 `attested` skips in twenty seconds) because voters author without the
leader when delivery is slower than the round, which makes the grouping race
regular rather than rare.

*Rejected fix.* Deriving the header round from the highest round in the newly
committed slice was tried: it removed the slot from the header id but not the
grouping, and finality still stopped at the first divergent grouping. It was
reverted.

**Consequence.** The proof is a sound local statement but a control frame is not
a decision record. The live path stays opt-in and unproven, and the default gate
is unchanged. The next stage must record the skip certificate where the DAG can
replay it (a vertex payload field or a canonical header boundary), so every node
commits the same prefix at the same height before the cursor moves. This is the
same requirement D59 met for set changes by carrying the certificate in the
snapshot and the store, and it is the last blocker for freeing `cursor 73`
without the finality race.

## D72 — Stage B: a certificate only counts inside the selected anchor's history

**Tried (opt-in).** Wire protocol 11 adds `ControlPayload` and
`Message::Control`; a vertex names a round-skip certificate by hash and the live
builder authors that binding vertex. The first live version let a held proof
preempt the anchor rule and made the pacemaker wait on a pending payload. A
four-node devnet converged on one certified head but finality stopped there: a
node with the certificate skipped while a node with an anchor committed the
leader's history, splitting the same prefix across different header boundaries.

**Revised (stage B).** The preempting rule and the pending wait are gone. A held
certificate is no longer a decision. `Dag::anchor_skip` walks the causal history
of the anchor the pacemaker actually selected and reports a certificate only
when:

- the binding vertex is an ancestor of that anchor;
- the leader the proof names is an ancestor;
- every vote and non-vote the proof lists is an ancestor.

A listed id outside the history is not causal evidence for this anchor and is
ignored. An ancestor the node does not hold is `MissingReference`, so the caller
repairs the anchor history instead of deciding on a partial one. If more than
one valid proof is in the same history, the reported one is chosen by digest
order; both imply a skip, so the decision does not depend on which arrives
first. A proof that is not in the selected anchor's history does not delay the
decision at all.

**Stage B keeps the anchor decision.** The pacemaker calls `anchor_skip` before
`try_indirect_decide` to prove the causal path is complete, but it ignores the
returned certificate: a round that the anchor rule commits still commits. The
purpose is to isolate the determinism question from the transaction question.
Overriding a commit with a skip changes what happens to the skipped leader's
batch, and that needs a recovery path before it is used live.

*Measured (unit).* Four new tests pin the stage-B rule:
`a_certificate_in_the_selected_anchors_history_does_not_change_the_decision`
(reported, anchor still commits, `attested` stays 0),
`a_certificate_outside_the_selected_anchors_history_is_ignored`,
`a_certificate_whose_evidence_is_outside_the_anchor_history_is_ignored`, and
`a_missing_ancestor_stops_the_certificate_check` (`MissingReference`). The full
gate passes: fmt, clippy `-D warnings`, 478 default tests and 479 all-features
tests.

*Measured (functional).* A four-validator release devnet with
`ROUND_SKIP=1 FENCE_SILENT=1 FAILURE_ROUNDS=15 CHECKPOINT_EVERY=128` built about
200 certificates per node and stayed healthy: after twenty seconds three nodes
reported the same certified height 2,368 and 10,463 committed entries, the
fourth was two heights ahead, and `attested` was 0 on every node. No node
skipped a round on the certificate; the chain followed the anchor rule exactly.

**Open.** Stage A will let a valid causal certificate turn a commit into a skip.
That is only safe to run live after a skipped batch is returned to the mempool
(or otherwise re-authored), because the leader's transactions are not final
through that anchor. The recovery path needs retry, deduplication, and
persistence tests of its own. Until then the default chain does not use the
certificate rule.

## D73 — Stage A: a causal certificate can turn a commit into a skip

**Superseded by D74.** The override described here forked the committed order in
an A/B devnet; the batch-recovery half survives, the override does not.

**Decided (opt-in, later removed).** With `--round-skip`, a valid certificate inside the
selected anchor's causal history now turns a reachable leader's `Commit` into a
`Skip`. The check runs before `try_indirect_decide`, because that call commits
the leader's history as a side effect. The override increments `attested` and
never runs when the direct vote quorum already commits the round.

**Batch recovery.** A skip leaves the leader's batch out of the committed order,
so its transactions are not applied. `RpcCore::readmit_batch` returns them to
the mempool from the batch content. It handles two shapes:

- the author still has the record from admission: clear its batch and vertex
  binding, then queue the envelope again;
- a restart has no records: verify the envelope like a client submission, check
  the restored sequence, and create the record.

`recover_skipped_batches` runs after every commit loop and once after restore.
It looks up the skipped round's author and digest, ignores a vertex already in
the order or below the floor, and is idempotent because the recovered
transaction's record dedupes the second attempt. If the skipped vertex later
commits through another anchor, the execution sequence rule rejects the
recovered copy, so a transaction cannot apply twice.

*Measured (unit).* Three new tests pin the recovery: a fresh core readmits a
batch from its content, the author's existing record is reused, and
`return_batch` makes the batch authorable again. The full gate passes: fmt,
clippy `-D warnings`, 481 default tests and 482 all-features tests.

*Measured (functional).* A four-validator release devnet with
`ROUND_SKIP=1 FENCE_SILENT=1 FAILURE_ROUNDS=15 CHECKPOINT_EVERY=128` reached
2,370-2,374 certified heights in about twenty-five seconds with 41-43 attested
skips per node; finality stayed within four heights across nodes. A submitted
transfer finalized in 100 ms. That single transaction did not land in a skipped
batch, so the devnet did not exercise `recover_skipped_batches`; the path is
pinned by the unit tests.

**Open.** A targeted devnet that puts a transaction in a skipped leader's batch,
a restart between the skip and the re-author, and the case where the author is
down while a peer holds the batch. The recovery path exists, but those three
runs are not measured yet.

## D74 — A causal certificate must not override an anchor commit

**Decided.** The stage A override (D73) is removed. A round-skip certificate is
reporting evidence, never a decision: the pacemaker checks only the anchor rule
and the fence rules for `Commit`/`Skip`, so `attested` stays zero. The
certificate is still verified, persisted, bound to a vertex, and reported by
`Dag::anchor_skip`; it cannot turn a reachable leader's commit into a skip.

**Why.** A certificate is negative evidence and arrives asynchronously. A node
that held the certificate inside its selected anchor's history skipped the
round; a node that had not received the binding vertex yet committed the same
round through `try_indirect_decide`, which commits every leader reachable from
the anchor without requiring a vote quorum for that leader. The orders fork
permanently:

- `ROUND_SKIP=1 FENCE_SILENT=1`, four validators, thirty seconds of client
transfers: node 0 `commit_root=9b88c815...`, nodes 1-3 `f9f1ba05...`, while all
four shared `state_root=5a01418f...`. The diverging node reported 65 attested
skips against 68 on a peer.
- The same load with `ROUND_SKIP` off: all four nodes
`commit_root=46275d46...` and `state_root=6b5abab2...`.
- Without `FENCE_SILENT` but with `ROUND_SKIP`, certified heights stopped at 517
while committed entries grew past 16,000; the same load without `ROUND_SKIP`
certified steadily (1,455 to 2,026 in ten seconds).

**What stays.** `RpcCore::readmit_batch` and `recover_skipped_batches` stay:
fence and absent skips still leave a leader's batch out of the order. A live
devnet observed `re-admitted` lines from those rules on every node.

**Measured (fixed build).** `ROUND_SKIP=1 FENCE_SILENT=1`, thirty seconds of
transfers: 590 submitted transactions, 590 applied, identical
`commit_root=24f4a493...` and `state_root=25131fa9...` on all four nodes,
`attested=0`, and 1/4/7/7 `re-admitted` events per node. The three client
failures were `/account` HTTP 409 (the certified applied count was older than
the retained state window), not submission or finality failures.

**Open.** A deterministic certificate rule still needs a causal cutoff that
proves the round cannot be committed by any anchor, not merely that no vote
quorum can form. Without that cutoff, an asynchronous certificate cannot decide
a round.

## D75 — A fenced validator is not a possible voter

**Decided.** `Dag::can_still_anchor` now excludes a validator that is fenced
from the voting round. A missing leader whose author is fenced also makes the
round impossible immediately. The rule feeds `stable_anchor`'s between-round
scan: before this, a fenced validator counted as a possible vote, so a round
whose leader was already failed stayed "possible" and the scan refused to use a
higher anchor.

**Why it matters.** A node killed and restarted at its own fence round stalled
forever on the round just before the fence. It held the previous leader, had two
votes of quorum three, and `can_still_anchor` said the next round could still
anchor even though the fence already said the next leader (the restarted node)
could never produce a vertex there. The survivors, which crossed the fence
before it was complete, moved on; the restarted node waited.

**Measured.** Four validators, `ROUND_SKIP=1 FENCE_SILENT=1 FAILURE_ROUNDS=15`,
node 3 killed at round ~2356 and restarted six seconds later:

- before the fix, the restarted node stalled at round 2356 with `votes 2 of
  quorum 3` and never advanced;
- after the fix, it passed 2356 and kept committing (9,418 to 11,568 entries in
  the remaining ~43 seconds) with no stall. The survivors committed 16,320
  entries; the restarted node was still catching up when the run ended, so this
  proves the fence stall is gone, not full convergence.

**Unit test.** `a_fenced_missing_leader_cannot_anchor` pins the missing-leader
case; the voter case is the same filter.

## D76 — Pruning floors gossip, and a hard reseed trigger is logged before it acts

**Decided.** `WIRE_PROTOCOL` 15 adds `Message::Floor { validator, floor }`. A
validator broadcasts `dag.floor()` when it starts, whenever a checkpoint moves
it, and every 500 ticks (about one second). A receiver records the floor per
validator in the set current at its own round, exposes the map at
`/status.peer_floors`, and logs a hard trigger when a missing commit dependency
has exhausted its want budget and sits at or below every peer's floor. The
trigger is log-only: no reseed path exists yet.

**Why.** A node that cannot repair a want has no way to tell a pruned peer from
a silent one. The gossip is the input a reseed decision needs, but acting on a
self-reported, unauthenticated floor before the reseed install is atomic would
add a liveness attack surface: a Byzantine peer could inflate its floor to push
the node out of a healthy mesh. The frame names its sender because the
handshake binds the chain, not the identity, so the value is diagnostic and no
safety decision uses it.

**Measured.** Four validators, in-process live mesh, checkpoint every four
heights, ten transactions per batch: every node logged peer floors, the values
advanced with checkpoints, and the run ended with `same commit root true` at 65
committed entries and equal state roots. The hard-trigger line is covered by
unit test but has not appeared in a run; reaching it needs a dependency pruned
by every peer.

## D77 — Compare state roots only on the same applied prefix

**Decided.** A `live` mesh no longer fails because a node at the drain boundary
has applied fewer transactions. The commit root is already compared at the
shortest common committed index; the state root is compared only when all nodes
applied the same count or committed the same length. Equal committed length with
different state still fails.

**Why.** A state root is a function of the applied prefix. A node still catching
up holds a shorter prefix, not a divergent state, and failing on different roots
made a short `--checkpoint-every` run exit 1 whenever the drain ended first.

**Measured.** Four validators, checkpoint every four heights, 20 rounds, ten
transactions per batch, 300 ms drain: committed lengths 51..54, applied 510 vs
540, `same commit root true` at 51 common committed entries, exit 0 with state
roots reported as not comparable.

## D78 — A snapshot pin has a budget and an explicit release

**Decided.** A served snapshot pins one floor with three independent bounds: the
ordinary 60 s TTL after the last request, a hard 300 s cap from the first
request, and a byte/request budget (512 MiB, 16 requests). The first request in a
window is always served; later ones are declined with `PinBusy` so the joiner
fails over instead of believing the history is protected. A joiner that
installed a snapshot sends `Message::SnapshotRelease { floor }` (wire protocol
16). The server marks the pin released and keeps a 10 s grace, because another
joiner may still be installing the same snapshot; a new request during the grace
clears the marker. Only the floor the pin actually covers can release it.

**Why.** A TTL that slides on every request lets one client defer pruning
forever. A release lets a healthy joiner tell the server it is done, so the next
checkpoint can prune without waiting the full window. The budget is deliberately
smaller than the possible join traffic: refusing a snapshot is visible and
recoverable by failover, while silently serving history that is about to be
pruned is not. The release frame is unauthenticated like the request; it can
only shorten a liveness pin, never change which history a server accepts.

**Measured.** Unit tests cover the lowest-floor rule, TTL and max-age expiry, the
byte and request bounds, the first-request exemption, and the release grace. The
release frame round-trips and is exercised against a real loopback snapshot link.
An end-to-end `--sync-from-peers` run that observes the server's release line is
still pending; the manual attempt was cut short by a stale process holding a
snapshot port, not by a release failure.

## D79 — A running node reseeds when repair cannot succeed

**Decided.** A node that executes and has a snapshot port now acts on a hard
trigger instead of only logging it. The fetch runs in a separate task so the
loop keeps serving; one attempt at a time, with a 10 s cooldown after a failure.
The snapshot is verified by the same `adopt_snapshot` path as a cold join, and
the live snapshot is written last. Four triggers qualify:

- a missing history vertex that has exhausted its want budget and sits at or
  below every current-set peer's floor (D76's trigger);
- a missing leader slot: `missing_history` cannot name a leader it never held,
  so the slot is checked by round and author against the same floors;
- a missing vote quorum: `missing_history` walks the leader's causal history,
  which does not contain the voting round's vertices; the slot requests are the
  repair path, and the trigger fires once the cursor has stood still for 1.5 s
  and every peer's floor covers the voting round;
- a finality gap: the certified head has not moved for 5 s while the DAG is at
  least 256 rounds ahead. This is what a node that missed a certificate share
  while it was down actually hits: the DAG catches up through vertices, but the
  first missing height cannot advance, so no later share helps.

**Safety rule.** A snapshot may be shorter than this node's committed *DAG*
order, but never shorter than its **certified** order. Entries above the
certified prefix are committed but not final; their vertices and batches stay
in the DAG and the store, so the live loop can commit them again. Refusing a
shorter ordered snapshot was measured to leave finality stuck behind a share
gap. The authoring round only moves forward (`max(saved, adopted)`) so a reseed
cannot make the node sign a second vertex for a round it already voted in; the
decision cursor follows the snapshot, which is the consistent cut every peer
decides from.

**Measured.** Four validators, `CHECKPOINT_EVERY=32 FAILURE_ROUNDS=15
--fence-silent`, node 3 exited gracefully after 20 s, the survivors fenced it
from round 2282, node 3 restarted 50 s later:

- hard vote trigger at round 2277: `votes 0 of quorum 3`, peer floors
  4491/4492/4495;
- snapshot from a peer: height 4790 round 5872, floor 5870, committed 19,854,
  tail 13 vertices, install 5 ms; the server's pin was released after install;
- final state on all four nodes: committed 23,592, certified head 5,725/7,118,
  `commit_root 8617a033…`, `state_root 690cb32b…`, conflicts 0. The restarted
  node authored 0 (it adopted its own fence) and followed; its store ended at
  35 KB after pruning 7,373 vertices below the adopted floor.

Two operational notes came out of the runs. The floor gossip is control traffic
and can be stale while a node drains a large vertex backlog (one restart saw
floors 504/778/779 while the peers were past round 5,000); the finality-gap and
1.5 s slot triggers are what released that node. A snapshot server can decline
at its own certified head when it lacks the committed order length
(`the certified head has no committed order length`); the joiner failed over to
another peer, which is the intended behaviour.

**Open.** A process killed with SIGTERM during a checkpoint can leave a store
whose latest header is not reproducible from the retained tail
(`the certified head does not match any committed prefix`). The measured reseed
used a graceful `--timeout-seconds` exit; crash-consistent recovery from a
mid-checkpoint kill is still open. D80 decides the recovery.

## D80 — A restart resumes only at a certified head the store can prove

**Decided.** `restore_live` no longer requires the last stored certified header's
`dag_root` to match a replayed prefix. It replays the retained tail once, walks
the stored headers in height order, and keeps the longest prefix whose roots the
replay reached. The header log is rewritten above that height through a
temporary file and rename (`Store::truncate_headers`), the finalizer adopts only
the kept headers, and the node resumes at that certified head. A drop is
reported with the height, the number discarded, and the previous top. A store
whose top header is reproducible takes the same path as before.

**Why.** A node can certify a peer-built header faster than it receives the
vertices behind that header's `dag_root`. `put_header` persisted the certificate
as soon as the finalizer advanced, so an abrupt stop could leave a header log
longer than the order the store could replay. `restore_live` then failed with
`the certified head does not match any committed prefix`, and `karsa audit`
could not re-derive those heights either. The committed entries above the last
provable header are not lost: the node still holds their vertices and commits
them as gossip or a reseed catches up. What must not happen is writing a head
the store cannot re-derive. The live snapshot anchor is kept, so the fallback is
deterministic across restarts; a new checkpoint still waits for a self-built
certified head with known coverage, because a dropped peer header has no
committed order length.

**Measured.** Four validators, `CHECKPOINT_EVERY=32 FAILURE_ROUNDS=15
--fence-silent`; node 3 paused 15 s, resumed 200 ms, then SIGKILL. Store:
1.69 MB header log, 3303 certified heights 1953..=5255, live snapshot anchor
1953. Before the change, a restart exited at the end of its lifetime with
`the certified head does not match any committed prefix`; `karsa audit`
re-derived 364 of 3302 heights and exited 1.

The same store restarted with the change:
`restart: the retained order reproduces height 2317, dropped 2938 stored headers
above it (top 5255)`, `replay: 9960 committed entries in 1219 ms`, certified
head 2317. With `--snapshot-port 0` (no reseed) the store ended at 365 headers
(1953..=2317); `karsa audit` re-derived 364 of 364 heights above the anchor and
exited 0. With a normal snapshot port the node then reseeded and adopted a peer
snapshot at height 15872; `karsa audit` also exited 0. A unit test appends a
certified header whose root the order cannot reproduce, restarts the mesh, and
checks both the truncated header log and a successful audit.

**Open.** The live loop still persists every certified header before checking
that its `dag_root` is in the retained order. The fallback heals such a store on
the next restart, but a crash can leave one unprovable interval until that
restart. Filtering at write time needs the coverage stored in the header record
(a store-format change) and a gapless-log story for audit.

## D81 — A rate estimate can release a soft reseed

**Decided.** Besides the four hard triggers, the live loop estimates whether
waiting can close its backlog. `mu` is the cursor's decisions per second, `lambda`
is how fast the DAG tip moves, and `B` is the rounds observed above the cursor.
Both rates come from a 10 s moving window sampled every 200 ms; repeated samples
are kept so a frozen counter decays to zero instead of holding an old rate. The
estimate is `T = B / (mu - lambda)` when `mu > lambda`, and unbounded when it is
not. A soft reseed needs `B >= 256`, a live network (`lambda > 0`), and either
`mu + 0.5 < lambda` (losing ground) or `T >= 60 s`; the condition must hold for
5 s (hysteresis). It shares the one-fetch slot and the 10 s cooldown with the
hard triggers, and hard triggers win when both are true. The pressure clock is
reset when an attempt starts or ends, and after an adopted snapshot.

**Why.** The hard triggers only fire after repair has failed: a dependency below
every peer's floor, a pruned vote quorum, a missing leader slot, or a certified
head that has not moved. A node can instead be committing steadily but slower
than the network, with a backlog that will never close; waiting for one of those
failures wastes the window in which a snapshot is cheap. Measuring the rates also
keeps the loop from reseeding for a **globally** stalled chain (`lambda = 0`),
where a snapshot cannot help, and from firing on the normal one-round authoring
lead.

**Observability.** Before a fetch the node logs either the hard trigger or
`soft catch-up pressure` with `B`, `lambda`, `mu`, and `T`, then the fetch line
carries the reason and the local committed index. On adoption the log names the
serving peer, anchor height/round, floor, snapshot committed index, the local
height/round and committed index from trigger time, the rates, the estimate, and
the install time. `/status` reports the live `catchup` estimate
(`backlog_rounds`, `lambda_rounds_per_s`, `mu_rounds_per_s`, `catchup_ms`,
`soft_pending_ms`) and the last adopted `reseed` with reason, detail, boundary,
local committed index, rates, backlog, estimate, serving peer, and install time.

**Measured.** Four validators, `CHECKPOINT_EVERY=32 FAILURE_ROUNDS=15
--fence-silent`; node 3 killed at 10 s and restarted 20 s later. It replayed 5845
entries, then a hard vote trigger at round 1463 reported `votes 2 of quorum 3`
with `lambda 684.0/s`, `mu 0.0/s`, backlog 2561. It adopted a snapshot at height
3380 round 4193, floor 4191, committed 14044 (local was 5849), install 4 ms; the
same fields appeared under `/status.reseed`. The other three nodes reported
backlog 0..1, `lambda == mu`, and no reseed during the normal part of the run.
A normal 90 s devnet with the same flags produced no `soft catch-up` line, so the
soft path did not misfire on ordinary jitter. An 80 ms stop / 20 ms run duty
cycle on one validator lowered `lambda` to 22/s and `mu` to 18.9/s, but the
backlog only reached 29 rounds and the committee itself slowed; 256 rounds was
not reachable that way. The soft threshold itself was not observed end-to-end:
in every measured stall a hard trigger fired first. Its window, estimate, and
threshold decisions are unit-tested.

**Open.** No run has produced a backlog where the hard triggers stay false while
the rate estimate says catch-up is hopeless. That is the scenario the soft
trigger exists for; the constants (10 s window, 256 rounds, 60 s, 5 s sustain,
0.5 rounds/s margin) are chosen conservatively and may need one measured
adjustment once such a run exists.

## D82 — A peer-certified head resets the local header builder

**Decided.** When `advance_certified` adopts a header this node did not build
(the header id is absent from `order_lens`), it resets `last_built` to that
header, clears `last_built_order` (coverage is unknown for a peer header), moves
`next_height` to at least `height + 1`, and drops pending heights the head has
passed. Pending heights already assigned above the head keep their numbers so
`record_commit` cannot create duplicate heights. A header this node did build
leaves the builder untouched, including when the local builder is ahead of the
certified head.

**Why.** A lagging validator can receive a quorum for a peer-built header before
it has built a matching one. The chain head then advances, but `last_built` still
named its own earlier header (or the anchor). Every later build used that orphan
as `previous`; no peer could sign it, so the node could never rejoin the
canonical chain without a reseed. A unit test reproduces it: the follower
certifies a peer height 1, then builds its next commit at height 1 with previous
genesis. After the change it builds height 2 with previous equal to the peer
id. The live consequence is that a node that falls behind but is not fenced must
be able to author again on the canonical chain.

**Measured.** Four validators, `CHECKPOINT_EVERY=32 FAILURE_ROUNDS=15`, no
`--fence-silent`; node 3 was stopped for 5 s at t=10 s and resumed. All four
ended at certified head 3622/4517, `commit_root 83aa2d32…`, `state_root
690cb32b…`, conflicts 0; node 3 authored 4519 rounds after the pause, the same
as nodes 0 and 1. The validator unit suite is green (170 tests), including the
new follower test.

**Open.** The fix covers a peer header adopted while the local builder is at or
below it. It does not reconstruct whether an already-built local chain above the
head was compatible; pending heights above the head are kept and built on the
new head, and a divergent one simply fails to collect a quorum. An ancestry map
for built headers would make that decision sharper.

## D83 — A node error is reported when it happens

**Decided.** `run_one_node` polls the node task alongside the readiness wait,
the execution wait, and the lifetime deadline. If the task completes early it
sends shutdown and returns its result immediately: an error is printed and the
process exits, an early `Ok` prints the usual summary. The deadline path is
unchanged: stop authoring, drain, shutdown, then await the task.

**Why.** A task that failed during link setup or store replay sent nothing, so the
process looked idle until `--timeout-seconds` expired. A crash-store replay error
was therefore indistinguishable from a hang, and a healed store that still had a
certification gap appeared stuck for the rest of the lifetime. The node task is
the component that knows it failed; waiting for the clock only hides that.

**Measured.** A node started with no peers and `--timeout-seconds 30` now prints
`error: node 0 cannot reach 127.0.0.1:9001: Connection refused` after 4 s (the
connect retry budget). During the crash-store investigation the same class of
error (`the certified head does not match any committed prefix`) surfaced only
at the end of the configured lifetime.

## D84 — A certified peer head carries a locally derived coverage

**Decided.** When a checkpoint is due, or a peer asks for a snapshot, the live
loop tries to derive the coverage of the latest peer-certified header by
searching its own committed prefixes for that header's `dag_root`. The search
starts at the last coverage the node proved and is capped at the last 4096
prefixes near the order tip, so a lagging node cannot turn certification into a
quadratic scan. The derived value is recorded with
`Finalizer::note_certified_order`; the first value wins. The node tracks
`last_provable`, the highest certified header with known coverage, and anchors
checkpoints and served snapshots there. `last_certified` still drives the
reseed minimum height and the finality-stall detector. Restore records the
coverage of the head it proved.

**Why.** After D82 a lagging follower advances its head through peer-certified
headers instead of its orphaned local builder. Those peer headers have no
coverage in the finalizer, so `build_live_snapshot` declined with `the certified
head has no committed order length` and the node never checkpointed: its store
grew without bound and a restart had to replay all of it. Anchoring at the
highest provable certified header is safe: a checkpoint may be shorter than the
node's committed DAG order, but never shorter than its certified prefix.

**Measured.** The in-process checkpoint test (four nodes, checkpoint every two
heights, 30 rounds, restart, audit) failed once during a gate with `node 1
finished without writing a checkpoint`. With coverage derivation the same test
passed three consecutive runs (31.0 s, 42.5 s, 35.7 s). A 60 s four-process
devnet with `CHECKPOINT_EVERY=32`: before this change node 3 wrote 0 checkpoints
while nodes 0..2 wrote 44..49; after, node 3 wrote 47 and kept a live snapshot.
The same run left node 0 at one checkpoint because that process was severely
lagged (its delivery p50 was seconds long); the in-process test is the stable
signal.

**Open.** A node further behind than the 4096-prefix scan window cannot derive
the peer head's coverage; `last_provable` stops advancing and it needs a reseed
to catch up. The bounded scan is still a walk rather than a frontier lookup;
that would remove the remaining cost.

## D85 — The header log only stores a prefix this node can reproduce

**Decided.** A newly certified header is persisted only when the committed
prefix its `dag_root` names is in the local order, and only as the next height
above the last record on disk. A header this node built carries that coverage in
the finalizer and is written immediately. A peer-built header usually does not:
it waits in a `HeaderWrites` backlog and is written at the checkpoint cadence,
where the committed order is scanned once from the last written coverage (an
incremental frontier, not `commit_root_at` per index) and the coverage is
recorded with `note_certified_order`. A failed scan is cached by (front height,
order length), so an unprovable header does not rescan the same prefix every
tick. A header whose root never appears blocks the queue: writing a later height
above the gap would make the log impossible to adopt. On snapshot adoption the
queue is rebased at the new anchor and stored headers above it are truncated. A
checkpoint whose anchor the queue could not reach writes the anchor record alone
after the snapshot is active, so the log stays auditable without a gap above the
live anchor.

Replay (`replay_to_provable_head`) now also requires ascending heights: headers
above the anchor must start at `anchor + 1` and be contiguous. A height gap ends
the provable prefix even when a later header's root is reachable. `audit` accepts
a store whose only header is the live snapshot anchor, and a snapshot-joined
store with no header record at all, because the anchor's certificate and state
are verified from the snapshot itself.

**Why.** D80 healed an unprovable stored head only on the next restart. Between
the write and that restart the store could not be replayed or audited, which is
exactly the state a SIGKILL during a checkpoint produced. Gating the write keeps
the invariant at the source. Height continuity is needed because the finalizer
adopts one link per height; root reachability alone is not enough. The anchor
written by an unactivated snapshot adoption is the one known gap: activation is
deliberately last, so a crash before it leaves an anchor record above the old
snapshot that replay must drop.

**Measured.** Four processes, `--checkpoint-every 4`, `FENCE_SILENT=1`; node 3
was killed with SIGKILL exactly while `live.snapshot.tmp` existed (196608 bytes
of the next snapshot written; the previous 906560-byte snapshot and its anchor
at height 3084 remained). The store also held the stopped adoption's anchor
record at height 3445. Before the continuity check, restart and `karsa audit`
both failed with `header height 3445 does not follow 3084`. After it, restart
printed `the retained order reproduces height 3084, dropped 1 stored headers
above it (top 3445)`, replayed 12601 committed entries in 10048 ms, caught a
finality gap (`certified head 3084/4093`, lambda 1218.3/s, mu 0), reseeded from
`127.0.0.1:7621` at height 3445/round 4574 (install 1773 ms), and finished at
committed 14044, `state_root 690cb32b…`, `commit_root 9756e1b6…`. `karsa audit`
then passed (anchor verified, 104771 stored vertices, no certified heights above
the anchor in that run). A random SIGKILL after an ordinary checkpoint restarted
with no drop: replay 2758 entries in 4693 ms, certified head 623, no repair.
Unit test `a_certified_header_waits_for_the_prefix_it_covers`; mesh test
`a_mesh_drops_a_stored_header_that_skips_a_height` (37.99 s, audit passed).
The first scan implementation rebuilt the frontier per header; a follower that
wrote about 50 headers/s from a backlog then spun at 99% CPU without logging for
minutes. The flush now builds one frontier per call and reuses it across the
queue, and the official 120 s four-process devnet finished with all four nodes:
nodes 0..2 at committed 23243, `state_root 690cb32b…`, `commit_root c41cf579…`;
node 3 at committed 23045 with the same state root (it authored only 353 rounds
and lagged), and both val-0 and val-3 audited above their anchors.

**Open.** An adoption that dies before activation leaves its tail vertices and
batches in the store; replay treats them as old-run data. In the measured store
this added 33241 tail vertices (25.8 MB) and made the next replay 10 s. Staging
the tail beside the snapshot and activating both with one rename would avoid
that. The queue scan is still a walk from the last written coverage, and a header
the local order never covers blocks the log until a reseed rebases it. Audit
still refuses a height gap on a store that has not been restarted; `restore_live`
is what drops the record above the gap, so the supported sequence is restart,
then audit.

## Open decisions

1. **Does a node serve history it does not hold?** Model B says no beyond the
   window. D42 shows a cold join from a peer's snapshot works in-process; the
   serving policy and archive availability are still open. That decides whether
   validators and archive nodes are different roles, and it is what a
   data-availability protocol would have to answer.
2. **How is the validator set itself changed?** The transition arithmetic, the
   harness path, and the 100-sample boundary measurement are done (D41); D59
   adds the authorized certificate, deterministic activation, snapshot/audit
   persistence, and the live proposal path. Who may propose a change, and the
   governance process around it, remains open. Key rotation is solved.
3. **Is there a validity or fraud proof for `state_root`?** A full node can now
   check the link by replay (D19); a light client still cannot, and that is what a
   zk or fraud proof would buy.
