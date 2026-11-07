# Handoff — run the finality benchmark on the laptop

Date: 2026-11-07

- Canonical repo: `karsahq/karsa`
- Branch: `experiment`
- Code commit: `e5f3d2e feat(finality): measure client submit to certified header`
- This file is a handoff, not design documentation. Delete it after the benchmark
  is recorded.

## 1. Sync this fork with the canonical repo

The laptop's `origin` is its own fork. Add the canonical repo as `upstream` and
bring `experiment` in. Do not force-push over `upstream`.

```sh
git remote -v
# If upstream is missing (SSH; use https://github.com/karsahq/karsa.git if needed):
git remote add upstream git@github.com:karsahq/karsa.git
git fetch upstream
git switch experiment
git log --oneline --decorate -5
# If the fork has no local commits on experiment:
git merge --ff-only upstream/experiment
# If it has local commits:
git rebase upstream/experiment
git status
```

The tip must be `e5f3d2e` (or later). If the fork has its own `origin/experiment`,
push only after the local branch matches upstream, and never force-push.

## 2. Verify the tree

```sh
CARGO=$(command -v cargo) ./scripts/rust-check.sh
```

The gate runs fmt, clippy with `-D warnings`, and every workspace test. It has
passed on the desktop before the last local tweaks; run the whole thing on the laptop
to make the gate authoritative.

Already verified on the desktop after the final tweaks:

- `cargo fmt --all -- --check`
- `cargo clippy -p karsa --all-targets -- -D warnings`
- `cargo test -p karsa finality` — 3 tests pass

## 3. What changed

- `cmd/karsa/src/finality.rs` — new `karsa finality`: a closed-loop client and a
  delayed validator mesh that measure submit → commit and submit → certified
  header, plus rounds to finality.
- `crates/validator/src/pacemaker.rs` — `Pacemaker::tick_one`, one decision at a
  time so a header can be materialized per commit.
- `crates/net/src/lib.rs` — `Node::commit_once`, the node-level wrapper.
- `cmd/karsa/src/chain.rs`, `cmd/karsa/src/live.rs` — `demo_batch` now takes the
  run's chain id, so a `--home` run does not execute transactions signed for the
  demo chain.
- `cmd/karsa/src/main.rs` — the `finality` subcommand.
- `README.md` — the command and the measurement model.

## 4. Build and run

Build once, then run the binary: a release compile is all-core work and must not
be mixed with the measurement, especially on the unstable desktop.

```sh
cargo build --release
tmux new -s finality
```

Run at two delays. The first is a data-center-like round trip; the second is a
wide-area-like one.

```sh
./target/release/karsa finality --samples 100 --delay-ms 25 --jitter-ms 5 \
    --timeout-seconds 60 | tee /tmp/finality-25ms.txt

./target/release/karsa finality --samples 100 --delay-ms 50 --jitter-ms 10 \
    --timeout-seconds 90 | tee /tmp/finality-50ms.txt
```

Optional floor, for the code's own cost rather than a network comparison:

```sh
./target/release/karsa finality --samples 100 --delay-ms 0 --jitter-ms 0 \
    --timeout-seconds 60 | tee /tmp/finality-loopback.txt
```

Use `tmux` or `screen`: an SSH drop must not kill the run. Each run keeps authoring
while it waits for the last certificate, so it does not terminate on the last
sample alone; the drain is included in the wall clock.

## 5. What to report

For each delay setting, report:

- `submit → commit`: p50, p95, p99, max.
- `submit → certified header`: p50, p95, p99, max.
- `commit → certificate` at the node whose certificate was first.
- `rounds to finality`: p50, p95, p99, max, split leader vs non-leader.
- The agreement line: order, state, headers, conflicts.
- Samples finalized on every node and on the submitter.
- Wall clock and the exact `--delay-ms` / `--jitter-ms`.

Compare `submit → certified header` with Sui's ~400–700 ms and IOTA's "a few
seconds". Do **not** compare block time. Keep the round count separate: it is
the protocol-level number (the wall clock is a function of the injected delay).

## 6. How the numbers are defined

- The clock starts just before the batch is handed to validator 0 and stops at
  the earliest commit decision, and at the earliest quorum certificate, across
  the nodes. Client signing time is outside the clock; the wait for the next
  authoring slot is inside it (closed loop: the next submit waits for the previous
  authoring acknowledgement).
- Links are `mpsc` channels with an injected one-way delay and deterministic jitter,
  not TCP. `karsa live` is the command that measures the wire. Four validators live
  in one process; this is a latency model with real signing, not independent
  operators.
- A header is the committed prefix at one pacemaker decision, signed by the
  certificate keys. Shares travel over the same links, so the certificate number
  includes the round trip a portable certificate needs.
- Rounds: vertex round → vote round. A decision at round `q` exists because round
  `q + 1` voted for its leader, so a leader vertex typically finalizes in 1 round
  and a non-leader in 2; 3 appears when a leader is skipped or late.

## 7. Preliminary result from the desktop

One completed run on the desktop (4 validators, 100 samples, 25 ms one-way,
5 ms jitter): submit → commit p50 125 ms, p95 190 ms, p99 214 ms; commit →
certificate ~3–8 ms; rounds p50 2, p95 3. Treat it as preliminary: a later rerun
froze the desktop, and the machine is known to freeze under all-core load.

## 8. Machine caveat (important)

The desktop freezes under all-core load: the screen loses signal, SSH dies, the
journal stops, power drops from 37 W to 27 W, and there is no panic, oops, MCE,
thermal trip, or watchdog. `scx_lavd` is masked and `sched_ext` is disabled, so
that is not the current cause. The remaining suspects are `linux-cachyos` 7.3.1,
C-state/VRM behaviour on the H81/i7-4790K, Polaris runtime PM/BACO, and non-ECC
RAM. Bazzite (stock Fedora kernel) has not frozen. The next test is the stock
`linux` kernel.

Run the benchmark on the laptop. On the desktop, only `cargo check`/clippy and
short n=4 runs with limited parallelism, and avoid rebuilding and measuring in
the same command.

## 9. Do not

- Do not compare block time with Sui/IOTA; compare submit → certified header.
- Do not bind the validator set to `epoch_rounds`. This benchmark does not add a
  committee-change path.
- Do not reintroduce `header.epoch != head.epoch` in `HeaderChain::advance`.
- Do not force-push the canonical `experiment` branch.
- Do not treat the desktop's 100-sample rerun as a code failure; it froze the
  machine before the run completed.
