#!/bin/sh
# Runs one Karsa validator per process and compares what each process reports.
#
# Usage:
#   ./scripts/live-multiprocess.sh [validators] [rounds] [txs] [port-base] [timeout-seconds]
#
# Every process runs `karsa live --node-index i` against the same demo committee.
# The run fails unless every process authored its rounds, applied every batch, and
# reported the same commit root and state root. Throughput is computed over the
# union of the per-process authoring windows, so a process that starts late is
# charged for the delay instead of being measured against its own clock.
set -eu

CARGO=${CARGO:-cargo}
VALIDATORS=${1:-4}
ROUNDS=${2:-20}
TXS=${3:-1000}
PORT_BASE=${4:-7100}
TIMEOUT=${5:-20}
# One process per validator shares the machine, so divide the logical CPUs
# between them. A real deployment gives each validator its own machine; this
# keeps the benchmark from oversubscribing one. Override with WORKERS=N.
CPUS=${CPUS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}
case "$CPUS" in
    ''|*[!0-9]*) CPUS=1 ;;
esac
WORKERS=${WORKERS:-$(( (CPUS + VALIDATORS - 1) / VALIDATORS ))}
if [ "$WORKERS" -lt 1 ]; then
    WORKERS=1
fi
# Verifier threads are the throughput lever, not the process boundary: default
# one per CPU slice the process got, and let VERIFY_THREADS override it. A value
# of 1 still reproduces the old serial-per-process configuration.
VERIFY_THREADS=${VERIFY_THREADS:-$WORKERS}
BIN=${BIN:-target/release/karsa}
OUT=${OUT:-/tmp/karsa-live-multiprocess}

if [ "$VALIDATORS" -lt 2 ] || [ "$VALIDATORS" -gt 64 ]; then
    echo "validators must be between 2 and 64, got $VALIDATORS" >&2
    exit 2
fi

# The workspace pins clang, which may not exist on every machine; gcc plus mold
# links the same binary.
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-gcc}
export CARGO_INCREMENTAL=0

if [ "${SKIP_BUILD:-0}" != 1 ]; then
    "$CARGO" build --release
fi

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== multiprocess live: $VALIDATORS validators, $ROUNDS rounds, $TXS tx/batch =="
echo "  ports $PORT_BASE..$((PORT_BASE + VALIDATORS - 1)), $WORKERS tokio workers and $VERIFY_THREADS verify threads per process, lifetime ${TIMEOUT}s"

pids=""
i=0
while [ "$i" -lt "$VALIDATORS" ]; do
    TOKIO_WORKER_THREADS=$WORKERS "$BIN" live \
        --node-index "$i" \
        --validators "$VALIDATORS" \
        --archives 0 \
        --port-base "$PORT_BASE" \
        --rounds "$ROUNDS" \
        --txs "$TXS" \
        --execute \
        --pre-sign \
        --verify-threads "$VERIFY_THREADS" \
        --timeout-seconds "$TIMEOUT" \
        > "$OUT/val-$i.log" 2>&1 &
    pids="$pids $!"
    i=$((i + 1))
done

failed=0
for pid in $pids; do
    if ! wait "$pid"; then
        failed=1
    fi
done

# Parse the one `result` line each process prints. It is a key=value line, so the
# check does not depend on the human-readable report around it.
field() {
    printf '%s\n' "$line" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"
}

min_first=""
max_last=""
commit_ref=""
state_ref=""
applied_ref=""
i=0
while [ "$i" -lt "$VALIDATORS" ]; do
    line=$(grep '^  result ' "$OUT/val-$i.log" 2>/dev/null | tail -n 1 || true)
    if [ -z "$line" ]; then
        echo "  val-$i  no result line (see $OUT/val-$i.log)" >&2
        failed=1
        i=$((i + 1))
        continue
    fi

    complete=$(field complete)
    authored=$(field authored)
    committed=$(field committed)
    applied=$(field applied_tx)
    first=$(field first_author_ms)
    last=$(field last_author_ms)
    commit=$(field commit_root)
    state=$(field state_root)

    if [ "$first" = "-" ] || [ "$last" = "-" ]; then
        echo "  val-$i  authored nothing" >&2
        failed=1
        i=$((i + 1))
        continue
    fi
    if [ "$complete" != 1 ] || [ "$authored" -ne $((ROUNDS + 1)) ]; then
        echo "  val-$i  did not finish authoring (complete=$complete, authored=$authored)" >&2
        failed=1
    fi
    # `applied` counts transactions, so compare it with the batch count the node
    # committed rather than with a fixed total: the last rounds cannot commit
    # without a following round to anchor them.
    if [ "$TXS" -gt 0 ] && [ "$applied" -ne $((committed * TXS)) ]; then
        echo "  val-$i  applied $applied transactions for $committed committed batches" >&2
        failed=1
    fi

    span=$((last - first))
    if [ "$span" -gt 0 ]; then
        rate=$(awk -v n="$authored" -v ms="$span" 'BEGIN { printf "%.1f", n * 1000 / ms }')
    else
        rate=0
    fi
    echo "  val-$i  authored=$authored committed=$committed applied_tx=$applied  ${span} ms  ${rate} rounds/s"

    if [ -z "$commit_ref" ]; then
        commit_ref=$commit
        state_ref=$state
        applied_ref=$applied
    else
        if [ "$commit" != "$commit_ref" ]; then
            echo "  val-$i  commit root differs: $commit vs $commit_ref" >&2
            failed=1
        fi
        if [ "$state" != "$state_ref" ]; then
            echo "  val-$i  state root differs: $state vs $state_ref" >&2
            failed=1
        fi
        if [ "$applied" != "$applied_ref" ]; then
            echo "  val-$i  applied $applied transactions, val-0 applied $applied_ref" >&2
            failed=1
        fi
    fi
    if [ -z "$min_first" ] || [ "$first" -lt "$min_first" ]; then
        min_first=$first
    fi
    if [ -z "$max_last" ] || [ "$last" -gt "$max_last" ]; then
        max_last=$last
    fi

    i=$((i + 1))
done

if [ "$failed" -ne 0 ]; then
    echo "multiprocess run failed; logs in $OUT" >&2
    exit 1
fi
if [ "$state_ref" = "-" ]; then
    echo "no state root was reported" >&2
    exit 1
fi

window=$((max_last - min_first))
if [ "$window" -le 0 ]; then
    echo "authoring window is ${window} ms; refusing to divide by it" >&2
    exit 1
fi
total_tx=$((VALIDATORS * (ROUNDS + 1) * TXS))
tps=$(awk -v t="$total_tx" -v ms="$window" 'BEGIN { printf "%.0f", t * 1000 / ms }')
applied_tps=$(awk -v t="$applied_ref" -v ms="$window" 'BEGIN { printf "%.0f", t * 1000 / ms }')

echo "  roots             all $VALIDATORS agree"
echo "  commit root       $(printf '%s' "$commit_ref" | cut -c1-16).."
echo "  state root        $(printf '%s' "$state_ref" | cut -c1-16).."
echo "  authoring window  ${window} ms (first vertex to last, all processes)"
echo "  throughput        ${tps} authored tx/s (${total_tx} authored; ${applied_ref} applied per node)"
echo "  committed         ${applied_ref} tx per node, ${applied_tps} tx/s over the same window"
