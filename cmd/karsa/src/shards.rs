//! Erasure-codes one batch payload and reconstructs it after losing shards.
//!
//! The point is not that encoding works — the unit tests cover that. It is that the
//! numbers a storage decision depends on are small enough to read: how much a shard
//! costs, how much overhead the code adds, how fast reconstruction is, and what a
//! node actually has to keep.

use std::error::Error;
use std::time::Instant;

use erasure::Code;

/// Transactions per batch used for the payload size.
const TRANSACTIONS: usize = 1_000;
/// Bytes per hybrid (post-quantum) transaction.
const HYBRID_TX_BYTES: usize = 3_500;

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn human(bytes: usize) -> String {
    let value = bytes as f64;
    if value >= 1e9 {
        format!("{:.2} GB", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let payload_len = TRANSACTIONS * HYBRID_TX_BYTES;
    let payload: Vec<u8> = (0..payload_len)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect();

    println!("== Erasure coding: one batch payload ==");
    println!(
        "  payload:  {} ({} hybrid transactions)",
        human(payload.len()),
        TRANSACTIONS
    );
    println!();
    println!(
        "  {}  {}  {}  {}  {}  {}  {}",
        left("shape", 9),
        pad("shard", 10),
        pad("wire", 10),
        pad("overhead", 10),
        pad("encode", 10),
        pad("decode", 10),
        pad("kept/node", 11)
    );

    for (data, total) in [(10usize, 16usize), (16, 24), (32, 48), (67, 100)] {
        let code = Code::new(data, total)?;

        let start = Instant::now();
        let encoded = code.encode(&payload)?;
        let encode_us = start.elapsed().as_micros();

        // Lose every shard the code can afford to lose, then reconstruct from the
        // furthest-away survivors.
        let survivors: Vec<(usize, &[u8])> = encoded
            .shards
            .iter()
            .enumerate()
            .skip(code.tolerance())
            .map(|(index, shard)| (index, shard.as_slice()))
            .collect();

        let start = Instant::now();
        let recovered = code.decode(&survivors, encoded.length)?;
        let decode_us = start.elapsed().as_micros();

        if recovered != payload {
            return Err(format!("{data}/{total} did not reconstruct").into());
        }

        let wire: usize = encoded.shards.iter().map(Vec::len).sum();
        let shard_len = encoded.shards.first().map_or(0, Vec::len);
        println!(
            "  {}  {}  {}  {}  {}  {}  {}",
            left(&format!("{data}/{total}"), 9),
            pad(&human(shard_len), 10),
            pad(&human(wire), 10),
            pad(
                &format!("{:.0}%", (total as f64 / data as f64 - 1.0) * 100.0),
                10
            ),
            pad(&format!("{encode_us} us"), 10),
            pad(&format!("{decode_us} us"), 10),
            pad(&format!("1 of {total}"), 11)
        );
    }

    println!();
    println!(
        "  Reconstruction uses {} of {} shards, so losing {} of them costs",
        32, 48, 16
    );
    println!("  nothing. That is what makes a slow or absent validator stop mattering");
    println!("  to data availability.");

    println!();
    println!();
    println!("== What coding costs in CPU (32/48, scalar GF(2^8)) ==");
    let reference = Code::new(32, 48)?;
    let start = Instant::now();
    let _ = reference.encode(&payload)?;
    let encode_us = start.elapsed().as_micros().max(1);
    let throughput = (payload.len() as f64 * 1e6) / encode_us as f64 / 1e6;
    println!("  encode:  {throughput:.0} MB/s");
    for tps in [1_000u64, 10_000, 100_000] {
        let needed = (tps as f64 * HYBRID_TX_BYTES as f64) / 1e6;
        println!(
            "  {tps:>7} TPS needs {needed:.1} MB/s of coding: {:.0}% of one core",
            needed / throughput * 100.0
        );
    }
    println!("  This implementation is scalar and chosen to be readable. Production");
    println!("  code uses SIMD over GF(2^16) and runs 10-50x faster, which is the");
    println!("  difference between erasure coding being free and being a core.");

    println!("== What a node has to keep, at 1,000 and 10,000 TPS ==");
    println!(
        "  {}  {}  {}  note",
        left("model", 26),
        pad("1k TPS", 12),
        pad("10k TPS", 12)
    );
    let per_tps = HYBRID_TX_BYTES as u64 * 86_400;
    // The window is a duration, so its cost scales with the rate, not with the
    // shard count.
    let window = |tps: u64| tps * HYBRID_TX_BYTES as u64 * 3_600;
    for (label, divisor, windowed, note) in [
        ("full replication", 1u64, false, "every batch, permanently"),
        ("shard only (32/48)", 32, false, "1/32 of every batch"),
        ("shard + 1h window", 32, true, "+ 3600 s of full payload"),
    ] {
        let column = |tps: u64| -> u64 {
            let day = tps * per_tps / divisor;
            if windowed { day + window(tps) } else { day }
        };
        println!(
            "  {}  {}  {}  {}",
            left(label, 26),
            pad(
                &human(usize::try_from(column(1_000)).unwrap_or(usize::MAX)),
                12
            ),
            pad(
                &human(usize::try_from(column(10_000)).unwrap_or(usize::MAX)),
                12
            ),
            note
        );
    }
    println!("  Per day, before retention. Pruning is what turns the first row into");
    println!("  the second; the third is what a validator keeps while still being able");
    println!("  to serve recent history.");

    Ok(())
}
