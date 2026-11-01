//! Bandwidth model for certificate and payload dissemination.
//!
//! This is arithmetic over the sizes measured by `karsa dagbench` and
//! `karsa certify`, not a network measurement: no gossip protocol, no packet
//! loss, no execution. Its job is to show which lever moves per-node bandwidth
//! and which one only looks like it does.
//!
//! The result that surprises people is in [`per_node_egress`]: when every
//! validator needs every certificate, changing the fanout changes the number of
//! connections and the number of hops, but not the bytes each node must send.

use std::error::Error;

use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65, ALG_SLH_DSA_SHA2_128S, lookup};

use crate::dagbench::projected_certificate_bytes;

/// Batch sizes the certificate table sweeps: transactions per certificate.
const BATCH_SIZES: [u64; 3] = [1, 100, 1_000];
/// Payload sizes for one transaction, from §8.8 of the registry document.
const CLASSICAL_TX_BYTES: u64 = 200;
const HYBRID_TX_BYTES: u64 = 3_500;
/// Erasure-coding shapes, `(enough, total)`.
const ERASURE_SHAPES: [(u64, u64); 3] = [(10, 16), (16, 24), (32, 48)];
/// Bytes of one block reference: a 32-byte digest, a 4-byte author, an 8-byte
/// round. This is the shape of the `BlockReference` the Starfish testbed uses.
const REFERENCE_BYTES: usize = 44;
/// Fixed block-header bytes other than references and the signature: author,
/// round, and a couple of small flags. An assumption, not a measurement.
const BLOCK_FIXED_BYTES: usize = 24;
/// References a non-leader block carries in the sparse styles: its own previous
/// block, the previous round's leader, and its certificate claim.
const NON_LEADER_REFERENCES: usize = 3;

/// One consensus style's per-round metadata shape.
struct Style {
    name: &'static str,
    /// Bytes of one artifact emitted by a non-leader validator.
    artifact_bytes: usize,
    /// Bytes of the artifact emitted by the round leader.
    leader_bytes: usize,
    /// Signatures the whole committee produces per round.
    signatures_per_round: u128,
}

/// Certificates per second when `transactions_per_certificate` transactions are
/// batched into each one.
#[must_use]
fn certificates_per_second(tps: u64, transactions_per_certificate: u64) -> u64 {
    if transactions_per_certificate == 0 {
        return 0;
    }
    tps.div_ceil(transactions_per_certificate)
}

/// Bytes per second emitted by the validators that produce certificates.
#[must_use]
fn originator_bytes_per_second(certificates: u64, certificate_bytes: usize) -> u128 {
    u128::from(certificates) * certificate_bytes as u128
}

/// Per-node egress when every certificate reaches every other validator.
///
/// Each validator emits `1/n` of the certificates and sends each of those to
/// `n-1` peers, so the per-node figure is `(n-1)/n` of the originator total.
/// **This does not depend on the fanout.** A tree topology spreads the same
/// bytes over fewer peers per message but more messages per node: every
/// certificate still has to cross `n-1` links once, and a node that forwards
/// everything it receives forwards `n-1` copies per certificate it originates.
#[must_use]
fn per_node_egress(originator_bytes: u128, validators: usize) -> u128 {
    if validators <= 1 {
        return 0;
    }
    let replicas = validators as u128 - 1;
    originator_bytes * replicas / validators as u128
}

/// Hops for a certificate to reach every node in a fanout tree.
///
/// A node that forwards to `k` peers reaches `1 + k + k² + … + k^h` nodes after
/// `h` hops. Assumes a spanning tree: a peer that already has the message is not
/// counted twice, which is optimistic for gossip and exact for a tree.
#[must_use]
fn hops(validators: usize, fanout: usize) -> usize {
    if validators <= 1 || fanout < 2 {
        return 1;
    }
    let mut reached = 1usize;
    let mut layer = 1usize;
    let mut hops = 0usize;
    while reached < validators {
        layer = layer.saturating_mul(fanout);
        reached = reached.saturating_add(layer);
        hops += 1;
    }
    hops
}

/// Bytes on the wire per certificate delivered to one node with `enough`-of-
/// `total` erasure coding.
#[must_use]
fn erasure_bytes(payload_bytes: u64, enough: u64, total: u64) -> u64 {
    if enough == 0 {
        return payload_bytes;
    }
    payload_bytes.saturating_mul(total) / enough
}

/// Per-round metadata for three consensus styles, all with one artifact per
/// validator per round.
///
/// * **certificate (ours)**: every validator emits a certificate carrying the
///   whole committee's signatures, so the committee produces `n²` signatures per
///   round.
/// * **bluestreak**: every validator emits one block signed once; non-leaders
///   carry three references and the leader carries the round's reference list.
/// * **sparse-starfish-speed**: the same, plus a constant `ceil(n/8)` strong-vote
///   bitmask per block; acknowledgments live on the leader's block only.
fn styles(validators: usize, signature_size: usize) -> Result<Vec<Style>, Box<dyn Error>> {
    let certificate = projected_certificate_bytes(validators, signature_size)?;
    let bluestreak_leader = BLOCK_FIXED_BYTES + signature_size + (validators + 1) * REFERENCE_BYTES;
    let bluestreak_voter =
        BLOCK_FIXED_BYTES + signature_size + NON_LEADER_REFERENCES * REFERENCE_BYTES;
    let bitmask = validators.div_ceil(8);
    let committee = validators as u128;

    Ok(vec![
        Style {
            name: "certificate (ours)",
            artifact_bytes: certificate,
            leader_bytes: certificate,
            signatures_per_round: committee * committee,
        },
        Style {
            name: "bluestreak",
            artifact_bytes: bluestreak_voter,
            leader_bytes: bluestreak_leader,
            signatures_per_round: committee,
        },
        Style {
            name: "sparse-starfish-speed",
            artifact_bytes: bluestreak_voter + bitmask,
            leader_bytes: bluestreak_leader + bitmask,
            signatures_per_round: committee,
        },
    ])
}

fn human(bytes_per_second: u128) -> String {
    let value = bytes_per_second as f64;
    if value >= 1e9 {
        format!("{:.2} GB/s", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1} MB/s", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB/s", value / 1e3)
    } else {
        format!("{bytes_per_second} B/s")
    }
}

fn bytes_human(bytes: usize) -> String {
    let value = bytes as f64;
    if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

pub fn run(
    validators: usize,
    tps: u64,
    fanout: usize,
    transactions_per_certificate: u64,
) -> Result<(), Box<dyn Error>> {
    if validators < 2 {
        return Err("--validators must be at least 2".into());
    }
    if tps == 0 {
        return Err("--tps must be greater than 0".into());
    }
    if fanout < 2 {
        return Err("--fanout must be at least 2".into());
    }

    println!("== Assumptions ==");
    println!("  validators:            {validators}");
    println!("  transactions/s:        {tps}");
    println!("  fanout:                {fanout} peers per forward");
    println!(
        "  certificates/second:   ~{} at {transactions_per_certificate} tx per certificate",
        certificates_per_second(tps, transactions_per_certificate)
    );
    println!("  every validator needs every certificate (no sharding, no committees)");
    println!();

    let schemes = [
        (ALG_ED25519, "ed25519"),
        (ALG_ML_DSA_65, "ml-dsa-65"),
        (ALG_SLH_DSA_SHA2_128S, "slh-dsa-128s"),
    ];

    println!("== Certificate stream, per-node egress ==");
    println!(
        "  {}  {}  {}  {}  {}  {}",
        left("scheme", 13),
        pad("tx/cert", 8),
        pad("cert bytes", 11),
        pad("certs/s", 9),
        pad("originators", 12),
        pad("per node", 11),
    );
    for (algorithm_id, name) in schemes {
        let signature_size = lookup(algorithm_id)?.signature_size;
        let certificate_bytes = projected_certificate_bytes(validators, signature_size)?;
        for batch in BATCH_SIZES {
            let certificates = certificates_per_second(tps, batch);
            let originators = originator_bytes_per_second(certificates, certificate_bytes);
            let per_node = per_node_egress(originators, validators);
            println!(
                "  {}  {}  {}  {}  {}  {}",
                left(name, 13),
                pad(&batch.to_string(), 8),
                pad(&bytes_human(certificate_bytes), 11),
                pad(&certificates.to_string(), 9),
                pad(&human(originators), 12),
                pad(&human(per_node), 11),
            );
        }
    }
    let mesh_peers = validators - 1;
    let mesh_hops = hops(validators, mesh_peers);
    let tree_hops = hops(validators, fanout);
    println!();
    println!("  The per-node column is identical for a mesh and for any fanout. A tree");
    println!("  changes connections per node ({mesh_peers} vs {fanout}) and hops");
    println!("  ({mesh_hops} vs {tree_hops}), not bytes: each certificate still crosses");
    println!("  {mesh_peers} links once.");
    println!("  Fanout does not reduce dissemination bandwidth; batching and smaller");
    println!("  certificates do.");
    println!();

    println!("== Consensus metadata per round, by style ==");
    println!(
        "  {}  {}  {}  {}  {}  {}",
        left("scheme", 10),
        left("style", 22),
        pad("sigs/round", 10),
        pad("artifact", 10),
        pad("per node", 11),
        pad("leader blk", 11),
    );
    for (algorithm_id, name) in schemes {
        let signature_size = lookup(algorithm_id)?.signature_size;
        for style in styles(validators, signature_size)? {
            let egress = (validators as u128 - 1) * style.artifact_bytes as u128;
            println!(
                "  {}  {}  {}  {}  {}  {}",
                left(name, 10),
                left(style.name, 22),
                pad(&style.signatures_per_round.to_string(), 10),
                pad(&bytes_human(style.artifact_bytes), 10),
                pad(
                    &bytes_human(usize::try_from(egress).unwrap_or(usize::MAX)),
                    11
                ),
                pad(&bytes_human(style.leader_bytes), 11),
            );
        }
    }
    println!("  A model, not a measurement. One artifact per validator per round.");
    println!(
        "  A block reference is {REFERENCE_BYTES} B, the fixed block overhead is {BLOCK_FIXED_BYTES} B,\n  a non-leader carries {NON_LEADER_REFERENCES} references and the leader carries n+1."
    );
    println!("  The certificate style pays n signatures per artifact; the block styles pay");
    println!("  one, which is where the two orders of magnitude come from. The SSFS bitmask");
    println!("  is ceil(n/8) bytes and is not where the saving is.");
    println!();

    println!("== Transaction payload stream ==");
    println!(
        "  {}  {}  {}  {}",
        left("payload", 10),
        pad("per tx", 8),
        pad("aggregate", 11),
        pad("per node", 11),
    );
    for (name, tx_bytes) in [
        ("classical", CLASSICAL_TX_BYTES),
        ("hybrid", HYBRID_TX_BYTES),
    ] {
        let aggregate = u128::from(tps) * u128::from(tx_bytes);
        // Every validator executes every transaction, so unlike certificates this
        // does not divide by the validator count. Only execution sharding would.
        println!(
            "  {}  {}  {}  {}",
            left(name, 10),
            pad(&bytes_human(tx_bytes as usize), 8),
            pad(&human(aggregate), 11),
            pad(&human(aggregate), 11),
        );
    }
    println!("  Every validator receives and executes every transaction, so per-node");
    println!("  ingress equals the aggregate. Sharding execution is the only thing");
    println!("  that divides it, and that is a protocol decision, not a transport one.");
    println!();

    println!("== Erasure coding of one batch payload ==");
    let batch_payload = u128::from(transactions_per_certificate) * u128::from(HYBRID_TX_BYTES);
    println!(
        "  payload per certificate: {} (hybrid, {transactions_per_certificate} tx)",
        bytes_human(usize::try_from(batch_payload).unwrap_or(usize::MAX))
    );
    println!(
        "  {}  {}  {}  {}  {}",
        left("enough/total", 13),
        pad("overhead", 9),
        pad("on the wire", 12),
        pad("per shard", 10),
        pad("streams", 8),
    );
    for (enough, total) in ERASURE_SHAPES {
        let payload = u64::try_from(batch_payload).unwrap_or(u64::MAX);
        let wire = erasure_bytes(payload, enough, total);
        let shard = payload / enough;
        println!(
            "  {}  {}  {}  {}  {}",
            left(&format!("{enough}/{total}"), 13),
            pad(
                &format!("{:.0}%", (total as f64 / enough as f64 - 1.0) * 100.0),
                9,
            ),
            pad(
                &bytes_human(usize::try_from(wire).unwrap_or(usize::MAX)),
                12
            ),
            pad(
                &bytes_human(usize::try_from(shard).unwrap_or(usize::MAX)),
                10
            ),
            pad(&enough.to_string(), 8),
        );
    }
    println!("  Erasure coding trades bytes (total/enough) for smaller parallel streams.");
    println!("  Whether that helps end to end depends on the topology, which this model");
    println!("  does not simulate.");
    println!();

    println!("== What moves the number ==");
    println!("  1. Batching: certificates/second is the multiplier. 1,000 tx per");
    println!("     certificate is 1,000x less certificate traffic than one.");
    println!("  2. Certificate size: 3,309 B ML-DSA signatures make a 100-validator");
    println!("     certificate 331 kB against 6.9 kB for Ed25519.");
    println!("  3. Committees or sharding: sending to fewer than n-1 peers is the only");
    println!("     way to cut per-node egress below (n-1)/n of the originator total.");
    println!("  4. Fanout: connections and latency, not bandwidth.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_transaction_per_certificate_reproduces_the_33_gb_per_second_figure() {
        // §8.8: 100,000 certificates/s at 331,403 B each is ~33 GB/s of
        // certificate bytes before any dissemination.
        let certificates = certificates_per_second(100_000, 1);
        assert_eq!(certificates, 100_000);
        let originators = originator_bytes_per_second(certificates, 331_403);
        assert_eq!(originators, 33_140_300_000);
        assert_eq!(human(originators), "33.14 GB/s");
    }

    #[test]
    fn batching_divides_the_certificate_stream() {
        let one = certificates_per_second(100_000, 1);
        let thousand = certificates_per_second(100_000, 1_000);
        assert_eq!(thousand * 1_000, one);
        assert_eq!(certificates_per_second(1_000, 3_000), 1);
    }

    #[test]
    fn per_node_egress_is_the_originated_total_less_this_nodes_share() {
        let originators = 1_000_000u128;
        assert_eq!(per_node_egress(originators, 100), 990_000);
        assert_eq!(per_node_egress(originators, 2), 500_000);
        assert_eq!(per_node_egress(originators, 1), 0);
    }

    #[test]
    fn fanout_changes_hops_not_bytes() {
        // Hops drop with fanout; the byte formula has no fanout parameter at all,
        // which is the point.
        assert_eq!(hops(100, 2), 6);
        assert_eq!(hops(100, 4), 4);
        assert_eq!(hops(100, 10), 2);
        assert_eq!(hops(100, 99), 1);
        assert_eq!(hops(1, 4), 1);
        assert_eq!(hops(100, 1), 1);
    }

    #[test]
    fn erasure_overhead_is_the_total_over_enough_ratio() {
        assert_eq!(erasure_bytes(1_000, 10, 16), 1_600);
        assert_eq!(erasure_bytes(1_000, 16, 16), 1_000);
        assert_eq!(erasure_bytes(1_000, 0, 16), 1_000);
    }

    #[test]
    fn certificate_style_is_quadratic_in_signatures() {
        let styles = styles(100, 64).unwrap();
        assert_eq!(styles[0].signatures_per_round, 10_000);
        assert_eq!(styles[1].signatures_per_round, 100);
        assert_eq!(styles[2].signatures_per_round, 100);
    }

    #[test]
    fn sparse_starfish_speed_adds_only_a_bitmask() {
        let validators = 100;
        let styles = styles(validators, 3_309).unwrap();
        let bitmask = validators.div_ceil(8);
        assert_eq!(styles[2].artifact_bytes - styles[1].artifact_bytes, bitmask);
        assert_eq!(styles[2].leader_bytes - styles[1].leader_bytes, bitmask);
    }

    #[test]
    fn the_leader_block_carries_the_reference_list() {
        let styles = styles(100, 64).unwrap();
        assert!(styles[1].leader_bytes > styles[1].artifact_bytes * 2);
        assert!(styles[2].leader_bytes > styles[2].artifact_bytes * 2);
    }

    #[test]
    fn one_signature_per_block_beats_one_bundle_per_certificate() {
        // ML-DSA-65 at n=100: the certificate style pays 100 signatures per
        // artifact, so it should be more than an order of magnitude larger even
        // after adding the bitmask and the leader list.
        let styles = styles(100, 3_309).unwrap();
        assert!(styles[0].artifact_bytes > styles[2].leader_bytes * 10);
    }
}
