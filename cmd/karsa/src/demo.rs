//! Prints the algorithm registry and a sample domain-separated signing payload.

use crypto::domain::{TxSigningFields, encode_tx_signing_payload};
use crypto::registry::{self, ALG_ED25519, AlgorithmKind, AlgorithmStatus};
use crypto::scheme::{Ed25519Scheme, verify_signature};

fn status_name(status: AlgorithmStatus) -> &'static str {
    match status {
        AlgorithmStatus::Enabled => "enabled",
        AlgorithmStatus::ActivationGated => "activation_gated",
        AlgorithmStatus::Deprecated => "deprecated",
    }
}

fn kind_name(kind: AlgorithmKind) -> &'static str {
    match kind {
        AlgorithmKind::Signature => "signature",
        AlgorithmKind::KeyEncapsulation => "key_encapsulation",
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("== Karsa registry (Rust) ==");
    println!("  ml-dsa enabled: {}", registry::ml_dsa_enabled());
    for spec in &registry::REGISTRY {
        println!(
            "  0x{:04x} {:<20} {:<9} {:<15} {:<18} pk={}B sig={}B",
            spec.id,
            spec.name,
            spec.specification,
            kind_name(spec.kind),
            status_name(spec.status),
            spec.public_key_size,
            spec.signature_size,
        );
    }

    let payload_hash = [0u8; 32];
    let fields = TxSigningFields {
        protocol_version: 1,
        chain_id: b"karsa-demo-1",
        sender: b"acct_alice",
        sequence: 1,
        fee: 1000,
        expiration: 2_000_000_000,
        policy_version: 1,
        payload_hash: &payload_hash,
    };
    let payload = encode_tx_signing_payload(&fields)?;
    let tag_len = u32::from_le_bytes(payload[0..4].try_into()?) as usize;
    let tag = std::str::from_utf8(&payload[4..4 + tag_len])?;

    println!();
    println!("  tx signing payload: {} bytes", payload.len());
    println!("  domain tag:         {tag}");

    let (public_key, private_key) = Ed25519Scheme::generate_keypair()?;
    let message = b"karsa rust demo";
    let signature = Ed25519Scheme.sign(&private_key, message)?;
    verify_signature(ALG_ED25519, &public_key, message, &signature)?;
    println!();
    println!(
        "  ed25519:            signed and verified a {} byte signature",
        signature.len()
    );
    Ok(())
}
