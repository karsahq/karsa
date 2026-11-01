//! Drives the demo node over keep-alive TCP connections and reports accepted
//! transactions per second.
//!
//! Signing happens before the timer starts, so this measures the node, not the
//! client. Each worker uses its own account (`load-0`, `load-1`, ...) so the
//! node's per-sender replay check does not reject parallel traffic.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::Authorization;

const DEMO_CHAIN_ID: &[u8] = b"karsa-demo-1";
const DEMO_KEY_ID: &[u8] = b"alice-1";
const TARGET: &str = "127.0.0.1:8099";

/// The node registers one benchmark account per worker, so the limits agree.
const MAX_WORKERS: usize = 32;

pub fn run(count: usize, concurrency: usize) -> Result<(), Box<dyn std::error::Error>> {
    if count == 0 || concurrency == 0 {
        return Err("count and concurrency must be positive".into());
    }
    if concurrency > MAX_WORKERS {
        return Err(format!("concurrency must be at most {MAX_WORKERS}").into());
    }
    let per_worker = count / concurrency;
    if per_worker == 0 {
        return Err("count must be at least the concurrency".into());
    }

    let private_key = demo_private_key()?;

    println!(
        "generating {} signed transactions for {concurrency} workers...",
        per_worker * concurrency
    );
    let mut batches = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let sender = format!("load-{worker}");
        let mut bodies = Vec::with_capacity(per_worker);
        for sequence in 1..=per_worker {
            match signed_body(&sender, sequence as u64, &private_key) {
                Ok(body) => bodies.push(body),
                Err(error) => return Err(format!("signing failed: {error}").into()),
            }
        }
        batches.push(bodies);
    }

    let start = Instant::now();
    let handles: Vec<_> = batches
        .into_iter()
        .enumerate()
        .map(|(id, bodies)| std::thread::spawn(move || worker(id, bodies)))
        .collect();
    let mut accepted = 0usize;
    for handle in handles {
        accepted += handle.join().unwrap_or(0);
    }
    let elapsed = start.elapsed();

    let total = per_worker * concurrency;
    let nanoseconds = elapsed.as_nanos().max(1);
    let tps = (accepted as u128 * 1_000_000_000) / nanoseconds;

    println!();
    println!("  accepted:   {accepted}");
    println!("  rejected:   {}", total - accepted);
    println!("  elapsed:    {} ms", elapsed.as_millis());
    println!("  throughput: {tps} tx/s");
    Ok(())
}

fn demo_private_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let seed = [0x42u8; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = seed.to_vec();
    private_key.extend_from_slice(&public_key);
    Ok(private_key)
}

fn signed_body(
    sender: &str,
    sequence: u64,
    private_key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut transaction = Transaction {
        protocol_version: PROTOCOL_VERSION_V1,
        chain_id: DEMO_CHAIN_ID.to_vec(),
        sender: sender.as_bytes().to_vec(),
        sequence,
        fee: 1_000,
        expiration: 2_000_000_000,
        policy_version: 1,
        payload: b"load test payload".to_vec(),
        authorization: Vec::new(),
    };
    let signature = Ed25519Scheme.sign(private_key, &transaction.signing_payload()?)?;
    transaction.authorization.push(Authorization {
        algorithm_id: ALG_ED25519,
        key_id: DEMO_KEY_ID.to_vec(),
        signature,
    });
    Ok(hex::encode(transaction.encode()?))
}

fn worker(id: usize, bodies: Vec<String>) -> usize {
    let mut stream = match TcpStream::connect(TARGET) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("worker {id}: cannot connect to {TARGET}: {error}");
            return 0;
        }
    };
    let _ = stream.set_nodelay(true);
    let mut buffer = [0u8; 16 * 1024];
    let mut accepted = 0usize;

    for body in bodies {
        let request = format!(
            "POST /tx HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        if stream.write_all(request.as_bytes()).is_err() {
            break;
        }
        match read_status(&mut stream, &mut buffer) {
            Ok(202) => accepted += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    accepted
}

/// Reads one HTTP response from a keep-alive connection and returns the status
/// after consuming the body.
fn read_status(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<u16> {
    let mut received: Vec<u8> = Vec::with_capacity(1024);
    let mut header_end = None;
    while header_end.is_none() {
        let read = stream.read(buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading headers",
            ));
        }
        received.extend_from_slice(&buffer[..read]);
        header_end = find_header_end(&received);
        if received.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response headers exceed 64 KiB",
            ));
        }
    }
    let header_end = header_end.expect("the loop exits when a header end is found");

    let text = String::from_utf8_lossy(&received[..header_end]);
    let status = text
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    let mut content_length = 0usize;
    for line in text.split("\r\n") {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body_have = received.len() - (header_end + 4);
    while body_have < content_length {
        let read = stream.read(buffer)?;
        if read == 0 {
            break;
        }
        body_have += read;
    }
    Ok(status)
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}
