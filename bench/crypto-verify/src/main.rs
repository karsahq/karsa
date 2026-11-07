//! Standalone benchmark for the protocol-lever decision.
//!
//! Three questions, one machine, median of three runs:
//!
//! 1. What does the current Ed25519 batch path cost at 1,000 and 4,096
//!    distinct transaction messages, and what does the per-transaction
//!    fallback cost?
//! 2. What does BLS12-381 aggregate verification cost for the same batches,
//!    including wire parsing, per-signature subgroup checks, and failure
//!    attribution by binary splitting?
//! 3. What does certificate verification cost at n=10 and n=30 for the
//!    current Ed25519 quorum certificate and for a BLS aggregate certificate?
//!
//! The target is deliberately outside the workspace. The BLS dependency does
//! not enter the default build, and `cargo test --all-features` in the
//! workspace is unaffected.
//!
//! Run with:
//!
//! ```text
//! CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \
//!   cargo run --release --manifest-path bench/crypto-verify/Cargo.toml
//! ```
//!
//! Measured vs modeled is labeled in the output. Nothing here changes
//! consensus or the trust model.

use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

use blst::BLST_ERROR;
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use crypto::registry::ALG_ED25519;
use crypto::scheme::{Ed25519BatchEntry, Ed25519Scheme, SignatureScheme, verify_ed25519_batch};
use validator::{Certificate, NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, bitmap_of};

/// Domain separation tag for BLS signatures in G2 (the `min_pk` layout).
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Transaction batch sizes from the measured TPS work.
const BATCH_SIZES: [usize; 2] = [1_000, 4_096];
/// Verifier-thread budgets. Four is the measured optimum on the 8C/16T runner.
const THREAD_COUNTS: [usize; 2] = [1, 4];
/// Launch committee sizes.
const CERTIFICATE_SIZES: [usize; 2] = [10, 30];
/// Timing runs. The project standard is median of three.
const RUNS: usize = 3;
/// Repetitions for cheap operations so timer noise stays small.
const CERTIFICATE_ITERATIONS: usize = 100;
const CERTIFICATE_FAILURE_ITERATIONS: usize = 20;
const SINGLE_VERIFY_ITERATIONS: usize = 10_000;

type BenchResult<T> = Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("crypto-verify-bench: {error}");
        std::process::exit(1);
    }
}

fn run() -> BenchResult<()> {
    if cfg!(debug_assertions) {
        eprintln!("warning: this is a debug build; timing numbers are meaningless");
    }

    println!("== crypto verification benchmark ==");
    print_machine("start");
    println!(
        "  runs: {RUNS} (median), certificate reps: {CERTIFICATE_ITERATIONS}, \
         single-verify reps: {SINGLE_VERIFY_ITERATIONS}"
    );
    println!();

    let largest = *BATCH_SIZES.iter().max().expect("sizes are not empty");
    println!("building fixtures (not timed)...");
    let ed25519 = Ed25519Fixture::new(largest)?;
    let bls = BlsFixture::new(largest)?;
    println!(
        "  Ed25519: {} keys/messages, BLS12-381: {} keys/messages",
        ed25519.len(),
        bls.len()
    );
    println!();

    let mut ed25519_batch_4096 = [Duration::ZERO; 2];
    let mut bls_full_4096 = [Duration::ZERO; 2];
    let mut ed25519_failure_4096 = Duration::ZERO;
    let mut bls_failure_4096 = Duration::ZERO;

    println!("== 1. Ed25519 transaction batch verification ==");
    println!(
        "  path: crypto::scheme::verify_ed25519_batch (key/signature parsing, \
         small-order R check, batch equation)"
    );
    println!(
        "  messages: distinct, {} bytes; keys: distinct",
        ed25519.message_len()
    );
    println!();
    println!(
        "  {:>5}  {:>7}  {:>14}  {:>15}  {:>13}  {:>10}",
        "n", "threads", "median ms", "range ms", "us/signature", "tx/s"
    );
    for &n in &BATCH_SIZES {
        for &threads in &THREAD_COUNTS {
            let samples = if threads == 1 {
                measure(|| verify_ed25519_batch(&ed25519.entries(n)))
            } else {
                measure(|| ed25519_batch_threaded(&ed25519, n, threads))
            };
            let med = median(&samples);
            print_measurement_row(n, threads, &samples, n);
            if n == 4_096 {
                let slot = if threads == 1 { 0 } else { 1 };
                ed25519_batch_4096[slot] = med;
            }
        }
    }
    println!();

    println!("  per-transaction fallback (no batch equation):");
    println!(
        "  {:>5}  {:>7}  {:>14}  {:>15}  {:>13}  {:>10}",
        "n", "threads", "median ms", "range ms", "us/signature", "tx/s"
    );
    for &n in &BATCH_SIZES {
        let samples = measure(|| ed25519_individual(&ed25519, n));
        print_measurement_row(n, 1, &samples, n);
    }
    println!();

    println!("  failure path: one invalid signature at the last position");
    println!("  (batch fails, then the current per-transaction fallback re-checks all)");
    println!(
        "  {:>5}  {:>14}  {:>15}  {:>10}",
        "n", "median ms", "range ms", "found"
    );
    for &n in &BATCH_SIZES {
        let samples = measure(|| ed25519_failure(&ed25519, n).0);
        let (_, found) = ed25519_failure(&ed25519, n);
        let med = median(&samples);
        if n == 4_096 {
            ed25519_failure_4096 = med;
        }
        println!(
            "  {n:>5}  {:>14.2}  {:>15}  {:>10}",
            milliseconds(med),
            spread(&samples),
            found
        );
        debug_assert_eq!(found, n - 1);
    }
    println!();

    println!("== 2. BLS12-381 aggregate verification (min_pk) ==");
    println!(
        "  sizes: public key {} B, signature {} B, aggregate signature {} B",
        bls.public_key_size(),
        bls.signature_size(),
        bls.aggregate_signature_size()
    );
    println!(
        "  blst is built with no-threads, so one row is one verifier thread; \
         parallelism is explicit"
    );
    println!(
        "  full wire path = deserialize + subgroup-check every signature + \
         aggregate + multi-pairing"
    );
    println!();
    println!(
        "  {:>5}  {:>32}  {:>14}  {:>15}  {:>13}  {:>10}",
        "n", "path", "median ms", "range ms", "us/signature", "tx/s"
    );
    for &n in &BATCH_SIZES {
        let sig_refs: Vec<&Signature> = bls.signatures[..n].iter().collect();
        let pk_refs: Vec<&PublicKey> = bls.public_keys[..n].iter().collect();
        let msg_refs: Vec<&[u8]> = bls.messages[..n].iter().map(Vec::as_slice).collect();

        let aggregate_only = measure(|| {
            AggregateSignature::aggregate(&sig_refs, false)
                .expect("fixture signatures aggregate")
                .to_signature()
        });
        print_path_row(n, "aggregate only", &aggregate_only, n);

        let aggregate = AggregateSignature::aggregate(&sig_refs, false)
            .expect("fixture signatures aggregate")
            .to_signature();
        let verify_only =
            measure(|| aggregate.aggregate_verify(false, &msg_refs, BLS_DST, &pk_refs, false));
        print_path_row(n, "multi-pairing only (pre-aggregated)", &verify_only, n);

        let batch_only = measure(|| {
            let aggregate = AggregateSignature::aggregate(&sig_refs, false)
                .expect("fixture signatures aggregate")
                .to_signature();
            aggregate.aggregate_verify(false, &msg_refs, BLS_DST, &pk_refs, false)
        });
        print_path_row(n, "aggregate + verify (pre-validated)", &batch_only, n);

        let parse_validate = measure(|| bls.parse_only(&bls.signature_bytes[..n]));
        print_path_row(n, "deserialize + subgroup check", &parse_validate, n);

        for &threads in &THREAD_COUNTS {
            let samples = if threads == 1 {
                measure(|| bls.full(0, n))
            } else {
                measure(|| bls.full_threaded(n, threads))
            };
            let med = median(&samples);
            let label = format!("full wire path ({threads} thread{})", plural(threads));
            print_path_row(n, &label, &samples, n);
            if n == 4_096 {
                let slot = if threads == 1 { 0 } else { 1 };
                bls_full_4096[slot] = med;
            }
        }
    }
    println!();

    println!("  failure path: one invalid signature at the last position");
    println!("  (full wire path fails, then binary splitting identifies the bad index)");
    println!(
        "  {:>5}  {:>14}  {:>15}  {:>10}",
        "n", "median ms", "range ms", "found"
    );
    for &n in &BATCH_SIZES {
        let bad_signature_bytes = bls.bad_signature_bytes(n);
        let samples = measure(|| {
            bls.failure(&bad_signature_bytes[..n], n)
                .expect("failure fixture must not verify")
                .0
        });
        let (_, found) = bls.failure(&bad_signature_bytes[..n], n)?;
        let med = median(&samples);
        if n == 4_096 {
            bls_failure_4096 = med;
        }
        println!(
            "  {n:>5}  {:>14.2}  {:>15}  {:>10}",
            milliseconds(med),
            spread(&samples),
            found
        );
        debug_assert_eq!(found, n - 1);
    }
    println!();

    println!("== 3. Certificate verification (n signers over one payload) ==");
    println!(
        "  Ed25519 path is validator::Certificate::verify; BLS path is \
         fast_aggregate_verify_pre_aggregated"
    );
    println!();
    println!(
        "  {:>7}  {:>3}  {:>38}  {:>15}  {:>13}",
        "scheme", "n", "path", "median us", "range us"
    );
    for &n in &CERTIFICATE_SIZES {
        let ed_cert = Ed25519CertificateFixture::new(n)?;
        let batch = measure_repeated(CERTIFICATE_ITERATIONS, || {
            ed_cert.certificate.verify(&ed_cert.set).is_ok()
        });
        print_certificate_row("ed25519", n, "batch path", &batch, CERTIFICATE_ITERATIONS);

        let individual = measure_repeated(CERTIFICATE_ITERATIONS, || {
            ed_cert.certificate.verify_individual(&ed_cert.set).is_ok()
        });
        print_certificate_row(
            "ed25519",
            n,
            "individual path",
            &individual,
            CERTIFICATE_ITERATIONS,
        );

        let bls_cert = BlsCertificateFixture::new(n)?;
        let pre_aggregated = measure_repeated(CERTIFICATE_ITERATIONS, || {
            bls_cert
                .aggregate_signature
                .fast_aggregate_verify_pre_aggregated(
                    false,
                    &bls_cert.payload,
                    BLS_DST,
                    &bls_cert.aggregate_public_key,
                )
        });
        print_certificate_row(
            "bls",
            n,
            "pre-aggregated key and signature",
            &pre_aggregated,
            CERTIFICATE_ITERATIONS,
        );

        let with_key_aggregation = measure_repeated(CERTIFICATE_ITERATIONS, || {
            let pk_refs: Vec<&PublicKey> = bls_cert.public_keys.iter().collect();
            let aggregate_public_key = AggregatePublicKey::aggregate(&pk_refs, false)
                .expect("certificate keys aggregate")
                .to_public_key();
            bls_cert
                .aggregate_signature
                .fast_aggregate_verify_pre_aggregated(
                    false,
                    &bls_cert.payload,
                    BLS_DST,
                    &aggregate_public_key,
                )
        });
        print_certificate_row(
            "bls",
            n,
            "aggregate keys + verify",
            &with_key_aggregation,
            CERTIFICATE_ITERATIONS,
        );

        let build = measure_repeated(CERTIFICATE_ITERATIONS, || {
            let signatures: Vec<Signature> = bls_cert
                .secret_keys
                .iter()
                .map(|key| key.sign(&bls_cert.payload, BLS_DST, &[]))
                .collect();
            let sig_refs: Vec<&Signature> = signatures.iter().collect();
            let _aggregate_signature =
                AggregateSignature::aggregate(&sig_refs, true).expect("signatures aggregate");
            let pk_refs: Vec<&PublicKey> = bls_cert.public_keys.iter().collect();
            let _aggregate_public_key =
                AggregatePublicKey::aggregate(&pk_refs, false).expect("keys aggregate");
        });
        print_certificate_row(
            "bls",
            n,
            "producer: n signs + aggregates",
            &build,
            CERTIFICATE_ITERATIONS,
        );
    }
    println!();

    println!("  certificate failure attribution: one invalid signature at the last position");
    println!(
        "  {:>7}  {:>3}  {:>38}  {:>15}  {:>13}",
        "scheme", "n", "path", "median us", "range us"
    );
    for &n in &CERTIFICATE_SIZES {
        let ed_cert = Ed25519CertificateFixture::new(n)?;
        let mut bad_certificate = ed_cert.certificate.clone();
        let first_signature = bad_certificate.signatures[0].clone();
        bad_certificate.signatures[n - 1] = first_signature;
        let ed_failure = measure_repeated(CERTIFICATE_FAILURE_ITERATIONS, || {
            let batch_ok = bad_certificate.verify(&ed_cert.set).is_ok();
            let individual_ok = bad_certificate.verify_individual(&ed_cert.set).is_ok();
            (batch_ok, individual_ok)
        });
        print_certificate_row(
            "ed25519",
            n,
            "batch fail + individual scan",
            &ed_failure,
            CERTIFICATE_FAILURE_ITERATIONS,
        );

        let bls_cert = BlsCertificateFixture::new(n)?;
        let mut bad_signatures = bls_cert.signatures.clone();
        let first_signature = bad_signatures[0];
        bad_signatures[n - 1] = first_signature;
        let bls_failure = measure_repeated(CERTIFICATE_FAILURE_ITERATIONS, || {
            bls_cert.find_bad(&bad_signatures)
        });
        print_certificate_row(
            "bls",
            n,
            "binary split",
            &bls_failure,
            CERTIFICATE_FAILURE_ITERATIONS,
        );
    }
    println!();

    println!("  threshold Schnorr (FROST) certificate, modeled not measured:");
    let (ed_public_key, ed_private_key) = deterministic_ed25519_key(900_000)?;
    let ed_message = b"karsa-bench-single-signature";
    let ed_signature = Ed25519Scheme.sign(&ed_private_key, ed_message)?;
    let single = measure_repeated(SINGLE_VERIFY_ITERATIONS, || {
        Ed25519Scheme
            .verify(&ed_public_key, ed_message, &ed_signature)
            .is_ok()
    });
    let single_median = median(&single);
    println!(
        "    one Ed25519 verify: {:.2} us (median of {RUNS}); a FROST/Schnorr \
         certificate verifies as one signature, independent of n",
        microseconds_per(single_median, SINGLE_VERIFY_ITERATIONS)
    );
    println!(
        "    this is a proxy for the final-signature check only; DKG, share \
         verification, and coordinator cost are not measured"
    );
    println!();

    println!("== 4. Decision rule ==");
    println!(
        "  rule: BLS transaction aggregation is worth pursuing only if aggregate \
         verification + failure handling is at least 2x faster than the Ed25519 \
         batch path at 4,096 transactions"
    );
    println!();
    println!(
        "  happy path, 1 thread:  Ed25519 {:.2} ms vs BLS {:.2} ms -> {:.2}x {}",
        milliseconds(ed25519_batch_4096[0]),
        milliseconds(bls_full_4096[0]),
        ratio(ed25519_batch_4096[0], bls_full_4096[0]),
        verdict(ed25519_batch_4096[0], bls_full_4096[0])
    );
    println!(
        "  happy path, 4 threads: Ed25519 {:.2} ms vs BLS {:.2} ms -> {:.2}x {}",
        milliseconds(ed25519_batch_4096[1]),
        milliseconds(bls_full_4096[1]),
        ratio(ed25519_batch_4096[1], bls_full_4096[1]),
        verdict(ed25519_batch_4096[1], bls_full_4096[1])
    );
    println!(
        "  failure path, 1 thread: Ed25519 {:.2} ms vs BLS {:.2} ms -> {:.2}x {}",
        milliseconds(ed25519_failure_4096),
        milliseconds(bls_failure_4096),
        ratio(ed25519_failure_4096, bls_failure_4096),
        verdict(ed25519_failure_4096, bls_failure_4096)
    );
    println!();
    println!(
        "  note: failure paths are whole-batch single-thread costs. A 4-thread \
         verifier falls back or splits only its own chunk."
    );
    println!();

    print_machine("end");
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Ed25519Fixture {
    public_keys: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
}

impl Ed25519Fixture {
    fn new(count: usize) -> BenchResult<Self> {
        let mut public_keys = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);
        let mut messages = Vec::with_capacity(count);
        for index in 0..count {
            let (public_key, private_key) = deterministic_ed25519_key(index)?;
            let message = benchmark_message(index);
            let signature = Ed25519Scheme.sign(&private_key, &message)?;
            public_keys.push(public_key);
            signatures.push(signature);
            messages.push(message);
        }
        let fixture = Self {
            public_keys,
            signatures,
            messages,
        };
        fixture.assert_valid(count)?;
        Ok(fixture)
    }

    fn len(&self) -> usize {
        self.messages.len()
    }

    fn message_len(&self) -> usize {
        self.messages[0].len()
    }

    fn entries(&self, count: usize) -> Vec<Ed25519BatchEntry<'_>> {
        (0..count)
            .map(|index| Ed25519BatchEntry {
                public_key: &self.public_keys[index],
                message: &self.messages[index],
                signature: &self.signatures[index],
            })
            .collect()
    }

    fn assert_valid(&self, count: usize) -> BenchResult<()> {
        verify_ed25519_batch(&self.entries(count))?;
        Ok(())
    }
}

struct BlsFixture {
    public_keys: Vec<PublicKey>,
    public_key_bytes: Vec<Vec<u8>>,
    signatures: Vec<Signature>,
    signature_bytes: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
}

impl BlsFixture {
    fn new(count: usize) -> BenchResult<Self> {
        let mut public_keys = Vec::with_capacity(count);
        let mut public_key_bytes = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);
        let mut signature_bytes = Vec::with_capacity(count);
        let mut messages = Vec::with_capacity(count);
        for index in 0..count {
            let secret_key = SecretKey::key_gen(&benchmark_ikm(index), b"karsa-bench")
                .map_err(|error| format!("BLS key {index}: {error:?}"))?;
            let public_key = secret_key.sk_to_pk();
            let message = benchmark_message(index);
            let signature = secret_key.sign(&message, BLS_DST, &[]);
            public_key_bytes.push(public_key.to_bytes().to_vec());
            signature_bytes.push(signature.to_bytes().to_vec());
            public_keys.push(public_key);
            signatures.push(signature);
            messages.push(message);
        }
        let fixture = Self {
            public_keys,
            public_key_bytes,
            signatures,
            signature_bytes,
            messages,
        };
        fixture.assert_valid(count)?;
        Ok(fixture)
    }

    fn len(&self) -> usize {
        self.messages.len()
    }

    fn public_key_size(&self) -> usize {
        self.public_key_bytes[0].len()
    }

    fn signature_size(&self) -> usize {
        self.signature_bytes[0].len()
    }

    fn aggregate_signature_size(&self) -> usize {
        self.signatures[0].to_bytes().len()
    }

    fn assert_valid(&self, count: usize) -> BenchResult<()> {
        for (index, signature) in self.signatures[..count].iter().enumerate() {
            signature
                .validate(true)
                .map_err(|error| format!("BLS signature {index}: {error:?}"))?;
        }
        let (sigs, pks, messages) = self.refs(count);
        let aggregate = AggregateSignature::aggregate(&sigs, false)
            .map_err(|error| format!("BLS aggregate: {error:?}"))?
            .to_signature();
        if aggregate.aggregate_verify(false, &messages, BLS_DST, &pks, false) != BLST_SUCCESS {
            return Err("BLS fixture does not verify".into());
        }
        Ok(())
    }

    fn refs(&self, count: usize) -> (Vec<&Signature>, Vec<&PublicKey>, Vec<&[u8]>) {
        let signatures = self.signatures[..count].iter().collect();
        let public_keys = self.public_keys[..count].iter().collect();
        let messages = self.messages[..count].iter().map(Vec::as_slice).collect();
        (signatures, public_keys, messages)
    }

    /// Full wire path over `[start, end)`: deserialize, subgroup-check every
    /// signature, aggregate, then verify the multi-pairing equation.
    fn full(&self, start: usize, end: usize) -> Result<bool, String> {
        let (public_keys, signatures) = self.parse(&self.signature_bytes, start, end)?;
        Ok(self.verify_parsed(&public_keys, &signatures, start, end))
    }

    fn full_threaded(&self, count: usize, threads: usize) -> Result<bool, String> {
        let chunk = count.div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|thread| {
                    let start = thread * chunk;
                    let end = ((thread + 1) * chunk).min(count);
                    scope.spawn(move || {
                        if start >= end {
                            Ok(true)
                        } else {
                            self.full(start, end)
                        }
                    })
                })
                .collect();
            let mut all = true;
            for handle in handles {
                all &= handle.join().expect("BLS worker panicked")?;
            }
            Ok(all)
        })
    }

    fn parse_only(&self, signature_bytes: &[Vec<u8>]) -> Result<usize, String> {
        let (_, signatures) = self.parse(signature_bytes, 0, signature_bytes.len())?;
        Ok(signatures.len())
    }

    fn parse(
        &self,
        signature_bytes: &[Vec<u8>],
        start: usize,
        end: usize,
    ) -> Result<(Vec<PublicKey>, Vec<Signature>), String> {
        if end > signature_bytes.len() || end > self.public_key_bytes.len() {
            return Err(format!("BLS parse range {start}..{end} is out of bounds"));
        }
        let mut public_keys = Vec::with_capacity(end - start);
        let mut signatures = Vec::with_capacity(end - start);
        for (index, bytes) in signature_bytes.iter().enumerate().take(end).skip(start) {
            let public_key = PublicKey::from_bytes(&self.public_key_bytes[index])
                .map_err(|error| format!("BLS public key {index}: {error:?}"))?;
            let signature = Signature::from_bytes(bytes)
                .map_err(|error| format!("BLS signature {index}: {error:?}"))?;
            signature
                .validate(true)
                .map_err(|error| format!("BLS signature {index} subgroup: {error:?}"))?;
            public_keys.push(public_key);
            signatures.push(signature);
        }
        Ok((public_keys, signatures))
    }

    fn verify_parsed(
        &self,
        public_keys: &[PublicKey],
        signatures: &[Signature],
        start: usize,
        end: usize,
    ) -> bool {
        let pk_refs: Vec<&PublicKey> = public_keys.iter().collect();
        let sig_refs: Vec<&Signature> = signatures.iter().collect();
        let msg_refs: Vec<&[u8]> = self.messages[start..end]
            .iter()
            .map(Vec::as_slice)
            .collect();
        match AggregateSignature::aggregate(&sig_refs, false) {
            Ok(aggregate) => {
                aggregate
                    .to_signature()
                    .aggregate_verify(false, &msg_refs, BLS_DST, &pk_refs, false)
                    == BLST_SUCCESS
            }
            Err(_) => false,
        }
    }

    /// One invalid signature at the last position: valid point, wrong
    /// equation. Returning the bytes keeps the fixture reusable across runs.
    fn bad_signature_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        let mut bytes = self.signature_bytes[..count].to_vec();
        bytes[count - 1] = self.signature_bytes[0].clone();
        bytes
    }

    /// End-to-end failure path: parse and validate, fail the full equation,
    /// then binary-split until the bad index is found. Returns the elapsed
    /// time and the index.
    fn failure(
        &self,
        signature_bytes: &[Vec<u8>],
        count: usize,
    ) -> Result<(Duration, usize), String> {
        let start = std::time::Instant::now();
        let (public_keys, signatures) = self.parse(signature_bytes, 0, count)?;
        if self.verify_parsed(&public_keys, &signatures, 0, count) {
            return Err("failure fixture unexpectedly verified".into());
        }
        let bad = find_bad_bls(&signatures, &public_keys, &self.messages[..count]);
        Ok((start.elapsed(), bad))
    }
}

struct Ed25519CertificateFixture {
    set: ValidatorSet,
    certificate: Certificate,
}

impl Ed25519CertificateFixture {
    fn new(count: usize) -> BenchResult<Self> {
        let mut validators = Vec::with_capacity(count);
        let mut private_keys = Vec::with_capacity(count);
        for index in 0..count {
            let (public_key, private_key) = deterministic_ed25519_key(100_000 + index)?;
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key,
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            private_keys.push(private_key);
        }
        let set = ValidatorSet {
            epoch: 1,
            validators,
        };
        set.validate()?;

        let mut certificate = Certificate {
            chain_id: b"karsa-bench-1".to_vec(),
            epoch: 1,
            round: 7,
            vertex_id: b"vertex-01".to_vec(),
            validator_set_id: b"set-genesis".to_vec(),
            signer_bitmap: bitmap_of(count, count),
            signatures: Vec::new(),
        };
        let payload = certificate.signing_payload()?;
        for private_key in &private_keys {
            certificate
                .signatures
                .push(Ed25519Scheme.sign(private_key, &payload)?);
        }
        certificate.verify(&set)?;
        Ok(Self { set, certificate })
    }
}

struct BlsCertificateFixture {
    public_keys: Vec<PublicKey>,
    secret_keys: Vec<SecretKey>,
    signatures: Vec<Signature>,
    aggregate_signature: Signature,
    aggregate_public_key: PublicKey,
    payload: Vec<u8>,
}

impl BlsCertificateFixture {
    fn new(count: usize) -> BenchResult<Self> {
        let payload = certificate_payload(count)?;
        let mut public_keys = Vec::with_capacity(count);
        let mut secret_keys = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);
        for index in 0..count {
            let secret_key = SecretKey::key_gen(&benchmark_ikm(200_000 + index), b"karsa-bench")
                .map_err(|error| format!("BLS certificate key {index}: {error:?}"))?;
            let public_key = secret_key.sk_to_pk();
            let signature = secret_key.sign(&payload, BLS_DST, &[]);
            signature
                .validate(true)
                .map_err(|error| format!("BLS certificate signature {index}: {error:?}"))?;
            public_keys.push(public_key);
            secret_keys.push(secret_key);
            signatures.push(signature);
        }
        let sig_refs: Vec<&Signature> = signatures.iter().collect();
        let aggregate_signature = AggregateSignature::aggregate(&sig_refs, false)
            .map_err(|error| format!("BLS certificate aggregate: {error:?}"))?
            .to_signature();
        let pk_refs: Vec<&PublicKey> = public_keys.iter().collect();
        let aggregate_public_key = AggregatePublicKey::aggregate(&pk_refs, false)
            .map_err(|error| format!("BLS certificate key aggregate: {error:?}"))?
            .to_public_key();
        if aggregate_signature.fast_aggregate_verify_pre_aggregated(
            false,
            &payload,
            BLS_DST,
            &aggregate_public_key,
        ) != BLST_SUCCESS
        {
            return Err("BLS certificate fixture does not verify".into());
        }
        Ok(Self {
            public_keys,
            secret_keys,
            signatures,
            aggregate_signature,
            aggregate_public_key,
            payload,
        })
    }

    /// Binary split with one bad signature. Each probe verifies one subset, so
    /// the cost is `log2(n)` two-pairing checks, not `n` pairings.
    fn find_bad(&self, signatures: &[Signature]) -> usize {
        let mut low = 0;
        let mut high = signatures.len();
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            if fast_verify_certificate(
                &signatures[low..mid],
                &self.public_keys[low..mid],
                &self.payload,
            )
            .is_ok()
            {
                low = mid;
            } else {
                high = mid;
            }
        }
        low
    }
}

// ---------------------------------------------------------------------------
// Operations and timing
// ---------------------------------------------------------------------------

fn ed25519_batch_threaded(fixture: &Ed25519Fixture, count: usize, threads: usize) -> bool {
    let chunk = count.div_ceil(threads);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|thread| {
                let start = thread * chunk;
                let end = ((thread + 1) * chunk).min(count);
                scope.spawn(move || {
                    let entries: Vec<Ed25519BatchEntry<'_>> = (start..end)
                        .map(|index| Ed25519BatchEntry {
                            public_key: &fixture.public_keys[index],
                            message: &fixture.messages[index],
                            signature: &fixture.signatures[index],
                        })
                        .collect();
                    verify_ed25519_batch(&entries).is_ok()
                })
            })
            .collect();
        let results: Vec<bool> = handles
            .into_iter()
            .map(|handle| handle.join().expect("Ed25519 worker panicked"))
            .collect();
        results.into_iter().all(|ok| ok)
    })
}

fn ed25519_individual(fixture: &Ed25519Fixture, count: usize) -> usize {
    let mut verified = 0;
    for ((public_key, message), signature) in fixture.public_keys[..count]
        .iter()
        .zip(&fixture.messages[..count])
        .zip(&fixture.signatures[..count])
    {
        if Ed25519Scheme.verify(public_key, message, signature).is_ok() {
            verified += 1;
        }
    }
    verified
}

fn ed25519_failure(fixture: &Ed25519Fixture, count: usize) -> (Duration, usize) {
    let mut signatures = fixture.signatures[..count].to_vec();
    signatures[count - 1] = fixture.signatures[0].clone();
    let start = Instant::now();
    let entries: Vec<Ed25519BatchEntry<'_>> = (0..count)
        .map(|index| Ed25519BatchEntry {
            public_key: &fixture.public_keys[index],
            message: &fixture.messages[index],
            signature: &signatures[index],
        })
        .collect();
    if verify_ed25519_batch(&entries).is_ok() {
        panic!("Ed25519 failure fixture unexpectedly verified");
    }
    let mut found = None;
    for (index, signature) in signatures.iter().enumerate().take(count) {
        if Ed25519Scheme
            .verify(
                &fixture.public_keys[index],
                &fixture.messages[index],
                signature,
            )
            .is_err()
        {
            found = Some(index);
        }
    }
    (
        start.elapsed(),
        found.expect("the invalid signature must be found"),
    )
}

fn find_bad_bls(
    signatures: &[Signature],
    public_keys: &[PublicKey],
    messages: &[Vec<u8>],
) -> usize {
    let mut low = 0;
    let mut high = signatures.len();
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if verify_bls_subset(signatures, public_keys, messages, low, mid).is_ok() {
            low = mid;
        } else {
            high = mid;
        }
    }
    low
}

fn verify_bls_subset(
    signatures: &[Signature],
    public_keys: &[PublicKey],
    messages: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Result<(), BLST_ERROR> {
    let sig_refs: Vec<&Signature> = signatures[start..end].iter().collect();
    let pk_refs: Vec<&PublicKey> = public_keys[start..end].iter().collect();
    let msg_refs: Vec<&[u8]> = messages[start..end].iter().map(Vec::as_slice).collect();
    let aggregate = AggregateSignature::aggregate(&sig_refs, false)?.to_signature();
    let status = aggregate.aggregate_verify(false, &msg_refs, BLS_DST, &pk_refs, false);
    if status == BLST_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

fn fast_verify_certificate(
    signatures: &[Signature],
    public_keys: &[PublicKey],
    payload: &[u8],
) -> Result<(), BLST_ERROR> {
    let sig_refs: Vec<&Signature> = signatures.iter().collect();
    let pk_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let aggregate_signature = AggregateSignature::aggregate(&sig_refs, false)?.to_signature();
    let aggregate_public_key = AggregatePublicKey::aggregate(&pk_refs, false)?.to_public_key();
    let status = aggregate_signature.fast_aggregate_verify_pre_aggregated(
        false,
        payload,
        BLS_DST,
        &aggregate_public_key,
    );
    if status == BLST_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

fn measure<T>(mut operation: impl FnMut() -> T) -> Vec<Duration> {
    black_box(operation());
    (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            black_box(operation());
            start.elapsed()
        })
        .collect()
}

fn measure_repeated<T>(iterations: usize, mut operation: impl FnMut() -> T) -> Vec<Duration> {
    black_box(operation());
    (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(operation());
            }
            start.elapsed()
        })
        .collect()
}

fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

// ---------------------------------------------------------------------------
// Deterministic inputs
// ---------------------------------------------------------------------------

fn deterministic_ed25519_key(index: usize) -> BenchResult<(Vec<u8>, Vec<u8>)> {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    seed[8..16].copy_from_slice(&0x5a5a_5a5a_5a5a_5a5a_u64.to_le_bytes());
    seed[16..24].copy_from_slice(&0x3c3c_3c3c_3c3c_3c3c_u64.to_le_bytes());
    seed[24..].copy_from_slice(&0xa5a5_a5a5_a5a5_a5a5_u64.to_le_bytes());
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = Vec::with_capacity(64);
    private_key.extend_from_slice(&seed);
    private_key.extend_from_slice(&public_key);
    Ok((public_key.to_vec(), private_key))
}

fn benchmark_ikm(index: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    ikm[8..16].copy_from_slice(&0x3c3c_3c3c_3c3c_3c3c_u64.to_le_bytes());
    ikm[16..24].copy_from_slice(&0x5a5a_5a5a_5a5a_5a5a_u64.to_le_bytes());
    ikm[24..].copy_from_slice(&0xc3c3_c3c3_c3c3_c3c3_u64.to_le_bytes());
    ikm
}

fn benchmark_message(index: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(b"karsa-bench-tx:");
    message.extend_from_slice(&(index as u64).to_le_bytes());
    message.extend_from_slice(&[0xa5u8; 48]);
    message
}

fn certificate_payload(count: usize) -> BenchResult<Vec<u8>> {
    let certificate = Certificate {
        chain_id: b"karsa-bench-1".to_vec(),
        epoch: 1,
        round: 7,
        vertex_id: b"vertex-01".to_vec(),
        validator_set_id: b"set-genesis".to_vec(),
        signer_bitmap: bitmap_of(count, count),
        signatures: Vec::new(),
    };
    Ok(certificate.signing_payload()?)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn print_machine(label: &str) {
    let parallelism = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    println!(
        "  machine ({label}): {} | {} hardware threads | load {}",
        cpu_model(),
        parallelism,
        load_average()
    );
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".to_string())
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|text| text.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

fn print_measurement_row(n: usize, threads: usize, samples: &[Duration], operations: usize) {
    let med = median(samples);
    println!(
        "  {n:>5}  {threads:>7}  {:>14.2}  {:>15}  {:>13.2}  {:>10.0}",
        milliseconds(med),
        spread(samples),
        microseconds_per(med, operations),
        operations as f64 / med.as_secs_f64()
    );
}

fn print_path_row(n: usize, path: &str, samples: &[Duration], operations: usize) {
    let med = median(samples);
    println!(
        "  {n:>5}  {:>32}  {:>14.2}  {:>15}  {:>13.2}  {:>10.0}",
        path,
        milliseconds(med),
        spread(samples),
        microseconds_per(med, operations),
        operations as f64 / med.as_secs_f64()
    );
}

fn print_certificate_row(
    scheme: &str,
    n: usize,
    path: &str,
    samples: &[Duration],
    iterations: usize,
) {
    let med = median(samples);
    let micros = microseconds_per(med, iterations);
    let min = samples.iter().min().copied().unwrap_or_default();
    let max = samples.iter().max().copied().unwrap_or_default();
    println!(
        "  {scheme:>7}  {n:>3}  {path:>38}  {micros:>15.2}  {:>6.2}-{:<6.2}",
        microseconds_per(min, iterations),
        microseconds_per(max, iterations)
    );
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn microseconds_per(duration: Duration, operations: usize) -> f64 {
    duration.as_secs_f64() * 1e6 / operations as f64
}

fn spread(samples: &[Duration]) -> String {
    let min = samples.iter().min().copied().unwrap_or_default();
    let max = samples.iter().max().copied().unwrap_or_default();
    format!("{:.2}-{:.2}", milliseconds(min), milliseconds(max))
}

fn ratio(baseline: Duration, candidate: Duration) -> f64 {
    if candidate.is_zero() {
        f64::INFINITY
    } else {
        baseline.as_secs_f64() / candidate.as_secs_f64()
    }
}

fn verdict(baseline: Duration, candidate: Duration) -> &'static str {
    if ratio(baseline, candidate) >= 2.0 {
        "meets the 2x rule"
    } else {
        "does not meet the 2x rule"
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}
