//! Checks NIST ACVP sigVer vectors published for FIPS 204 and FIPS 205.
//!
//! The file's `algorithm` field selects the backend, so one subcommand checks
//! whichever vector set it is given. Only the groups this implementation can
//! represent are executed: the registered parameter set, the external signature
//! interface, and pure (non-pre-hashed) signatures with an explicit context.
//! Everything else is counted as skipped rather than silently ignored.

use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct AcvpFile {
    #[serde(default)]
    algorithm: String,
    #[serde(rename = "isSample")]
    is_sample: bool,
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "signatureInterface")]
    signature_interface: String,
    #[serde(rename = "preHash")]
    pre_hash: String,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    pk: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    context: String,
    signature: String,
    #[serde(default)]
    reason: String,
}

/// The single parameter set this build registers for each algorithm family.
#[derive(Clone, Copy)]
enum Backend {
    MlDsa65,
    SlhDsaSha2_128s,
}

impl Backend {
    fn for_algorithm(algorithm: &str) -> Option<Self> {
        if algorithm.contains("ML-DSA") {
            Some(Self::MlDsa65)
        } else if algorithm.contains("SLH-DSA") {
            Some(Self::SlhDsaSha2_128s)
        } else {
            None
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        }
    }

    fn verify(self, public_key: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> bool {
        match self {
            Self::MlDsa65 => {
                crypto::ml_dsa::verify_with_context(public_key, message, signature, context).is_ok()
            }
            Self::SlhDsaSha2_128s => {
                crypto::slh_dsa::verify_with_context(public_key, message, signature, context)
                    .is_ok()
            }
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let suite: AcvpFile = serde_json::from_str(&data)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    let backend = Backend::for_algorithm(&suite.algorithm).ok_or_else(|| {
        format!(
            "{}: unsupported ACVP algorithm `{}`",
            path.display(),
            suite.algorithm
        )
    })?;
    check(&suite, backend)
}

fn check(suite: &AcvpFile, backend: Backend) -> Result<(), Box<dyn std::error::Error>> {
    let mut executed = 0usize;
    let mut matched = 0usize;
    let mut skipped = 0usize;
    let mut mismatches = Vec::new();

    for group in &suite.test_groups {
        if !is_supported(group, backend) {
            skipped += group.tests.len();
            continue;
        }
        for test in &group.tests {
            executed += 1;
            let verified = verify_case(test, backend).unwrap_or(false);
            if verified == test.test_passed {
                matched += 1;
            } else if mismatches.len() < 10 {
                mismatches.push(format!(
                    "tcId={} expected={} got={} ({})",
                    test.tc_id, test.test_passed, verified, test.reason
                ));
            }
        }
    }

    println!(
        "{} sigVer, external interface, pure signatures, explicit context",
        backend.label()
    );
    println!("  vectors:    {}", suite.is_sample);
    println!("  executed:   {executed}");
    println!("  matched:    {matched}");
    println!("  mismatched: {}", executed - matched);
    println!("  skipped:    {skipped} (other parameter sets or interfaces)");
    for line in &mismatches {
        println!("  MISMATCH {line}");
    }

    if executed == 0 {
        return Err(format!(
            "no {} external/pure vectors found in this file",
            backend.label()
        )
        .into());
    }
    if matched != executed {
        return Err(format!("{} of {executed} vectors mismatched", executed - matched).into());
    }
    Ok(())
}

fn is_supported(group: &Group, backend: Backend) -> bool {
    group.parameter_set == backend.label()
        && group.signature_interface == "external"
        && group.pre_hash == "pure"
}

/// Returns the verification result, mapping any error to "did not verify"
/// because ACVP asks only whether the signature is accepted.
fn verify_case(test: &TestCase, backend: Backend) -> Option<bool> {
    let public_key = hex::decode(&test.pk).ok()?;
    let message = hex::decode(&test.message).ok()?;
    let signature = hex::decode(&test.signature).ok()?;
    let context = hex::decode(&test.context).ok()?;
    Some(backend.verify(&public_key, &message, &signature, &context))
}
