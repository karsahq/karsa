//! Checks the NIST ACVP ML-DSA-65 sigVer vectors published for FIPS 204.
//!
//! Only the groups this implementation can represent are executed: ML-DSA-65,
//! the external signature interface, pure signatures, with an explicit context
//! string. Everything else is counted as skipped rather than silently ignored.

use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct AcvpFile {
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

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let suite: AcvpFile = serde_json::from_str(&data)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    check(&suite)
}

fn check(suite: &AcvpFile) -> Result<(), Box<dyn std::error::Error>> {
    let mut executed = 0usize;
    let mut matched = 0usize;
    let mut skipped = 0usize;
    let mut mismatches = Vec::new();

    for group in &suite.test_groups {
        if !is_supported(group) {
            skipped += group.tests.len();
            continue;
        }
        for test in &group.tests {
            executed += 1;
            let verified = verify_case(test).unwrap_or(false);
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

    println!("ML-DSA-65 sigVer, external interface, pure signatures, explicit context");
    println!("  vectors:    {}", suite.is_sample);
    println!("  executed:   {executed}");
    println!("  matched:    {matched}");
    println!("  mismatched: {}", executed - matched);
    println!("  skipped:    {skipped} (other parameter sets or interfaces)");
    for line in &mismatches {
        println!("  MISMATCH {line}");
    }

    if executed == 0 {
        return Err("no ML-DSA-65 external/pure vectors found in this file".into());
    }
    if matched != executed {
        return Err(format!("{} of {executed} vectors mismatched", executed - matched).into());
    }
    Ok(())
}

fn is_supported(group: &Group) -> bool {
    group.parameter_set == "ML-DSA-65"
        && group.signature_interface == "external"
        && group.pre_hash == "pure"
}

/// Returns the verification result, mapping any error to "did not verify"
/// because ACVP asks only whether the signature is accepted.
fn verify_case(test: &TestCase) -> Option<bool> {
    let public_key = hex::decode(&test.pk).ok()?;
    let message = hex::decode(&test.message).ok()?;
    let signature = hex::decode(&test.signature).ok()?;
    let context = hex::decode(&test.context).ok()?;
    Some(crypto::ml_dsa::verify_with_context(&public_key, &message, &signature, &context).is_ok())
}
