//! Karsa demo HTTP node.
//!
//! Exercises the pipeline from `docs/crypto-registry.md` over HTTP:
//! decode a canonical envelope, resolve the account policy, verify the
//! signatures, enforce per-sender sequence replay protection, and store the
//! result. It has no consensus, no persistence, and no peer networking.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use crypto::registry::{self, ALG_ED25519, AlgorithmKind, AlgorithmStatus};
use crypto::scheme::Ed25519Scheme;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, Authorization, KeyStatus, NO_EXPIRY};

const DEMO_CHAIN_ID: &[u8] = b"karsa-demo-1";
const DEMO_ACCOUNT: &[u8] = b"acct_alice";
const DEMO_KEY_ID: &[u8] = b"alice-1";
const DEMO_LISTEN: &str = "127.0.0.1:8099";

/// One demo account per worker, so a load generator can run several connections
/// in parallel without tripping the per-sender replay check.
const BENCHMARK_ACCOUNTS: usize = 32;

type Shared = Arc<Mutex<NodeState>>;

#[derive(Serialize)]
struct ApiError {
    code: i32,
    error: String,
}

#[derive(Serialize)]
struct HealthView {
    status: &'static str,
    protocol_version: u16,
    ed25519_backend: &'static str,
    ml_dsa_enabled: bool,
}

#[derive(Serialize)]
struct AlgorithmView {
    id: String,
    name: &'static str,
    specification: &'static str,
    kind: &'static str,
    status: &'static str,
    public_key_size: usize,
    signature_size: usize,
}

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    algorithm_id: String,
    public_key: String,
    status: &'static str,
}

#[derive(Serialize)]
struct AccountView {
    account_id: String,
    policy: &'static str,
    policy_nonce: u64,
    keys: Vec<KeyView>,
}

#[derive(Serialize)]
struct AcceptedView {
    id: String,
    used_keys: Vec<String>,
}

#[derive(Serialize)]
struct TransactionView {
    id: String,
    sender: String,
    sequence: u64,
    fee: u64,
    used_keys: Vec<String>,
}

struct StoredTransaction {
    sender: String,
    sequence: u64,
    fee: u64,
    used_keys: Vec<String>,
}

struct NodeState {
    transactions: HashMap<String, StoredTransaction>,
    order: Vec<String>,
    accounts: HashMap<String, AuthPolicy>,
    sequences: HashMap<String, u64>,
}

impl NodeState {
    fn demo() -> Self {
        let public_key = Ed25519Scheme::public_key_from_seed(&[0x42u8; 32])
            .expect("the demo seed derives a valid key");
        let policy = demo_policy(&public_key);

        let mut accounts = HashMap::new();
        accounts.insert(
            String::from_utf8_lossy(DEMO_ACCOUNT).into_owned(),
            policy.clone(),
        );
        for index in 0..BENCHMARK_ACCOUNTS {
            accounts.insert(format!("load-{index}"), policy.clone());
        }

        Self {
            transactions: HashMap::new(),
            order: Vec::new(),
            accounts,
            sequences: HashMap::new(),
        }
    }
}

fn demo_policy(public_key: &[u8; 32]) -> AuthPolicy {
    AuthPolicy {
        kind: AuthPolicyKind::Single,
        threshold: 0,
        policy_nonce: 1,
        keys: vec![AuthKey {
            key_id: DEMO_KEY_ID.to_vec(),
            algorithm_id: ALG_ED25519,
            public_key: public_key.to_vec(),
            weight: 1,
            status: KeyStatus::Active,
            valid_from: 0,
            valid_until: NO_EXPIRY,
        }],
    }
}

fn demo_private_key() -> [u8; 64] {
    let seed = [0x42u8; 32];
    let public_key =
        Ed25519Scheme::public_key_from_seed(&seed).expect("the demo seed derives a valid key");
    let mut private_key = [0u8; 64];
    private_key[..32].copy_from_slice(&seed);
    private_key[32..].copy_from_slice(&public_key);
    private_key
}

fn sample_envelope(sequence: u64) -> Result<Vec<u8>, crypto::CryptoError> {
    let private_key = demo_private_key();
    let mut transaction = Transaction {
        protocol_version: PROTOCOL_VERSION_V1,
        chain_id: DEMO_CHAIN_ID.to_vec(),
        sender: DEMO_ACCOUNT.to_vec(),
        sequence,
        fee: 1_000,
        expiration: 2_000_000_000,
        policy_version: 1,
        payload: b"transfer 10 to bob".to_vec(),
        authorization: Vec::new(),
    };
    let signature = Ed25519Scheme.sign(&private_key, &transaction.signing_payload()?)?;
    transaction.authorization.push(Authorization {
        algorithm_id: ALG_ED25519,
        key_id: DEMO_KEY_ID.to_vec(),
        signature,
    });
    transaction.encode()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn kind_name(kind: AlgorithmKind) -> &'static str {
    match kind {
        AlgorithmKind::Signature => "signature",
        AlgorithmKind::KeyEncapsulation => "key_encapsulation",
    }
}

fn status_name(status: AlgorithmStatus) -> &'static str {
    match status {
        AlgorithmStatus::Enabled => "enabled",
        AlgorithmStatus::ActivationGated => "activation_gated",
        AlgorithmStatus::Deprecated => "deprecated",
    }
}

fn policy_kind_name(kind: AuthPolicyKind) -> &'static str {
    match kind {
        AuthPolicyKind::Single => "single",
        AuthPolicyKind::All => "all",
        AuthPolicyKind::Threshold => "threshold",
    }
}

fn key_status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Active => "active",
        KeyStatus::Retired => "retired",
        KeyStatus::Revoked => "revoked",
    }
}

fn json_error(status: StatusCode, code: i32, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            code,
            error: message.into(),
        }),
    )
        .into_response()
}

async fn health() -> Json<HealthView> {
    Json(HealthView {
        status: "ok",
        protocol_version: PROTOCOL_VERSION_V1,
        ed25519_backend: "rust",
        ml_dsa_enabled: registry::ml_dsa_enabled(),
    })
}

async fn list_algorithms() -> Json<Vec<AlgorithmView>> {
    let views = registry::REGISTRY
        .iter()
        .map(|spec| AlgorithmView {
            id: format!("0x{:04x}", spec.id),
            name: spec.name,
            specification: spec.specification,
            kind: kind_name(spec.kind),
            status: status_name(spec.status),
            public_key_size: spec.public_key_size,
            signature_size: spec.signature_size,
        })
        .collect();
    Json(views)
}

async fn list_accounts(State(state): State<Shared>) -> Json<Vec<AccountView>> {
    let guard = state.lock().expect("node state lock poisoned");
    let mut ids: Vec<&String> = guard.accounts.keys().collect();
    ids.sort();
    let views = ids
        .into_iter()
        .map(|id| {
            let policy = &guard.accounts[id];
            AccountView {
                account_id: id.clone(),
                policy: policy_kind_name(policy.kind),
                policy_nonce: policy.policy_nonce,
                keys: policy
                    .keys
                    .iter()
                    .map(|key| KeyView {
                        key_id: String::from_utf8_lossy(&key.key_id).into_owned(),
                        algorithm_id: format!("0x{:04x}", key.algorithm_id),
                        public_key: hex::encode(&key.public_key),
                        status: key_status_name(key.status),
                    })
                    .collect(),
            }
        })
        .collect();
    Json(views)
}

async fn list_transactions(State(state): State<Shared>) -> Json<Vec<String>> {
    let guard = state.lock().expect("node state lock poisoned");
    Json(guard.order.clone())
}

async fn get_transaction(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    let guard = state.lock().expect("node state lock poisoned");
    match guard.transactions.get(&id) {
        Some(stored) => Json(TransactionView {
            id,
            sender: stored.sender.clone(),
            sequence: stored.sequence,
            fee: stored.fee,
            used_keys: stored.used_keys.clone(),
        })
        .into_response(),
        None => json_error(StatusCode::NOT_FOUND, -1, "unknown transaction"),
    }
}

async fn post_transaction(State(state): State<Shared>, body: String) -> Response {
    let body = body.trim();
    if body.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            -1,
            "body must be a hex-encoded transaction envelope",
        );
    }
    let envelope = match hex::decode(body) {
        Ok(envelope) => envelope,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, -1, format!("invalid hex: {error}"));
        }
    };
    let transaction = match Transaction::decode(&envelope) {
        Ok(transaction) => transaction,
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                i32::from(error.code()),
                error.to_string(),
            );
        }
    };
    if transaction.protocol_version != PROTOCOL_VERSION_V1 {
        return json_error(
            StatusCode::BAD_REQUEST,
            -1,
            format!(
                "unsupported protocol version {}",
                transaction.protocol_version
            ),
        );
    }

    let sender = String::from_utf8_lossy(&transaction.sender).into_owned();
    let policy = {
        let guard = state.lock().expect("node state lock poisoned");
        match guard.accounts.get(&sender) {
            Some(policy) => policy.clone(),
            None => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    -1,
                    format!("unknown account: {sender}"),
                );
            }
        }
    };

    let used = match transaction.verify(&policy, now()) {
        Ok(used) => used,
        Err(error) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                i32::from(error.code()),
                error.to_string(),
            );
        }
    };
    let id = hex::encode(Sha256::digest(&envelope));
    let used_keys: Vec<String> = used
        .iter()
        .map(|key| String::from_utf8_lossy(key).into_owned())
        .collect();

    {
        let mut guard = state.lock().expect("node state lock poisoned");
        let previous = guard.sequences.get(&sender).copied().unwrap_or(0);
        if transaction.sequence <= previous {
            return json_error(
                StatusCode::CONFLICT,
                -1,
                format!(
                    "replay: sequence {} is not greater than the last accepted {previous}",
                    transaction.sequence
                ),
            );
        }
        guard.sequences.insert(sender.clone(), transaction.sequence);
        guard.transactions.insert(
            id.clone(),
            StoredTransaction {
                sender,
                sequence: transaction.sequence,
                fee: transaction.fee,
                used_keys: used_keys.clone(),
            },
        );
        guard.order.push(id.clone());
    }

    (StatusCode::ACCEPTED, Json(AcceptedView { id, used_keys })).into_response()
}

fn build_router(state: Shared) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/registry", get(list_algorithms))
        .route("/accounts", get(list_accounts))
        .route("/tx", get(list_transactions).post(post_transaction))
        .route("/tx/{id}", get(get_transaction))
        .with_state(state)
}

/// Runs the HTTP node until the process is stopped.
///
/// # Errors
///
/// Returns an error when the listener cannot bind or the server fails.
pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let state: Shared = Arc::new(Mutex::new(NodeState::demo()));
    let app = build_router(state);
    println!("karsa demo node (rust)");
    println!("  listen:         http://{DEMO_LISTEN}");
    println!("  ml-dsa enabled: {}", registry::ml_dsa_enabled());
    println!("  accounts:       {} demo accounts", BENCHMARK_ACCOUNTS + 1);
    println!("  sample tx:      karsa sample-tx");

    let listener = tokio::net::TcpListener::bind(DEMO_LISTEN).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Prints one signed demo envelope as hex on stdout.
///
/// # Errors
///
/// Returns an error if the demo envelope cannot be built.
pub fn print_sample_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = sample_envelope(1)?;
    println!("{}", hex::encode(&envelope));
    eprintln!("{} bytes", envelope.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_app() -> Router {
        build_router(Arc::new(Mutex::new(NodeState::demo())))
    }

    async fn get(app: Router, uri: &str) -> (StatusCode, String) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn post(app: Router, uri: &str, body: String) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "text/plain")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn health_endpoint() {
        let (status, body) = get(test_app(), "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"status\":\"ok\""), "{body}");
    }

    #[tokio::test]
    async fn registry_lists_every_algorithm() {
        let (status, body) = get(test_app(), "/registry").await;
        assert_eq!(status, StatusCode::OK);
        for name in ["Ed25519", "ML-DSA-65", "SLH-DSA-SHA2-128s", "ML-KEM-768"] {
            assert!(body.contains(name), "{name} missing from {body}");
        }
    }

    #[tokio::test]
    async fn accounts_expose_the_policy() {
        let (status, body) = get(test_app(), "/accounts").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("acct_alice"), "{body}");
        assert!(body.contains("\"policy\":\"single\""), "{body}");
    }

    #[tokio::test]
    async fn post_accepts_a_signed_transaction() {
        let body = hex::encode(sample_envelope(1).unwrap());
        let (status, response) = post(test_app(), "/tx", body).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        assert!(
            response.contains("\"used_keys\":[\"alice-1\"]"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn replay_is_rejected() {
        let app = test_app();
        let body = hex::encode(sample_envelope(1).unwrap());
        let (first, _) = post(app.clone(), "/tx", body.clone()).await;
        assert_eq!(first, StatusCode::ACCEPTED);

        let (second, response) = post(app, "/tx", body).await;
        assert_eq!(second, StatusCode::CONFLICT, "{response}");
        assert!(response.contains("replay"), "{response}");
    }

    #[tokio::test]
    async fn increasing_sequences_are_accepted() {
        let app = test_app();
        for sequence in [1u64, 2, 3] {
            let body = hex::encode(sample_envelope(sequence).unwrap());
            let (status, response) = post(app.clone(), "/tx", body).await;
            assert_eq!(
                status,
                StatusCode::ACCEPTED,
                "sequence {sequence}: {response}"
            );
        }
    }

    #[tokio::test]
    async fn tampered_sequence_is_rejected() {
        let envelope = sample_envelope(1).unwrap();
        let mut transaction = Transaction::decode(&envelope).unwrap();
        transaction.sequence = 2;
        let body = hex::encode(transaction.encode().unwrap());

        let (status, response) = post(test_app(), "/tx", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert!(response.contains("invalid_signature"), "{response}");
    }

    #[tokio::test]
    async fn unknown_account_is_rejected() {
        let envelope = sample_envelope(1).unwrap();
        let mut transaction = Transaction::decode(&envelope).unwrap();
        transaction.sender = b"acct_mallory".to_vec();
        let body = hex::encode(transaction.encode().unwrap());

        let (status, response) = post(test_app(), "/tx", body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
        assert!(response.contains("unknown account"), "{response}");
    }

    #[tokio::test]
    async fn malformed_hex_is_rejected() {
        let (status, response) = post(test_app(), "/tx", "not-hex".to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(response.contains("invalid hex"), "{response}");
    }

    #[tokio::test]
    async fn unknown_transaction_is_404() {
        let (status, _) = get(test_app(), "/tx/deadbeef").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
