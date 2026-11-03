//! Karsa demo HTTP node.
//!
//! Exercises the pipeline from `docs/crypto-registry.md` over HTTP:
//! decode a canonical envelope, resolve the account policy, verify the
//! signatures, enforce per-sender sequence replay protection, and store the
//! result. It also carries the epoch-bound validator key schedule from
//! `crates/validator`, so a key rotation can be registered, authorized, and
//! observed at an epoch boundary. It has no consensus, no persistence, and no
//! peer networking.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use crypto::domain::{KeyRegistrationSigningFields, encode_key_registration_payload};
use crypto::registry::{self, ALG_ED25519, AlgorithmKind, AlgorithmStatus};
use crypto::scheme::Ed25519Scheme;
use crypto::{CryptoError, CryptoErrorKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, Authorization, KeyStatus, NO_EXPIRY};
use validator::{
    NO_EXPIRY as NO_EPOCH_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, ValidatorSignature,
};

const DEMO_CHAIN_ID: &[u8] = b"karsa-demo-1";
const DEMO_ACCOUNT: &[u8] = b"acct_alice";
const DEMO_KEY_ID: &[u8] = b"alice-1";
pub const DEMO_LISTEN: &str = "127.0.0.1:8099";

/// The single genesis validator and its first consensus key.
const DEMO_VALIDATOR: &[u8] = b"val-1";
const GENESIS_VALIDATOR_KEY_ID: &[u8] = b"val-1-genesis";
const GENESIS_VALIDATOR_SEED: [u8; 32] = [0x11; 32];
/// Seed of the second key, used by `karsa register-demo` to show a rotation.
const ROTATION_VALIDATOR_KEY_ID: &[u8] = b"val-1-next";
const ROTATION_VALIDATOR_SEED: [u8; 32] = [0x22; 32];

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
    slh_dsa_enabled: bool,
    epoch: u64,
    validators: usize,
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

#[derive(Serialize)]
struct ValidatorKeyView {
    key_id: String,
    algorithm_id: String,
    public_key: String,
    activation_epoch: u64,
    retirement_epoch: u64,
    status: &'static str,
}

#[derive(Serialize)]
struct ValidatorView {
    validator_id: String,
    keys: Vec<ValidatorKeyView>,
}

#[derive(Serialize)]
struct ValidatorSetView {
    epoch: u64,
    supermajority: usize,
    validators: Vec<ValidatorView>,
}

#[derive(Deserialize, Serialize)]
struct RegisterKeyRequest {
    key_id: String,
    algorithm_id: String,
    public_key: String,
    activation_epoch: u64,
    #[serde(default = "no_epoch_expiry")]
    retirement_epoch: u64,
    signed_at_epoch: u64,
    authorizer_key_id: String,
    /// Retire the authorizing key at the new key's activation epoch, which is
    /// what makes a scheduled rotation contiguous instead of overlapping.
    #[serde(default)]
    retire_authorizer: bool,
    signature: String,
}

#[derive(Deserialize)]
struct AdvanceEpochRequest {
    epoch: u64,
}

fn no_epoch_expiry() -> u64 {
    NO_EPOCH_EXPIRY
}

struct NodeState {
    transactions: HashMap<String, StoredTransaction>,
    order: Vec<String>,
    accounts: HashMap<String, AuthPolicy>,
    sequences: HashMap<String, u64>,
    validators: ValidatorSet,
    epoch: u64,
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
            validators: genesis_validator_set().expect("the genesis validator set is well formed"),
            epoch: 0,
        }
    }
}

/// Builds the genesis set: one validator with one Ed25519 key from epoch 0.
fn genesis_validator_set() -> Result<ValidatorSet, CryptoError> {
    let public_key = Ed25519Scheme::public_key_from_seed(&GENESIS_VALIDATOR_SEED)?;
    let set = ValidatorSet {
        epoch: 0,
        validators: vec![ValidatorRecord {
            validator_id: DEMO_VALIDATOR.to_vec(),
            keys: vec![ValidatorKey {
                key_id: GENESIS_VALIDATOR_KEY_ID.to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: public_key.to_vec(),
                activation_epoch: 0,
                retirement_epoch: NO_EPOCH_EXPIRY,
            }],
        }],
    };
    set.validate()?;
    Ok(set)
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
    private_key_for(&[0x42u8; 32]).expect("the demo seed derives a valid key")
}

/// Builds the `seed ‖ public_key` private key encoding for an Ed25519 seed.
fn private_key_for(seed: &[u8; 32]) -> Result<[u8; 64], crypto::CryptoError> {
    let public_key = Ed25519Scheme::public_key_from_seed(seed)?;
    let mut private_key = [0u8; 64];
    private_key[..32].copy_from_slice(seed);
    private_key[32..].copy_from_slice(&public_key);
    Ok(private_key)
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

async fn health(State(state): State<Shared>) -> Json<HealthView> {
    let guard = state.lock().expect("node state lock poisoned");
    Json(HealthView {
        status: "ok",
        protocol_version: PROTOCOL_VERSION_V1,
        ed25519_backend: "rust",
        ml_dsa_enabled: registry::ml_dsa_enabled(),
        slh_dsa_enabled: registry::slh_dsa_enabled(),
        epoch: guard.epoch,
        validators: guard.validators.validators.len(),
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

fn supermajority_threshold(validators: usize) -> usize {
    validators * 2 / 3 + 1
}

fn key_epoch_status(key: &ValidatorKey, epoch: u64) -> &'static str {
    if key.is_active(epoch) {
        "active"
    } else if epoch < key.activation_epoch {
        "not_yet_active"
    } else {
        "retired"
    }
}

fn validator_set_view(set: &ValidatorSet, epoch: u64) -> ValidatorSetView {
    ValidatorSetView {
        epoch,
        supermajority: supermajority_threshold(set.validators.len()),
        validators: set
            .validators
            .iter()
            .map(|record| ValidatorView {
                validator_id: String::from_utf8_lossy(&record.validator_id).into_owned(),
                keys: record
                    .keys
                    .iter()
                    .map(|key| ValidatorKeyView {
                        key_id: String::from_utf8_lossy(&key.key_id).into_owned(),
                        algorithm_id: format!("0x{:04x}", key.algorithm_id),
                        public_key: hex::encode(&key.public_key),
                        activation_epoch: key.activation_epoch,
                        retirement_epoch: key.retirement_epoch,
                        status: key_epoch_status(key, epoch),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Returns the epoch-bound validator set as the node currently sees it.
async fn list_validators(State(state): State<Shared>) -> Json<ValidatorSetView> {
    let guard = state.lock().expect("node state lock poisoned");
    Json(validator_set_view(&guard.validators, guard.epoch))
}

/// Answers a protocol rejection with the frozen error code from
/// `docs/crypto-registry.md` §7, the same way the transaction path does.
fn crypto_reject(error: &CryptoError) -> Response {
    json_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        i32::from(error.code()),
        error.to_string(),
    )
}

fn parse_algorithm_id(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(digits, 16).ok()
}

/// Registers a validator consensus key inside an epoch window.
///
/// A registration is authorized by a key the validator already holds: the node
/// rebuilds the canonical registration payload and verifies the submitted
/// signature with that existing key at the epoch the signature claims. This is
/// the property a production chain needs — knowing a validator id must never be
/// enough to enroll a key under it.
async fn post_validator_key(
    State(state): State<Shared>,
    Path(validator_id): Path<String>,
    Json(request): Json<RegisterKeyRequest>,
) -> Response {
    let validator_id = validator_id.into_bytes();
    if request.key_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, -1, "key_id must not be empty");
    }
    let Some(algorithm_id) = parse_algorithm_id(&request.algorithm_id) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            -1,
            format!("invalid algorithm id: {}", request.algorithm_id),
        );
    };
    let public_key = match hex::decode(&request.public_key) {
        Ok(public_key) => public_key,
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                -1,
                format!("invalid public_key hex: {error}"),
            );
        }
    };
    let signature = match hex::decode(&request.signature) {
        Ok(signature) => signature,
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                -1,
                format!("invalid signature hex: {error}"),
            );
        }
    };

    // Only an algorithm this build can verify may be enrolled. This is the same
    // gate the transaction path uses, so a gated PQ key is refused here rather
    // than failing verification later.
    let spec = match registry::require_signature_algorithm(algorithm_id) {
        Ok(spec) => spec,
        Err(error) => return crypto_reject(&error),
    };
    if public_key.len() != spec.public_key_size {
        return crypto_reject(&CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            format!(
                "{}: want {} bytes, got {}",
                spec.name,
                spec.public_key_size,
                public_key.len()
            ),
        ));
    }

    let payload = match encode_key_registration_payload(&KeyRegistrationSigningFields {
        chain_id: DEMO_CHAIN_ID,
        validator_id: &validator_id,
        key_id: request.key_id.as_bytes(),
        algorithm_id,
        public_key: &public_key,
        activation_epoch: request.activation_epoch,
        retirement_epoch: request.retirement_epoch,
        signed_at_epoch: request.signed_at_epoch,
    }) {
        Ok(payload) => payload,
        Err(error) => return crypto_reject(&error),
    };

    let mut guard = state.lock().expect("node state lock poisoned");
    let current = match guard.validators.validator(&validator_id) {
        Some(record) => record.clone(),
        None => {
            return json_error(
                StatusCode::NOT_FOUND,
                -1,
                format!(
                    "unknown validator: {}",
                    String::from_utf8_lossy(&validator_id)
                ),
            );
        }
    };
    if request.signed_at_epoch > guard.epoch {
        return crypto_reject(&CryptoError::new(
            CryptoErrorKind::KeyOutOfWindow,
            format!(
                "authorization claims epoch {} but the node is at {}",
                request.signed_at_epoch, guard.epoch
            ),
        ));
    }

    let authorizer = ValidatorSignature {
        validator_id: validator_id.clone(),
        key_id: request.authorizer_key_id.as_bytes().to_vec(),
        signature,
    };
    if let Err(error) = guard.validators.verify_signatures(
        &payload,
        request.signed_at_epoch,
        std::slice::from_ref(&authorizer),
    ) {
        return crypto_reject(&error);
    }

    let new_key = ValidatorKey {
        key_id: request.key_id.as_bytes().to_vec(),
        algorithm_id,
        public_key,
        activation_epoch: request.activation_epoch,
        retirement_epoch: request.retirement_epoch,
    };

    // Validate the schedule the node would end up with before committing it: an
    // overlapping or inverted interval is a registration error now, not an
    // ambiguity discovered when a vote is verified later.
    let mut keys = current.keys;
    if request.retire_authorizer {
        let authorizer_key_id = request.authorizer_key_id.as_bytes();
        let Some(existing) = keys.iter_mut().find(|key| key.key_id == authorizer_key_id) else {
            return crypto_reject(&CryptoError::new(
                CryptoErrorKind::UnknownKey,
                "authorizing key is not registered on this validator",
            ));
        };
        existing.retirement_epoch = request.activation_epoch;
    }
    keys.push(new_key.clone());
    let candidate = ValidatorRecord {
        validator_id: validator_id.clone(),
        keys,
    };
    if let Err(error) = candidate.validate_schedule() {
        return crypto_reject(&error);
    }

    if let Some(record) = guard
        .validators
        .validators
        .iter_mut()
        .find(|record| record.validator_id == validator_id)
    {
        record.keys = candidate.keys;
    }
    let epoch = guard.epoch;

    let view = ValidatorKeyView {
        key_id: String::from_utf8_lossy(&new_key.key_id).into_owned(),
        algorithm_id: format!("0x{:04x}", new_key.algorithm_id),
        public_key: hex::encode(&new_key.public_key),
        activation_epoch: new_key.activation_epoch,
        retirement_epoch: new_key.retirement_epoch,
        status: key_epoch_status(&new_key, epoch),
    };
    (StatusCode::CREATED, Json(view)).into_response()
}

/// Advances the demo epoch clock.
///
/// A production chain derives the epoch from consensus time. The demo node has
/// no consensus, so the epoch is explicit and monotonic: it can only move
/// forward, and it refuses a target epoch that would leave a validator without
/// an active key.
async fn post_epoch(
    State(state): State<Shared>,
    Json(request): Json<AdvanceEpochRequest>,
) -> Response {
    let mut guard = state.lock().expect("node state lock poisoned");
    if request.epoch <= guard.epoch {
        return json_error(
            StatusCode::CONFLICT,
            -1,
            format!(
                "epoch must advance: {} is not greater than {}",
                request.epoch, guard.epoch
            ),
        );
    }
    for record in &guard.validators.validators {
        if let Err(error) = record.active_key(request.epoch) {
            return crypto_reject(&error);
        }
    }
    guard.epoch = request.epoch;
    guard.validators.epoch = request.epoch;
    Json(validator_set_view(&guard.validators, guard.epoch)).into_response()
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
        .route("/validators", get(list_validators))
        .route("/validators/{id}/keys", post(post_validator_key))
        .route("/epoch", post(post_epoch))
        .route("/accounts", get(list_accounts))
        .route("/tx", get(list_transactions).post(post_transaction))
        .route("/tx/{id}", get(get_transaction))
        .with_state(state)
}

/// Runs the HTTP node until the process is stopped.
///
/// # Errors
///
/// Returns an error when the listen address is not valid, the listener cannot
/// bind, or the server fails.
pub async fn serve(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state: Shared = Arc::new(Mutex::new(NodeState::demo()));
    let app = build_router(state);
    println!("karsa demo node (rust)");
    println!("  listen:         http://{listen}");
    println!("  ml-dsa enabled: {}", registry::ml_dsa_enabled());
    println!("  slh-dsa enabled: {}", registry::slh_dsa_enabled());
    println!("  validators:     1 at epoch 0");
    println!("  accounts:       {} demo accounts", BENCHMARK_ACCOUNTS + 1);
    println!("  sample tx:      karsa sample-tx");
    println!("  rotate a key:   karsa register-demo 1  # prints the signed body");

    let listener = tokio::net::TcpListener::bind(listen).await?;
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

/// Prints the JSON body that registers a second consensus key for the genesis
/// validator, signed by the key that is active today.
///
/// It is the same payload the node rebuilds and verifies, so the body can be
/// posted unchanged with `curl -d @- http://127.0.0.1:8099/validators/val-1/keys`.
///
/// # Errors
///
/// Returns an error if the payload cannot be encoded or signed.
pub fn print_demo_registration(activation_epoch: u64) -> Result<(), Box<dyn std::error::Error>> {
    let authorizer = private_key_for(&GENESIS_VALIDATOR_SEED)?;
    let new_public_key = Ed25519Scheme::public_key_from_seed(&ROTATION_VALIDATOR_SEED)?;
    let payload = encode_key_registration_payload(&KeyRegistrationSigningFields {
        chain_id: DEMO_CHAIN_ID,
        validator_id: DEMO_VALIDATOR,
        key_id: ROTATION_VALIDATOR_KEY_ID,
        algorithm_id: ALG_ED25519,
        public_key: &new_public_key,
        activation_epoch,
        retirement_epoch: NO_EPOCH_EXPIRY,
        signed_at_epoch: 0,
    })?;
    let signature = Ed25519Scheme.sign(&authorizer, &payload)?;

    let request = RegisterKeyRequest {
        key_id: String::from_utf8_lossy(ROTATION_VALIDATOR_KEY_ID).into_owned(),
        algorithm_id: format!("0x{ALG_ED25519:04x}"),
        public_key: hex::encode(new_public_key),
        activation_epoch,
        retirement_epoch: NO_EPOCH_EXPIRY,
        signed_at_epoch: 0,
        authorizer_key_id: String::from_utf8_lossy(GENESIS_VALIDATOR_KEY_ID).into_owned(),
        retire_authorizer: true,
        signature: hex::encode(signature),
    };
    println!("{}", serde_json::to_string_pretty(&request)?);
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

    async fn get_shared(app: &Router, uri: &str) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn post_json(app: &Router, uri: &str, body: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Builds a registration request signed by the genesis validator key.
    fn registration(
        activation_epoch: u64,
        authorizer_key_id: &str,
        retire_authorizer: bool,
    ) -> RegisterKeyRequest {
        let authorizer = private_key_for(&GENESIS_VALIDATOR_SEED).unwrap();
        let new_public_key = Ed25519Scheme::public_key_from_seed(&ROTATION_VALIDATOR_SEED).unwrap();
        let key_id = String::from_utf8_lossy(ROTATION_VALIDATOR_KEY_ID).into_owned();
        let payload = encode_key_registration_payload(&KeyRegistrationSigningFields {
            chain_id: DEMO_CHAIN_ID,
            validator_id: DEMO_VALIDATOR,
            key_id: key_id.as_bytes(),
            algorithm_id: ALG_ED25519,
            public_key: &new_public_key,
            activation_epoch,
            retirement_epoch: NO_EPOCH_EXPIRY,
            signed_at_epoch: 0,
        })
        .unwrap();
        let signature = Ed25519Scheme.sign(&authorizer, &payload).unwrap();
        RegisterKeyRequest {
            key_id,
            algorithm_id: format!("0x{ALG_ED25519:04x}"),
            public_key: hex::encode(new_public_key),
            activation_epoch,
            retirement_epoch: NO_EPOCH_EXPIRY,
            signed_at_epoch: 0,
            authorizer_key_id: authorizer_key_id.to_string(),
            retire_authorizer,
            signature: hex::encode(signature),
        }
    }

    fn body_of(request: &RegisterKeyRequest) -> String {
        serde_json::to_string(request).unwrap()
    }

    #[tokio::test]
    async fn validators_show_the_genesis_key() {
        let (status, body) = get(test_app(), "/validators").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"validator_id\":\"val-1\""), "{body}");
        assert!(body.contains("\"key_id\":\"val-1-genesis\""), "{body}");
        assert!(body.contains("\"status\":\"active\""), "{body}");
        assert!(body.contains("\"supermajority\":1"), "{body}");
    }

    #[tokio::test]
    async fn registration_is_rejected_without_a_valid_authorizer() {
        let mut request = registration(1, "val-1-genesis", true);
        request.signature = hex::encode([0u8; 64]);

        let (status, body) =
            post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // invalid_signature
        assert!(body.contains("\"code\":6"), "{body}");
    }

    #[tokio::test]
    async fn registration_by_an_unregistered_key_is_rejected() {
        let request = registration(1, "val-1-nope", true);
        let (status, body) =
            post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // unknown_key
        assert!(body.contains("\"code\":7"), "{body}");
    }

    #[tokio::test]
    async fn registration_for_an_unknown_validator_is_404() {
        let request = registration(1, "val-1-genesis", true);
        let (status, body) =
            post_json(&test_app(), "/validators/val-9/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    #[tokio::test]
    async fn overlapping_registration_is_rejected() {
        // Without retiring the authorizing key the intervals overlap, which is the
        // ambiguity the schedule rules exist to prevent.
        let request = registration(1, "val-1-genesis", false);
        let (status, body) =
            post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // invalid_key_schedule
        assert!(body.contains("\"code\":21"), "{body}");
    }

    #[tokio::test]
    async fn rotation_switches_the_active_key_at_the_epoch() {
        let app = test_app();
        let request = registration(1, "val-1-genesis", true);
        let (status, body) = post_json(&app, "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert!(body.contains("\"status\":\"not_yet_active\""), "{body}");

        let (_, before) = get_shared(&app, "/validators").await;
        assert!(
            before.contains("\"key_id\":\"val-1-next\",\"algorithm_id\":\"0x0001\""),
            "{before}"
        );
        assert!(before.contains("\"status\":\"active\""), "{before}");

        let (status, after) = post_json(&app, "/epoch", r#"{"epoch":1}"#).await;
        assert_eq!(status, StatusCode::OK, "{after}");
        // The genesis key is retired at its published epoch and the scheduled key
        // takes over; the record never has two active keys.
        assert!(after.contains("\"key_id\":\"val-1-genesis\""), "{after}");
        assert!(after.contains("\"status\":\"retired\""), "{after}");
        assert!(after.contains("\"status\":\"active\""), "{after}");
        assert!(after.contains("\"epoch\":1"), "{after}");
    }

    #[tokio::test]
    async fn epoch_cannot_move_backwards() {
        let (status, body) = post_json(&test_app(), "/epoch", r#"{"epoch":0}"#).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }

    #[tokio::test]
    async fn epoch_refuses_to_strand_a_validator() {
        let mut state = NodeState::demo();
        state.validators.validators[0].keys[0].retirement_epoch = 1;
        let app = build_router(Arc::new(Mutex::new(state)));

        let (status, body) = post_json(&app, "/epoch", r#"{"epoch":2}"#).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // key_not_active
        assert!(body.contains("\"code\":8"), "{body}");
    }

    #[tokio::test]
    async fn gated_or_non_signature_algorithms_are_not_registrable() {
        // ML-KEM-768 is a key-encapsulation algorithm, never a validator key.
        let mut request = registration(1, "val-1-genesis", true);
        request.algorithm_id = "0x0201".to_string();
        let (status, body) =
            post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // unsupported_algorithm
        assert!(body.contains("\"code\":1"), "{body}");

        if !registry::ml_dsa_enabled() {
            // A compiled-but-gated algorithm is refused before any signing happens.
            let mut request = registration(1, "val-1-genesis", true);
            request.algorithm_id = "0x0101".to_string();
            let (status, body) =
                post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            // algorithm_not_enabled
            assert!(body.contains("\"code\":2"), "{body}");
        }
    }

    #[tokio::test]
    async fn registration_in_the_future_epoch_is_rejected() {
        let mut request = registration(1, "val-1-genesis", true);
        request.signed_at_epoch = 5;
        let (status, body) =
            post_json(&test_app(), "/validators/val-1/keys", &body_of(&request)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // key_out_of_window
        assert!(body.contains("\"code\":9"), "{body}");
    }
}
