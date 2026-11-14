//! Append-only on-disk state for a validator node.
//!
//! A node that forgets everything on restart is a demo, not a node. This crate
//! persists the three things a validator cannot recompute on its own — the
//! vertices it received, the batches those vertices name, and the roots it last
//! reported — and nothing else. Everything derived is replayed on open, so a
//! restart is a replay that either reproduces the same roots or reports a
//! disagreement rather than silently serving a different chain.
//!
//! # Crash safety
//!
//! Each log is a sequence of `u32 len || payload` records. On open, a record that
//! is *incomplete* — fewer than four bytes for a length, or fewer bytes than the
//! length claims — is treated as a torn tail and ignored, because that is exactly
//! what a crash during an append leaves behind. A record that is complete but does
//! not decode is a different thing: that is corruption, and it is an error. The
//! two cases are deliberately not conflated.
//!
//! Slot-decision intents are the exception: their root-level journal is synced
//! on every successful reservation and rejects even incomplete tails.
//!
//! The inactive slot-application WAL likewise rejects torn records and syncs before
//! in-memory application. It follows the active generation and does not replace
//! authenticated checkpoint restoration or persist transaction/finalizer effects.
//!
//! Other logs do not fsync on every append: durability of the last record is the
//! caller's tradeoff, and `Store::sync` exists for callers that want it.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

mod slot_agreement_journal;
#[cfg(test)]
mod slot_agreement_signing_tests;
#[cfg(test)]
mod slot_agreement_tests;
mod slot_application_journal;
#[cfg(test)]
mod slot_application_tests;
mod slot_decision_journal;

pub use slot_agreement_journal::{DurableSlotAgreement, SlotAgreementBootstrap};
pub use slot_application_journal::{StoredSlotApplication, StoredSlotApplicationRequest};

use crypto::CryptoError;
use crypto::encoding::{Decoder, Encoder};
use tx::batch::Batch;
use validator::{
    Certificate, CommitFrontier, FenceCertificate, Header, RoundSkipProof, TransitionCertificate,
    Vertex, VertexId,
};

/// Where the last reported roots are kept.
const ROOTS_FILE: &str = "roots";
/// The vertex log.
const VERTICES_FILE: &str = "vertices.log";
/// The batch log.
const BATCHES_FILE: &str = "batches.log";
/// The state snapshot.
const SNAPSHOT_FILE: &str = "snapshot";
/// The erasure-coded shard log.
const SHARDS_FILE: &str = "shards.log";
/// The one authorized set change this store has seen.
const SET_CHANGE_FILE: &str = "set-change";
/// The fences this store has adopted.
const FENCES_FILE: &str = "fences";
/// Round-skip proofs this store has adopted, one per leader round.
const ROUND_SKIPS_FILE: &str = "round-skips";
/// Fence shares this node signed but has not completed into a certificate.
const FENCE_SHARES_FILE: &str = "fence-shares";
/// Version of one local fence-share record.
///
/// The log carries both a signed share and a tombstone, so clearing a stale
/// proposal survives a restart instead of resurrecting a promise the node no
/// longer stands behind.
const FENCE_SHARES_VERSION: u16 = 1;
const FENCE_SHARE_SIGNED: u8 = 0;
const FENCE_SHARE_CLEARED: u8 = 1;
/// The legacy single-fence file, still read for an older store.
const FENCE_FILE: &str = "fence";
/// The chain this directory belongs to.
const GENESIS_FILE: &str = "genesis";
const GENESIS_HEADER_FILE: &str = "genesis.header";
const GENESIS_STATE_FILE: &str = "genesis.state";
/// The certified header log.
const HEADERS_FILE: &str = "headers.log";
/// Rounds seen at a wall-clock time, for age-based retention.
///
/// A vertex carries no timestamp: adding one would change every record's shape for
/// a fact the node can observe once per second instead. This file is that
/// observation, kept small by trimming it to the retention window on every prune.
const CLOCK_FILE: &str = "clock";
/// Version of the roots record.
const ROOTS_VERSION: u16 = 1;

/// A failure reading or writing the store.
#[derive(Debug)]
pub enum StoreError {
    /// The filesystem refused an operation.
    Io(std::io::Error),
    /// A complete record did not decode.
    Decode(CryptoError),
    /// The directory belongs to a different chain than the one being run.
    ChainMismatch {
        /// Chain the store was written under.
        stored: [u8; 32],
        /// Chain the caller is running.
        expected: [u8; 32],
    },
}

/// First bytes of a hash, for a message a person reads.
fn short(hash: &[u8; 32]) -> String {
    hash[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "store io: {error}"),
            Self::Decode(error) => write!(f, "store decode: {error}"),
            Self::ChainMismatch { stored, expected } => write!(
                f,
                "store belongs to chain {}, not {}",
                short(stored),
                short(expected)
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::ChainMismatch { .. } => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for StoreError {
    fn from(error: CryptoError) -> Self {
        Self::Decode(error)
    }
}

/// The two roots a node last reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roots {
    /// Merkle root over the committed sequence.
    pub commit_root: [u8; 32],
    /// Merkle root over the account state.
    pub state_root: [u8; 32],
}

/// An execution-state snapshot taken at a prune point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Highest round covered by the snapshot. Everything at or below it is gone.
    pub round: u64,
    /// The encoded state, opaque to this crate.
    pub state: Vec<u8>,
}

/// The live snapshot a node adopted when it joined from a peer.
///
/// Unlike [`Snapshot`], this carries everything needed to resume consensus: the
/// certified anchor, the committed order prefix, the decision cursor, and the
/// DAG floor. It is written once after a snapshot join and read before a replay.
///
/// The committed order is split: `prefix` summarizes the leaves at or below the
/// DAG floor, whose vertices are gone, and `order` holds the tail above it.
/// `order_len` is the total, so a header's `dag_root` can be rebuilt without the
/// dropped leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSnapshot {
    /// Round of the certified anchor.
    pub round: u64,
    /// Rounds at or below this are covered by `state`.
    pub floor: Option<u64>,
    /// Decision round the node resumes from.
    pub cursor: u64,
    /// Transactions applied at the anchor.
    pub applied: u64,
    /// Encoded execution state at the anchor.
    pub state: Vec<u8>,
    /// Committed order tail above the compact prefix.
    pub order: Vec<VertexId>,
    /// Total committed entries the anchor covers.
    pub order_len: usize,
    /// Peaks of the committed order at or below the floor.
    pub prefix: CommitFrontier,
    /// The certified header the state belongs to.
    pub header: Header,
    /// Quorum certificate over `header`.
    pub certificate: Certificate,
    /// The authorized set change that applies above this snapshot, if any.
    pub transition: Option<TransitionCertificate>,
    /// Quorum fences the snapshot sender adopted, including below its floor.
    pub fences: Vec<FenceCertificate>,
}

/// What one pruning pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Vertices removed from the log.
    pub vertices: usize,
    /// Certified headers removed from the log.
    pub headers: usize,
    /// Batches whose payload was removed.
    pub batches_dropped: usize,
    /// Batches whose payload was kept because no shard backs it.
    pub batches_held: usize,
    /// Bytes the two logs shrank by.
    pub bytes_freed: u64,
    /// Bytes still above the disk cap after pruning, when the cap could not be met.
    ///
    /// Non-zero means the store legitimately cannot shrink further: shards and
    /// headers are kept forever, and a payload no shard backs is never dropped.
    pub cap_shortfall: u64,
}

/// How much history a pruning node keeps: a time window and a disk cap, whichever
/// ends first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Days of history. Zero means no time bound.
    pub days: u32,
    /// Cap on the whole store directory in bytes. Zero means no size bound.
    pub max_bytes: u64,
}

impl Retention {
    /// Reads the policy as `node.toml` states it: days, and gigabytes (decimal).
    #[must_use]
    pub fn from_days_and_gb(days: u32, max_gb: u32) -> Self {
        Self {
            days,
            max_bytes: u64::from(max_gb) * 1_000_000_000,
        }
    }

    /// A policy that would delete nothing.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            days: 0,
            max_bytes: 0,
        }
    }
}

/// What a retention policy decided, before anything was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Highest round the age window alone would drop.
    pub age_cutoff: Option<u64>,
    /// Highest round the disk cap alone would drop.
    pub size_cutoff: Option<u64>,
    /// Highest round that will actually be dropped.
    ///
    /// The two windows end at different rounds, and "whichever comes first" is the
    /// one that leaves less history, so this is the larger cutoff. It is clamped to
    /// [`RetentionPlan::snapshot_round`], and is `None` when there is no snapshot to
    /// replay from.
    pub cutoff: Option<u64>,
    /// Round covered by the newest snapshot, the floor pruning may not cross.
    pub snapshot_round: Option<u64>,
    /// Bytes the store occupies now.
    pub disk_bytes: u64,
    /// The cap that was applied, if any.
    pub max_bytes: u64,
}

/// One erasure-coded shard this node holds for a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredShard {
    /// Digest of the batch the shard belongs to.
    pub digest: [u8; 32],
    /// Which of the `total` shards this is.
    pub index: u16,
    /// Shard bytes.
    pub bytes: Vec<u8>,
}

/// The certified snapshot a node joined from, kept so a restart resumes from it
/// instead of replaying a history it never had.
const LIVE_SNAPSHOT_FILE: &str = "live.snapshot";
/// Version of the live snapshot record.
///
/// Version 4 adds the quorum fences. Version 3 added the optional set-change
/// certificate. Version 2 stored the compact prefix and tail; version 1 stored
/// the full committed order.
const LIVE_SNAPSHOT_VERSION: u16 = 4;
const LIVE_SNAPSHOT_VERSION_TRANSITION: u16 = 3;
const LIVE_SNAPSHOT_VERSION_PREFIX: u16 = 2;
const LIVE_SNAPSHOT_VERSION_FULL: u16 = 1;

/// A finalised header together with the quorum certificate that finalised it.
///
/// The certificate is what makes the header a claim the chain agreed on rather
/// than a number a node computed; the roots inside it are what an auditor checks
/// the stored data against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedHeader {
    /// The header itself, including `state_root` and `dag_root`.
    pub header: Header,
    /// The quorum certificate over the header id.
    pub certificate: Certificate,
}

/// A directory holding a node's append-only state.
///
/// This is a single-owner, single-writer store, not a concurrent database.
/// An OS-backed exclusive lock excludes independently opened handles (including
/// other processes) for the lifetime of the owner and all its clones. Callers
/// must still serialize compound operations and must not use owner clones during
/// staging or activation. Clones follow activation, but the path lock does not
/// make compound operations concurrent-safe.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    active: Arc<RwLock<PathBuf>>,
    // Closing the last owner, clone, or private view releases the OS lock.
    lock: Arc<File>,
    // Shared with private staged views; never follows active-generation routing.
    slot_decisions: Arc<Mutex<PathBuf>>,
    // Serialize the inactive application WAL across clones and staged views.
    slot_applications: Arc<Mutex<()>>,
}

/// An unpublished private copy, borrowing its owner until activation or drop.
/// Dropping without activation removes the copy best-effort. Neither this view
/// nor its clones may be retained or used after activation or drop: they are
/// private flat handles, not owner clones, and do not follow publication.
#[derive(Debug)]
pub struct StagedStore<'a> {
    owner: &'a mut Store,
    view: Store,
    generation: String,
    published: bool,
}

impl StagedStore<'_> {
    /// The flat private store on which to perform adoption writes.
    pub fn store(&self) -> &Store {
        &self.view
    }

    /// Publishes the complete generation by atomically replacing `CURRENT`.
    ///
    /// # Errors
    /// Returns filesystem errors before publication. Cleanup after publication
    /// is best-effort and cannot turn successful publication into an error.
    pub fn activate(mut self) -> Result<(), StoreError> {
        validate_generation(&self.view.root)?;
        validate_pointer_file(&self.owner.root.join("CURRENT"))?;
        let temporary = self.owner.root.join("CURRENT.tmp");
        // Remove only a regular abandoned pointer, never follow a symlink.
        validate_pointer_file(&temporary)?;
        if temporary.try_exists()? {
            fs::remove_file(&temporary)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(self.generation.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, self.owner.root.join("CURRENT"))?;
        // Publication is irreversible: even a poisoned path lock must not make
        // Drop remove the generation now selected by CURRENT.
        self.published = true;
        *self.owner.active.write().expect("store path lock poisoned") = self.view.root.clone();
        cleanup_generations(&self.owner.root, Some(&self.generation));
        Ok(())
    }
}

impl Drop for StagedStore<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = remove_generation(&self.view.root);
        }
    }
}

impl Store {
    /// Opens (and creates) a store directory.
    ///
    /// The root is canonicalized before locking and routing so later cwd changes
    /// cannot redirect this owner or its clones to a different directory.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the directory cannot be created, or when `CURRENT`
    /// is malformed, not a regular file, or names a missing or invalid generation.
    /// An absent pointer selects the legacy flat store; an invalid one never does.
    /// Returns an actionable [`StoreError::Io`] if another handle holds the
    /// exclusive directory lock. The `.lock` entry must be a regular file.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root.as_ref())?;
        let lock_path = root.join(".lock");
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(invalid_layout("store .lock is not a regular file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("cannot exclusively lock store {}: {error}; close other store handles or stop the process using this directory", root.display()),
            )
        })?;
        let lock = Arc::new(lock);
        let pointer = root.join("CURRENT");
        validate_pointer_file(&pointer)?;
        let generation = match fs::read_to_string(&pointer) {
            Ok(name) if generation_name(&name) => Some(name),
            Ok(_) => return Err(invalid_layout("malformed CURRENT")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let active = if let Some(name) = &generation {
            let path = root.join(name);
            validate_generation(&path)?;
            path
        } else {
            root.clone()
        };
        slot_decision_journal::read(&root)?;
        slot_agreement_journal::validate(&root)?;
        slot_application_journal::read(&active)?;
        cleanup_generations(&root, generation.as_deref());
        Ok(Self {
            slot_decisions: Arc::new(Mutex::new(root.clone())),
            slot_applications: Arc::new(Mutex::new(())),
            root,
            active: Arc::new(RwLock::new(active)),
            lock,
        })
    }

    /// The canonical absolute logical root, independent of the active generation.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    fn path_of(&self, name: &str) -> PathBuf {
        self.active
            .read()
            .expect("store path lock poisoned")
            .join(name)
    }

    /// Copies the active files into an unpublished generation on the same filesystem.
    ///
    /// No other handles or clones may be used until this stage is dropped or
    /// activated. The borrowed owner cannot be used in the meantime.
    ///
    /// # Errors
    /// Returns filesystem errors for invalid layouts or failed copies, and decode
    /// errors for complete corrupt log records. The active files are unchanged.
    pub fn stage(&mut self) -> Result<StagedStore<'_>, StoreError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let source = self
            .active
            .read()
            .expect("store path lock poisoned")
            .clone();
        let (generation, path) = loop {
            let name = format!(
                "generation-{}{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = self.root.join(&name);
            match fs::create_dir(&path) {
                Ok(()) => break (name, path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };
        let lock = Arc::clone(&self.lock);
        let slot_decisions = Arc::clone(&self.slot_decisions);
        let slot_applications = Arc::clone(&self.slot_applications);
        let stage = StagedStore {
            owner: self,
            view: Store {
                root: path.clone(),
                active: Arc::new(RwLock::new(path.clone())),
                lock,
                slot_decisions,
                slot_applications,
            },
            generation,
            published: false,
        };
        for entry in fs::read_dir(&source)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == slot_decision_journal::FILE
                || name == ".lock"
                || name == "CURRENT"
                || name == "CURRENT.tmp"
                || name.ends_with(".tmp")
                || generation_name(&name)
            {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(invalid_layout("symlink in active store"));
            }
            if kind.is_file() {
                fs::copy(entry.path(), path.join(name.as_ref()))?;
            } else if source != stage.owner.root {
                return Err(invalid_layout("directory in active generation"));
            }
        }
        // Validate complete records before trimming framing-only torn tails.
        stage.view.vertices()?;
        stage.view.batches()?;
        stage.view.shards()?;
        stage.view.headers()?;
        stage.view.fences()?;
        stage.view.round_skips()?;
        stage.view.fence_shares()?;
        stage.view.clock_samples()?;
        for name in LOG_FILES {
            trim_torn_tail(&path.join(name))?;
        }
        Ok(stage)
    }

    /// Flushes both logs to the operating system.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when a file cannot be opened or synced.
    pub fn sync(&self) -> Result<(), StoreError> {
        for name in [VERTICES_FILE, BATCHES_FILE] {
            let path = self.path_of(name);
            if path.exists() {
                OpenOptions::new().append(true).open(&path)?.sync_all()?;
            }
        }
        Ok(())
    }

    /// Appends one vertex.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the vertex
    /// cannot be encoded.
    pub fn append_vertex(&self, vertex: &Vertex) -> Result<(), StoreError> {
        append_record(&self.path_of(VERTICES_FILE), &vertex.encode()?)?;
        Ok(())
    }

    /// Reads every complete vertex record, in append order.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a complete
    /// record does not decode.
    pub fn vertices(&self) -> Result<Vec<Vertex>, StoreError> {
        read_records(&self.path_of(VERTICES_FILE), Vertex::decode)
    }

    /// Appends one batch. Appending the same batch twice is harmless on read.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the batch
    /// cannot be encoded.
    pub fn put_batch(&self, batch: &Batch) -> Result<(), StoreError> {
        append_record(&self.path_of(BATCHES_FILE), &batch.encode()?)?;
        Ok(())
    }

    /// Reads every stored batch, deduplicated by digest, in first-append order.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a complete
    /// record does not decode.
    pub fn batches(&self) -> Result<Vec<Batch>, StoreError> {
        let records: Vec<Batch> = read_records(&self.path_of(BATCHES_FILE), Batch::decode)?;
        let mut seen = std::collections::HashSet::new();
        let mut unique = Vec::with_capacity(records.len());
        for batch in records {
            if seen.insert(batch.digest()?) {
                unique.push(batch);
            }
        }
        Ok(unique)
    }

    /// Writes the roots a node last reported, replacing any previous value.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure.
    pub fn put_roots(&self, roots: Roots) -> Result<(), StoreError> {
        let mut record = Vec::with_capacity(68);
        record.extend_from_slice(&ROOTS_VERSION.to_le_bytes());
        record.extend_from_slice(&roots.commit_root);
        record.extend_from_slice(&roots.state_root);

        let path = self.path_of(ROOTS_FILE);
        let temporary = self.path_of("roots.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&record)?;
        }
        // Rename is atomic on the platforms this experiment targets, so a crash
        // leaves either the old roots or the new ones, never a half-written file.
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    /// Appends one erasure-coded shard.
    ///
    /// Model B stores a shard permanently and the full batch only for a retention
    /// window, so this is what survives pruning. Appending the same
    /// `(digest, index)` twice is harmless on read: the last one wins.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the shard is
    /// too large for the record length field.
    pub fn put_shard(&self, digest: &[u8; 32], index: u16, bytes: &[u8]) -> Result<(), StoreError> {
        let length = u32::try_from(bytes.len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "shard does not fit a u32 length",
            ))
        })?;
        let mut record = Vec::with_capacity(38 + bytes.len());
        record.extend_from_slice(digest);
        record.extend_from_slice(&index.to_le_bytes());
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(bytes);
        append_record(&self.path_of(SHARDS_FILE), &record)?;
        Ok(())
    }

    /// Reads every stored shard, last write per `(digest, index)` only.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a record is
    /// short.
    pub fn shards(&self) -> Result<Vec<StoredShard>, StoreError> {
        let raw: Vec<Vec<u8>> = read_records(&self.path_of(SHARDS_FILE), |bytes| {
            if bytes.len() < 38 {
                return Err(CryptoError::new(
                    crypto::CryptoErrorKind::TruncatedInput,
                    "shard record is shorter than its header",
                ));
            }
            Ok(bytes.to_vec())
        })?;

        let mut seen: std::collections::HashMap<([u8; 32], u16), StoredShard> =
            std::collections::HashMap::new();
        for bytes in raw {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes[..32]);
            let index = u16::from_le_bytes([bytes[32], bytes[33]]);
            let length = u32::from_le_bytes([bytes[34], bytes[35], bytes[36], bytes[37]]) as usize;
            let start: usize = 38;
            let Some(end) = start.checked_add(length) else {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::TruncatedInput,
                    "shard length overflows",
                )));
            };
            if end > bytes.len() {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::TruncatedInput,
                    "shard body is shorter than its length field",
                )));
            }
            seen.insert(
                (digest, index),
                StoredShard {
                    digest,
                    index,
                    bytes: bytes[start..end].to_vec(),
                },
            );
        }

        let mut shards: Vec<StoredShard> = seen.into_values().collect();
        shards.sort_by(|a, b| a.digest.cmp(&b.digest).then(a.index.cmp(&b.index)));
        Ok(shards)
    }

    /// Appends a certified header.
    ///
    /// A store that cannot show which headers the chain finalised cannot be
    /// audited at all: the roots it holds would be local arithmetic with nothing
    /// to compare against. Appending the same height twice is harmless on read —
    /// the last one wins.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when either
    /// object does not encode or the record exceeds the length field.
    pub fn put_header(&self, header: &Header, certificate: &Certificate) -> Result<(), StoreError> {
        let record = encode_header_record(header, certificate)?;
        append_record(&self.path_of(HEADERS_FILE), &record)
    }

    /// Reads every certified header, last write per height, sorted by height.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a record is
    /// short or either object does not decode.
    pub fn headers(&self) -> Result<Vec<CertifiedHeader>, StoreError> {
        let records: Vec<CertifiedHeader> =
            read_records(&self.path_of(HEADERS_FILE), decode_header_record)?;
        let mut by_height: std::collections::BTreeMap<u64, CertifiedHeader> =
            std::collections::BTreeMap::new();
        for record in records {
            by_height.insert(record.header.height, record);
        }
        Ok(by_height.into_values().collect())
    }

    /// Drops certified headers above `height`.
    ///
    /// A restart that cannot reproduce a stored header's committed prefix
    /// resumes from the highest header it can prove. Rewriting the log keeps the
    /// next restart and audit from walking a head the retained order cannot
    /// account for. Nothing below `height` is touched, so a store that never
    /// crossed the point is left byte-for-byte alone.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read or write failure, [`StoreError::Decode`] when a
    /// retained record does not encode.
    pub fn truncate_headers(&self, height: u64) -> Result<usize, StoreError> {
        let headers = self.headers()?;
        let kept: Vec<&CertifiedHeader> = headers
            .iter()
            .filter(|record| record.header.height <= height)
            .collect();
        let dropped = headers.len() - kept.len();
        if dropped == 0 {
            return Ok(0);
        }
        let mut encoded = Vec::new();
        for record in kept {
            let bytes = encode_header_record(&record.header, &record.certificate)?;
            let length = u32::try_from(bytes.len()).map_err(|_| {
                StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::FieldTooLong,
                    "header record does not fit a u32 length",
                ))
            })?;
            encoded.extend_from_slice(&length.to_le_bytes());
            encoded.extend_from_slice(&bytes);
        }
        rewrite(&self.path_of(HEADERS_FILE), &encoded)?;
        Ok(dropped)
    }

    /// Writes a state snapshot taken at `round`, replacing any previous one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the
    /// state does not fit the record length field.
    pub fn put_snapshot(&self, round: u64, state: &[u8]) -> Result<(), StoreError> {
        let length = u32::try_from(state.len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "snapshot does not fit a u32 length",
            ))
        })?;
        let mut record = Vec::with_capacity(14 + state.len());
        record.extend_from_slice(&ROOTS_VERSION.to_le_bytes());
        record.extend_from_slice(&round.to_le_bytes());
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(state);

        let temporary = self.path_of("snapshot.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&record)?;
        }
        fs::rename(&temporary, self.path_of(SNAPSHOT_FILE))?;
        Ok(())
    }

    /// Reads the state snapshot, if one was written.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when the record is
    /// short or carries an unknown version.
    pub fn snapshot(&self) -> Result<Option<Snapshot>, StoreError> {
        let path = self.path_of(SNAPSHOT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let record = fs::read(&path)?;
        if record.len() < 14 {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "snapshot is shorter than its header",
            )));
        }
        let version = u16::from_le_bytes([record[0], record[1]]);
        if version != ROOTS_VERSION {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::MalformedCertificate,
                format!("unsupported snapshot version {version}"),
            )));
        }
        let mut round = [0u8; 8];
        round.copy_from_slice(&record[2..10]);
        let mut length = [0u8; 4];
        length.copy_from_slice(&record[10..14]);
        let length = u32::from_le_bytes(length) as usize;
        let start = 14usize;
        let Some(end) = start.checked_add(length) else {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "snapshot length overflows",
            )));
        };
        if end > record.len() {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "snapshot body is shorter than its length field",
            )));
        }
        Ok(Some(Snapshot {
            round: u64::from_le_bytes(round),
            state: record[start..end].to_vec(),
        }))
    }

    /// Writes the authorized set change this store adopted.
    ///
    /// The prototype allows one transition per chain. Rewriting the same
    /// certificate is a no-op; a different certificate is refused rather than
    /// silently replacing the authorization a restart and an audit depend on.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the
    /// certificate does not encode, or when a different change is already stored.
    pub fn put_set_change(&self, certificate: &TransitionCertificate) -> Result<(), StoreError> {
        if let Some(existing) = self.set_change()? {
            if existing != *certificate {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::InvalidKeySchedule,
                    "the store already holds a different set change",
                )));
            }
            return Ok(());
        }
        let encoded = certificate.encode()?;
        let temporary = self.path_of("set-change.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&encoded)?;
        }
        fs::rename(&temporary, self.path_of(SET_CHANGE_FILE))?;
        Ok(())
    }

    /// Reads the set change this store adopted, if any.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when the file
    /// does not decode.
    pub fn set_change(&self) -> Result<Option<TransitionCertificate>, StoreError> {
        let path = self.path_of(SET_CHANGE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        Ok(Some(TransitionCertificate::decode(&bytes)?))
    }

    /// Writes a quorum-authorized fence this node adopted.
    ///
    /// A restart must keep the fence: without it, a node would wait again on a
    /// leader that the quorum already declared failed. The record is a list keyed
    /// by validator; the same certificate is a no-op, a lower starting round
    /// replaces the entry (the DAG's rule), and a higher one is ignored.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the
    /// certificate does not encode or the existing record cannot be read.
    pub fn put_fence(&self, certificate: &FenceCertificate) -> Result<(), StoreError> {
        if let Some(existing) = self
            .fences()?
            .iter()
            .find(|existing| existing.fence.validator_id == certificate.fence.validator_id)
            && existing.fence.from_round <= certificate.fence.from_round
        {
            return Ok(());
        }
        // The log keeps both records; `fences` reduces each validator to its
        // lowest starting round, which is the promise the DAG enforces.
        append_record(&self.path_of(FENCES_FILE), &certificate.encode()?)
    }

    /// Reads the fences this store adopted, oldest record format included.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a record
    /// does not decode.
    pub fn fences(&self) -> Result<Vec<FenceCertificate>, StoreError> {
        let mut records = Vec::new();
        let path = self.path_of(FENCES_FILE);
        if path.exists() {
            records.extend(read_records(&path, FenceCertificate::decode)?);
        }
        // A store written before the list existed holds one bare certificate.
        // Read both when both exist, so appending to the list never hides it.
        let legacy = self.path_of(FENCE_FILE);
        if legacy.exists() {
            let bytes = fs::read(&legacy)?;
            records.push(FenceCertificate::decode(&bytes)?);
        }
        Ok(lowest_fences(records))
    }

    /// Writes a round-skip proof this node verified.
    ///
    /// The proof is a decision input: a restart that lost it would replay the
    /// same vertices and might decide a round the original run skipped. The log
    /// keeps one proof per leader round; re-writing the same proof is a no-op and
    /// a different proof for the same round is refused, because the round can
    /// name only one leader.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the proof
    /// does not encode or a different proof is already stored for the round.
    pub fn put_round_skip(&self, proof: &RoundSkipProof) -> Result<(), StoreError> {
        let round = proof.attestation.skip.round();
        if let Some(existing) = self
            .round_skips()?
            .into_iter()
            .find(|existing| existing.attestation.skip.round() == round)
        {
            if existing == *proof {
                return Ok(());
            }
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::InvalidVertex,
                format!("the store already holds a different round skip at {round}"),
            )));
        }
        append_record(&self.path_of(ROUND_SKIPS_FILE), &proof.encode()?)
    }

    /// Reads the round-skip proofs this store adopted, one per leader round.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a record
    /// does not decode.
    pub fn round_skips(&self) -> Result<Vec<RoundSkipProof>, StoreError> {
        let mut by_round: BTreeMap<u64, RoundSkipProof> = BTreeMap::new();
        for proof in read_records(&self.path_of(ROUND_SKIPS_FILE), RoundSkipProof::decode)? {
            by_round
                .entry(proof.attestation.skip.round())
                .or_insert(proof);
        }
        Ok(by_round.into_values().collect())
    }

    /// Writes one fence share this node signed, before a quorum completes it.
    ///
    /// The promise is durable: a node that forgets a share on restart would be
    /// free to vote for an author it already declared failed. The same share is
    /// a no-op and a lower starting round replaces the entry, matching the DAG.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the
    /// certificate does not encode or the existing log cannot be read.
    pub fn put_fence_share(&self, certificate: &FenceCertificate) -> Result<(), StoreError> {
        if let Some(existing) = self
            .fence_shares()?
            .iter()
            .find(|existing| existing.fence.validator_id == certificate.fence.validator_id)
            && existing.fence.from_round <= certificate.fence.from_round
        {
            return Ok(());
        }
        append_record(
            &self.path_of(FENCE_SHARES_FILE),
            &encode_fence_share(&FenceShareRecord::Signed(certificate.clone()))?,
        )
    }

    /// Forgets a local fence share whose proposal the node abandoned.
    ///
    /// A tombstone is appended rather than rewriting the log, so a later share
    /// for the same validator is ordered after it and takes effect again.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the
    /// existing log cannot be read.
    pub fn clear_fence_share(&self, validator_id: &[u8]) -> Result<(), StoreError> {
        if self
            .fence_shares()?
            .iter()
            .all(|certificate| certificate.fence.validator_id != validator_id)
        {
            return Ok(());
        }
        append_record(
            &self.path_of(FENCE_SHARES_FILE),
            &encode_fence_share(&FenceShareRecord::Cleared(validator_id.to_vec()))?,
        )
    }

    /// Reads the fence shares this node signed and has not cleared.
    ///
    /// The log is reduced per validator to the lowest starting round; a
    /// tombstone removes the validator until a later share re-adds it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when a record
    /// does not decode.
    pub fn fence_shares(&self) -> Result<Vec<FenceCertificate>, StoreError> {
        let mut by_validator: BTreeMap<Vec<u8>, FenceCertificate> = BTreeMap::new();
        for record in read_records(&self.path_of(FENCE_SHARES_FILE), decode_fence_share)? {
            match record {
                FenceShareRecord::Signed(certificate) => {
                    let validator = certificate.fence.validator_id.clone();
                    match by_validator.get(&validator) {
                        Some(existing)
                            if existing.fence.from_round <= certificate.fence.from_round => {}
                        _ => {
                            by_validator.insert(validator, certificate);
                        }
                    }
                }
                FenceShareRecord::Cleared(validator) => {
                    by_validator.remove(&validator);
                }
            }
        }
        Ok(by_validator.into_values().collect())
    }

    /// Writes the snapshot a snapshot join adopted, replacing any previous one.
    ///
    /// The committed order is written as a compact frontier plus its tail above
    /// the floor. A snapshot that never split its order writes an empty frontier
    /// and the full tail, which is byte-compatible with version 1 on read.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when a field
    /// does not encode or the order length does not match its parts.
    pub fn put_live_snapshot(&self, snapshot: &LiveSnapshot) -> Result<(), StoreError> {
        if snapshot.order_len != snapshot.prefix.len().saturating_add(snapshot.order.len()) {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot order length does not match its prefix and tail",
            )));
        }
        let mut encoder = Encoder::with_capacity(
            64 + snapshot.state.len()
                + snapshot.order.len() * 56
                + snapshot.prefix.peaks().len() * 34,
        );
        encoder.put_u16(LIVE_SNAPSHOT_VERSION);
        encoder.put_u64(snapshot.round);
        match snapshot.floor {
            None => encoder.put_u8(0),
            Some(floor) => {
                encoder.put_u8(1);
                encoder.put_u64(floor);
            }
        }
        encoder.put_u64(snapshot.cursor);
        encoder.put_u64(snapshot.applied);
        encoder.put_bytes(&snapshot.state)?;
        encoder.put_u64(u64::try_from(snapshot.order_len).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot order length does not fit a u64",
            ))
        })?);
        encoder.put_u64(u64::try_from(snapshot.prefix.len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot prefix length does not fit a u64",
            ))
        })?);
        encoder.put_u32(u32::try_from(snapshot.prefix.peaks().len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot peak count does not fit a u32",
            ))
        })?);
        for peak in snapshot.prefix.peaks() {
            encoder.put_bytes(peak)?;
        }
        encoder.put_u32(u32::try_from(snapshot.order.len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot order does not fit a u32 count",
            ))
        })?);
        for id in &snapshot.order {
            encoder.put_u64(id.round);
            encoder.put_bytes(&id.author)?;
            encoder.put_bytes(&id.digest)?;
        }
        encoder.put_bytes(&snapshot.header.encode()?)?;
        encoder.put_bytes(&snapshot.certificate.encode()?)?;
        match &snapshot.transition {
            None => encoder.put_u8(0),
            Some(transition) => {
                encoder.put_u8(1);
                encoder.put_bytes(&transition.encode()?)?;
            }
        }
        encoder.put_u32(u32::try_from(snapshot.fences.len()).map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::FieldTooLong,
                "live snapshot fences do not fit a u32 count",
            ))
        })?);
        for certificate in &snapshot.fences {
            encoder.put_bytes(&certificate.encode()?)?;
        }

        let temporary = self.path_of("live.snapshot.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(encoder.as_slice())?;
        }
        fs::rename(&temporary, self.path_of(LIVE_SNAPSHOT_FILE))?;
        Ok(())
    }

    /// Reads the snapshot a snapshot join adopted, if one was written.
    ///
    /// Version 1 stored the whole committed order and is read as an empty
    /// frontier with that order as the tail. Version 2 reads the compact prefix
    /// and the tail above it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure, [`StoreError::Decode`] when the record
    /// is short, a field does not decode, or its order parts disagree.
    pub fn live_snapshot(&self) -> Result<Option<LiveSnapshot>, StoreError> {
        let path = self.path_of(LIVE_SNAPSHOT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let record = fs::read(&path)?;
        let mut decoder = Decoder::new(&record);
        let version = decoder.read_u16()?;
        if version != LIVE_SNAPSHOT_VERSION
            && version != LIVE_SNAPSHOT_VERSION_TRANSITION
            && version != LIVE_SNAPSHOT_VERSION_PREFIX
            && version != LIVE_SNAPSHOT_VERSION_FULL
        {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::MalformedCertificate,
                format!("unsupported live snapshot version {version}"),
            )));
        }
        let round = decoder.read_u64()?;
        let floor = match decoder.read_u8()? {
            0 => None,
            1 => Some(decoder.read_u64()?),
            other => {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::InvalidVertex,
                    format!("unknown live snapshot floor flag {other}"),
                )));
            }
        };
        let cursor = decoder.read_u64()?;
        let applied = decoder.read_u64()?;
        let state = decoder.read_bytes()?.to_vec();
        let (order_len, prefix, order) = if version == LIVE_SNAPSHOT_VERSION_FULL {
            let order = decode_live_order(&mut decoder, record.len())?;
            (order.len(), CommitFrontier::empty(), order)
        } else {
            let order_len = usize::try_from(decoder.read_u64()?).map_err(|_| {
                StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::FieldTooLong,
                    "live snapshot order length does not fit this host",
                ))
            })?;
            let prefix_len = usize::try_from(decoder.read_u64()?).map_err(|_| {
                StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::FieldTooLong,
                    "live snapshot prefix length does not fit this host",
                ))
            })?;
            let peak_count = decoder.read_u32()? as usize;
            if peak_count > record.len() {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::FieldTooLong,
                    "live snapshot peak count exceeds the record",
                )));
            }
            let mut peaks = Vec::with_capacity(peak_count.min(64));
            for _ in 0..peak_count {
                let peak: [u8; 32] = decoder.read_bytes()?.try_into().map_err(|_| {
                    StoreError::Decode(CryptoError::new(
                        crypto::CryptoErrorKind::TruncatedInput,
                        "live snapshot peak is not 32 bytes",
                    ))
                })?;
                peaks.push(peak);
            }
            let prefix = CommitFrontier::from_peaks(prefix_len, peaks)?;
            let order = decode_live_order(&mut decoder, record.len())?;
            if prefix.len().checked_add(order.len()) != Some(order_len) {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::InvalidVertex,
                    "live snapshot order length does not match its prefix and tail",
                )));
            }
            (order_len, prefix, order)
        };
        let header = Header::decode(decoder.read_bytes()?)?;
        let certificate = Certificate::decode(decoder.read_bytes()?)?;
        let transition = if version >= LIVE_SNAPSHOT_VERSION_TRANSITION {
            match decoder.read_u8()? {
                0 => None,
                1 => Some(TransitionCertificate::decode(decoder.read_bytes()?)?),
                other => {
                    return Err(StoreError::Decode(CryptoError::new(
                        crypto::CryptoErrorKind::InvalidVertex,
                        format!("unknown live snapshot transition flag {other}"),
                    )));
                }
            }
        } else {
            None
        };
        let fences = if version >= LIVE_SNAPSHOT_VERSION {
            let fence_count = decoder.read_u32()? as usize;
            if fence_count > record.len() {
                return Err(StoreError::Decode(CryptoError::new(
                    crypto::CryptoErrorKind::FieldTooLong,
                    "live snapshot fence count exceeds the record",
                )));
            }
            let mut fences = Vec::with_capacity(fence_count.min(64));
            for _ in 0..fence_count {
                fences.push(FenceCertificate::decode(decoder.read_bytes()?)?);
            }
            fences
        } else {
            Vec::new()
        };
        decoder.finish()?;
        Ok(Some(LiveSnapshot {
            round,
            floor,
            cursor,
            applied,
            state,
            order,
            order_len,
            prefix,
            header,
            certificate,
            transition,
            fences,
        }))
    }

    /// Drops every vertex at or below `round`, and every payload no kept vertex
    /// names — but only when a shard still backs that payload.
    ///
    /// This is model B's closing edge. A shard is kept forever; a payload is kept
    /// for a window and then dropped, because `n` nodes each holding one shard can
    /// rebuild what none of them holds whole. The rule that decides *when* is:
    ///
    /// * a batch is deletable once nothing in the retained tail names it, and
    /// * this node holds at least `min_shards` shards of it.
    ///
    /// So a node with no shards keeps every payload: deleting data it alone holds
    /// would be silent loss, not pruning. `min_shards = 0` deletes
    /// unconditionally and is only correct for a node outside the erasure set.
    ///
    /// The window is the caller's `round`. Payload cannot be kept *longer* than
    /// metadata in this layout: once the vertices are gone, nothing on disk says
    /// which round a batch belonged to, so there is no way to age it out later.
    /// A longer payload window therefore means a longer vertex window too.
    ///
    /// Each log is rewritten through a temporary file and renamed into place, so a
    /// crash leaves either the old log or the new one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read or write failure, [`StoreError::Decode`] when a
    /// record does not decode.
    pub fn prune_below(&self, round: u64, min_shards: usize) -> Result<PruneReport, StoreError> {
        self.prune_records(round, min_shards, None)
    }

    /// Drops everything the stored live snapshot already covers.
    ///
    /// The live snapshot is the trust anchor a restart resumes from: it carries
    /// the state, the committed order prefix, and the certificate for its header.
    /// Everything at or below its floor has therefore been decided, and the tail
    /// above it is all a restart still has to replay. Certified headers below the
    /// anchor height go too; the anchor's own header is kept, so an audit and a
    /// restart still see the certified height they resume above.
    ///
    /// `min_shards` has the same meaning as in [`Store::prune_below`]. A live node
    /// that stores whole payloads is outside the erasure set and passes zero; a node
    /// that holds one shard per batch passes one. A payload named by a kept vertex
    /// is never dropped, because the vertex may still be committed after the restart.
    ///
    /// With no live snapshot, or with one whose floor is absent, nothing is dropped.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read or write failure, [`StoreError::Decode`] when a
    /// record does not decode.
    pub fn prune_to_checkpoint(&self, min_shards: usize) -> Result<PruneReport, StoreError> {
        let Some(snapshot) = self.live_snapshot()? else {
            return Ok(PruneReport::default());
        };
        let Some(floor) = snapshot.floor else {
            return Ok(PruneReport::default());
        };
        let report = self.prune_records(floor, min_shards, Some(snapshot.header.height))?;
        self.trim_clock(floor)?;
        Ok(report)
    }

    fn prune_records(
        &self,
        round: u64,
        min_shards: usize,
        keep_headers_from: Option<u64>,
    ) -> Result<PruneReport, StoreError> {
        let vertices = self.vertices()?;
        let kept: Vec<&Vertex> = vertices
            .iter()
            .filter(|vertex| vertex.round > round)
            .collect();
        let removed = vertices.len() - kept.len();

        let mut hashes = std::collections::HashSet::new();
        for vertex in &kept {
            hashes.insert(vertex.payload_hash);
        }

        let mut shard_count: std::collections::HashMap<[u8; 32], usize> =
            std::collections::HashMap::new();
        for shard in self.shards()? {
            *shard_count.entry(shard.digest).or_default() += 1;
        }

        let mut before: u64 = 0;
        for name in [VERTICES_FILE, BATCHES_FILE] {
            let path = self.path_of(name);
            if path.exists() {
                before += fs::metadata(&path)?.len();
            }
        }
        if keep_headers_from.is_some() && self.path_of(HEADERS_FILE).exists() {
            before += fs::metadata(self.path_of(HEADERS_FILE))?.len();
        }

        let mut kept_batches = Vec::new();
        let mut report = PruneReport {
            vertices: removed,
            ..PruneReport::default()
        };
        for batch in self.batches()? {
            let digest = batch.digest()?;
            let named = hashes.contains(&digest);
            let backed = shard_count.get(&digest).copied().unwrap_or(0) >= min_shards;
            if !named && backed {
                report.batches_dropped += 1;
                continue;
            }
            if !named {
                report.batches_held += 1;
            }
            let bytes = batch.encode()?;
            kept_batches.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            kept_batches.extend_from_slice(&bytes);
        }

        if removed > 0 {
            let mut encoded = Vec::new();
            for vertex in &kept {
                let bytes = vertex.encode()?;
                encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                encoded.extend_from_slice(&bytes);
            }
            rewrite(&self.path_of(VERTICES_FILE), &encoded)?;
        }
        if report.batches_dropped > 0 {
            rewrite(&self.path_of(BATCHES_FILE), &kept_batches)?;
        }
        if let Some(keep_from) = keep_headers_from {
            let headers = self.headers()?;
            let removed = headers
                .iter()
                .filter(|record| record.header.height < keep_from)
                .count();
            if removed > 0 {
                let mut encoded = Vec::new();
                for record in headers
                    .iter()
                    .filter(|record| record.header.height >= keep_from)
                {
                    let bytes = encode_header_record(&record.header, &record.certificate)?;
                    encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    encoded.extend_from_slice(&bytes);
                }
                rewrite(&self.path_of(HEADERS_FILE), &encoded)?;
            }
            report.headers = removed;
        }

        let mut after: u64 = 0;
        for name in [VERTICES_FILE, BATCHES_FILE] {
            let path = self.path_of(name);
            if path.exists() {
                after += fs::metadata(&path)?.len();
            }
        }
        if keep_headers_from.is_some() && self.path_of(HEADERS_FILE).exists() {
            after += fs::metadata(self.path_of(HEADERS_FILE))?.len();
        }
        report.bytes_freed = before.saturating_sub(after);

        Ok(report)
    }

    /// Bytes the store occupies, every file in the directory included.
    ///
    /// The cap is about a volume, not about one log, so headers, shards, the
    /// snapshot, and the clock file count. Files that pruning cannot shrink are
    /// exactly what makes a shortfall possible.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the directory cannot be read.
    pub fn disk_bytes(&self) -> Result<u64, StoreError> {
        directory_bytes(&self.root)
    }

    /// Records that the node's head was at `round` at `unix_seconds`.
    ///
    /// Age-based retention needs a round-to-time map, and this is it. The caller
    /// decides the cadence; once a second is plenty, because pruning days of
    /// history does not need better resolution than a second. Samples are
    /// discarded when a later prune drops that part of the log.
    ///
    /// A round that goes backwards is ignored rather than recorded: a store that
    /// is reopened by a fresh demo run would otherwise claim that round 0 happened
    /// after round 500, which would make the age window prune the wrong tail.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the clock file cannot be read or written, and
    /// [`StoreError::Decode`] when an existing record does not decode.
    pub fn record_clock(&self, round: u64, unix_seconds: u64) -> Result<(), StoreError> {
        if let Some((last_round, _)) = self.clock_samples()?.last()
            && round < *last_round
        {
            return Ok(());
        }
        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(&round.to_le_bytes());
        payload[8..].copy_from_slice(&unix_seconds.to_le_bytes());
        append_record(&self.path_of(CLOCK_FILE), &payload)
    }

    /// Works out what a retention policy would drop, without dropping anything.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when a log cannot be read, and [`StoreError::Decode`]
    /// when a record does not decode.
    pub fn plan(
        &self,
        retention: Retention,
        now_unix: u64,
        min_shards: usize,
    ) -> Result<RetentionPlan, StoreError> {
        let vertices = self.vertices()?;
        let disk_bytes = self.disk_bytes()?;
        let age_cutoff = self.age_cutoff(retention.days, now_unix)?;
        let size_cutoff =
            self.size_cutoff(&vertices, retention.max_bytes, min_shards, disk_bytes)?;
        let desired = match (age_cutoff, size_cutoff) {
            (Some(age), Some(size)) => Some(age.max(size)),
            (age, size) => age.or(size),
        };
        // A snapshot at round S is the state after S: only what is above S has to
        // be replayed, so dropping above S leaves a hole nothing can fill. With no
        // snapshot there is no anchor at all, and the safe answer is to prune
        // nothing rather than to make the store unreplayable.
        let snapshot_round = self.snapshot()?.map(|snapshot| snapshot.round);
        let cutoff = match (desired, snapshot_round) {
            (Some(desired), Some(snapshot)) => Some(desired.min(snapshot)),
            _ => None,
        };
        Ok(RetentionPlan {
            age_cutoff,
            size_cutoff,
            cutoff,
            snapshot_round,
            disk_bytes,
            max_bytes: retention.max_bytes,
        })
    }

    /// Applies a retention policy and reports what it removed.
    ///
    /// "This many days or this much disk, whichever comes first" is a single
    /// cutoff: both halves are converted to a round, and the one that leaves less
    /// history wins. A policy with neither bound does nothing, and so does a store
    /// with no snapshot: there would be no state to replay the tail onto.
    ///
    /// # Errors
    ///
    /// Anything [`Store::plan`] or [`Store::prune_below`] reports.
    pub fn prune(
        &self,
        retention: Retention,
        now_unix: u64,
        min_shards: usize,
    ) -> Result<PruneReport, StoreError> {
        let plan = self.plan(retention, now_unix, min_shards)?;
        let Some(cutoff) = plan.cutoff else {
            return Ok(PruneReport::default());
        };
        let mut report = self.prune_below(cutoff, min_shards)?;
        self.trim_clock(cutoff)?;
        if plan.max_bytes > 0 {
            report.cap_shortfall = self.disk_bytes()?.saturating_sub(plan.max_bytes);
        }
        Ok(report)
    }

    /// Rounds older than the window, read off the clock file.
    ///
    /// With no samples the answer is `None`, not "everything": a store whose age
    /// is unknown must not be emptied on a guess.
    fn age_cutoff(&self, days: u32, now_unix: u64) -> Result<Option<u64>, StoreError> {
        if days == 0 {
            return Ok(None);
        }
        let window = u64::from(days).saturating_mul(86_400);
        let threshold = now_unix.saturating_sub(window);
        let mut cutoff = None;
        for (round, at) in self.clock_samples()? {
            if at <= threshold {
                cutoff = Some(round);
            }
        }
        Ok(cutoff)
    }

    /// The round the disk cap alone requires dropping to, if the cap is exceeded.
    ///
    /// Freed bytes are counted with the same rule [`Store::prune_below`] applies: a
    /// vertex's record goes, and a batch goes only when no kept vertex names it and
    /// enough shards back it. Counting is one pass over rounds rather than a
    /// simulation per candidate, because the freed set only grows as the cutoff
    /// rises.
    fn size_cutoff(
        &self,
        vertices: &[Vertex],
        max_bytes: u64,
        min_shards: usize,
        disk_bytes: u64,
    ) -> Result<Option<u64>, StoreError> {
        if max_bytes == 0 || disk_bytes <= max_bytes {
            return Ok(None);
        }
        let need = disk_bytes - max_bytes;

        let mut shard_count: std::collections::HashMap<[u8; 32], usize> =
            std::collections::HashMap::new();
        for shard in self.shards()? {
            *shard_count.entry(shard.digest).or_default() += 1;
        }
        let backed =
            |digest: &[u8; 32]| shard_count.get(digest).copied().unwrap_or(0) >= min_shards;

        let mut batch_sizes: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        for batch in self.batches()? {
            let digest = batch.digest()?;
            batch_sizes.insert(digest, batch.encode()?.len() as u64 + 4);
        }
        if vertices.is_empty() {
            let droppable: u64 = batch_sizes
                .iter()
                .filter(|(digest, _)| backed(digest))
                .map(|(_, size)| *size)
                .sum();
            return Ok((droppable > 0).then_some(0));
        }

        let mut name_counts: std::collections::HashMap<[u8; 32], usize> =
            std::collections::HashMap::new();
        let mut records: Vec<(u64, u64, [u8; 32])> = Vec::with_capacity(vertices.len());
        for vertex in vertices {
            *name_counts.entry(vertex.payload_hash).or_default() += 1;
            records.push((
                vertex.round,
                vertex.encode()?.len() as u64 + 4,
                vertex.payload_hash,
            ));
        }
        records.sort_by_key(|(round, _, _)| *round);

        // A batch no vertex names is droppable before any round is considered.
        let mut freed: u64 = batch_sizes
            .iter()
            .filter(|(digest, _)| !name_counts.contains_key(*digest) && backed(digest))
            .map(|(_, size)| *size)
            .sum();

        let mut index = 0usize;
        while index < records.len() {
            let round = records[index].0;
            while index < records.len() && records[index].0 == round {
                let (_, size, digest) = records[index];
                freed = freed.saturating_add(size);
                if let Some(count) = name_counts.get_mut(&digest) {
                    *count -= 1;
                    if *count == 0
                        && let Some(batch_size) = batch_sizes.get(&digest)
                        && backed(&digest)
                    {
                        freed = freed.saturating_add(*batch_size);
                    }
                }
                index += 1;
            }
            if freed >= need {
                return Ok(Some(round));
            }
        }

        // Even dropping every round does not reach the cap. Prune what can go and
        // let the caller see the shortfall rather than reporting a lie.
        Ok(Some(records[records.len() - 1].0))
    }

    /// Drops clock samples below `cutoff`, keeping the last one that still anchors
    /// the boundary so a later age window has a reference point.
    fn trim_clock(&self, cutoff: u64) -> Result<(), StoreError> {
        let path = self.path_of(CLOCK_FILE);
        if !path.exists() {
            return Ok(());
        }
        let mut boundary = None;
        let mut kept = Vec::new();
        for (round, at) in self.clock_samples()? {
            if round <= cutoff {
                boundary = Some((round, at));
            } else {
                kept.push((round, at));
            }
        }
        let mut encoded = Vec::with_capacity((kept.len() + 1) * 20);
        for (round, at) in boundary.into_iter().chain(kept) {
            encoded.extend_from_slice(&16u32.to_le_bytes());
            encoded.extend_from_slice(&round.to_le_bytes());
            encoded.extend_from_slice(&at.to_le_bytes());
        }
        rewrite(&path, &encoded)
    }

    fn clock_samples(&self) -> Result<Vec<(u64, u64)>, StoreError> {
        read_records(&self.path_of(CLOCK_FILE), clock_record)
    }

    /// Records the chain this directory belongs to.
    ///
    /// Written once, at the first write. A second call with the same hash is a
    /// no-op; a different one is refused, because the alternative is reinterpreting
    /// what is already on disk as another chain's data, which is the one mistake a
    /// store cannot recover from.
    ///
    /// # Errors
    ///
    /// [`StoreError::ChainMismatch`] when the directory is already bound to another
    /// chain, and [`StoreError::Io`] when the record cannot be written.
    pub fn bind_genesis(&self, hash: &[u8; 32]) -> Result<(), StoreError> {
        match self.genesis()? {
            Some(stored) if stored == *hash => Ok(()),
            Some(stored) => Err(StoreError::ChainMismatch {
                stored,
                expected: *hash,
            }),
            None => {
                fs::write(self.path_of(GENESIS_FILE), hash)?;
                Ok(())
            }
        }
    }

    /// Writes the genesis header this store was built under.
    ///
    /// The chain id binding says *which* chain; this says where that chain's
    /// state started. A live node credits balances on top of the demo genesis, so
    /// the state root in its first header is not the one a command can rebuild
    /// from the membership alone. Persisting the header makes audit and restart
    /// use the same anchor instead of guessing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure and [`StoreError::Decode`] when the
    /// header does not encode.
    pub fn put_genesis_header(&self, header: &Header) -> Result<(), StoreError> {
        let encoded = header.encode()?;
        let temporary = self.path_of("genesis.header.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&encoded)?;
        }
        fs::rename(&temporary, self.path_of(GENESIS_HEADER_FILE))?;
        Ok(())
    }

    /// Reads the genesis header, if one was written.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure and [`StoreError::Decode`] when the
    /// record does not decode.
    pub fn genesis_header(&self) -> Result<Option<Header>, StoreError> {
        let path = self.path_of(GENESIS_HEADER_FILE);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Header::decode(&fs::read(&path)?)?))
    }

    /// Writes the encoded state the chain started from.
    ///
    /// A genesis header names only a root. If the starting state is not the one a
    /// command can rebuild from the membership alone — the live harness credits
    /// demo balances — the root cannot be checked by replaying from a guessed
    /// genesis. Persisting the bytes makes audit and restart use the exact state.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure.
    pub fn put_genesis_state(&self, state: &[u8]) -> Result<(), StoreError> {
        let temporary = self.path_of("genesis.state.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(state)?;
        }
        fs::rename(&temporary, self.path_of(GENESIS_STATE_FILE))?;
        Ok(())
    }

    /// Reads the encoded genesis state, if one was written.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure.
    pub fn genesis_state(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.path_of(GENESIS_STATE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read(&path)?))
    }

    /// The chain recorded in this directory, if one was ever written.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the file cannot be read, and
    /// [`StoreError::Decode`] when it is not a 32-byte hash.
    pub fn genesis(&self) -> Result<Option<[u8; 32]>, StoreError> {
        let path = self.path_of(GENESIS_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "genesis record is not 32 bytes",
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Some(hash))
    }

    /// Refuses a directory that belongs to another chain.
    ///
    /// A store with no recorded chain is accepted: directories written before this
    /// existed, and a first write, are both legitimate. Only a positive disagreement
    /// is an error.
    ///
    /// # Errors
    ///
    /// [`StoreError::ChainMismatch`] when the recorded chain differs.
    pub fn require_genesis(&self, hash: &[u8; 32]) -> Result<(), StoreError> {
        match self.genesis()? {
            Some(stored) if stored != *hash => Err(StoreError::ChainMismatch {
                stored,
                expected: *hash,
            }),
            _ => Ok(()),
        }
    }

    /// Reads the last reported roots, if any were ever written.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read failure.
    pub fn roots(&self) -> Result<Option<Roots>, StoreError> {
        let path = self.path_of(ROOTS_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let record = fs::read(&path)?;
        if record.len() < 2 + 64 {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "roots record is shorter than its header",
            )));
        }
        let version = u16::from_le_bytes([record[0], record[1]]);
        if version != ROOTS_VERSION {
            return Err(StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::MalformedCertificate,
                format!("unsupported roots version {version}"),
            )));
        }
        let mut commit_root = [0u8; 32];
        commit_root.copy_from_slice(&record[2..34]);
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&record[34..66]);
        Ok(Some(Roots {
            commit_root,
            state_root,
        }))
    }
}

/// Encodes one `u32 header len || header || u32 certificate len || certificate`.
fn encode_header_record(header: &Header, certificate: &Certificate) -> Result<Vec<u8>, StoreError> {
    let header = header.encode()?;
    let certificate = certificate.encode()?;
    let mut record = Vec::with_capacity(8 + header.len() + certificate.len());
    let header_len = u32::try_from(header.len()).map_err(|_| {
        StoreError::Decode(CryptoError::new(
            crypto::CryptoErrorKind::FieldTooLong,
            "header does not fit a u32 length",
        ))
    })?;
    let certificate_len = u32::try_from(certificate.len()).map_err(|_| {
        StoreError::Decode(CryptoError::new(
            crypto::CryptoErrorKind::FieldTooLong,
            "certificate does not fit a u32 length",
        ))
    })?;
    record.extend_from_slice(&header_len.to_le_bytes());
    record.extend_from_slice(&header);
    record.extend_from_slice(&certificate_len.to_le_bytes());
    record.extend_from_slice(&certificate);
    Ok(record)
}

/// Decodes one `u32 header len || header || u32 certificate len || certificate`.
fn decode_header_record(bytes: &[u8]) -> Result<CertifiedHeader, CryptoError> {
    if bytes.len() < 8 {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            "header record is shorter than its two length fields",
        ));
    }
    let header_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let certificate_start: usize = 4;
    let Some(certificate_length_start) = certificate_start.checked_add(header_len) else {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            "header length overflows",
        ));
    };
    if certificate_length_start + 4 > bytes.len() {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            "header body is shorter than its length field",
        ));
    }
    let certificate_len = u32::from_le_bytes([
        bytes[certificate_length_start],
        bytes[certificate_length_start + 1],
        bytes[certificate_length_start + 2],
        bytes[certificate_length_start + 3],
    ]) as usize;
    let certificate_start = certificate_length_start + 4;
    let Some(certificate_end) = certificate_start.checked_add(certificate_len) else {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            "certificate length overflows",
        ));
    };
    if certificate_end > bytes.len() {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            "certificate body is shorter than its length field",
        ));
    }
    Ok(CertifiedHeader {
        header: Header::decode(&bytes[4..certificate_length_start])?,
        certificate: Certificate::decode(&bytes[certificate_start..certificate_end])?,
    })
}

/// Decodes the `u32 count || ids` part of a live snapshot order.
fn decode_live_order(
    decoder: &mut Decoder<'_>,
    record_len: usize,
) -> Result<Vec<VertexId>, StoreError> {
    let count = decoder.read_u32()? as usize;
    if count > record_len {
        return Err(StoreError::Decode(CryptoError::new(
            crypto::CryptoErrorKind::FieldTooLong,
            "live snapshot order count exceeds the record",
        )));
    }
    let mut order = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let round = decoder.read_u64()?;
        let author = decoder.read_bytes()?.to_vec();
        let digest: [u8; 32] = decoder.read_bytes()?.try_into().map_err(|_| {
            StoreError::Decode(CryptoError::new(
                crypto::CryptoErrorKind::TruncatedInput,
                "live snapshot order digest is not 32 bytes",
            ))
        })?;
        order.push(VertexId {
            round,
            author,
            digest,
        });
    }
    Ok(order)
}

const LOG_FILES: &[&str] = &[
    VERTICES_FILE,
    BATCHES_FILE,
    SHARDS_FILE,
    HEADERS_FILE,
    FENCES_FILE,
    ROUND_SKIPS_FILE,
    FENCE_SHARES_FILE,
    CLOCK_FILE,
];
const LEGACY_FILES: &[&str] = &[
    ROOTS_FILE,
    VERTICES_FILE,
    BATCHES_FILE,
    SNAPSHOT_FILE,
    SHARDS_FILE,
    SET_CHANGE_FILE,
    FENCES_FILE,
    ROUND_SKIPS_FILE,
    FENCE_SHARES_FILE,
    FENCE_FILE,
    GENESIS_FILE,
    GENESIS_HEADER_FILE,
    GENESIS_STATE_FILE,
    HEADERS_FILE,
    CLOCK_FILE,
    LIVE_SNAPSHOT_FILE,
];

fn invalid_layout(message: &str) -> StoreError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

fn generation_name(name: &str) -> bool {
    name.strip_prefix("generation-")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn validate_pointer_file(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(invalid_layout("pointer is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_generation(path: &Path) -> Result<(), StoreError> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(invalid_layout("generation is not a directory"));
    }
    for entry in fs::read_dir(path)? {
        if !entry?.file_type()?.is_file() {
            return Err(invalid_layout("generation contains a non-regular file"));
        }
    }
    Ok(())
}

fn remove_generation(path: &Path) -> Result<(), StoreError> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(invalid_layout("generation is not a directory"));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_generation(&entry.path())?;
        } else {
            // Unlink symlinks themselves; never traverse their targets.
            fs::remove_file(entry.path())?;
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn cleanup_generations(root: &Path, active: Option<&str>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if generation_name(name) && Some(name) != active {
            let _ = remove_generation(&entry.path());
        } else if active.is_some()
            && LEGACY_FILES.contains(&name)
            && entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn directory_bytes(path: &Path) -> Result<u64, StoreError> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        } else if kind.is_dir() {
            total = total.saturating_add(directory_bytes(&entry.path())?);
        }
    }
    Ok(total)
}

fn trim_torn_tail(path: &Path) -> Result<(), StoreError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut cursor = 0usize;
    while bytes.len() - cursor >= 4 {
        let length = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("four-byte length"),
        ) as usize;
        let Some(end) = (cursor + 4).checked_add(length) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(cursor as u64)?;
    }
    Ok(())
}

fn rewrite(path: &Path, contents: &[u8]) -> Result<(), StoreError> {
    let temporary = path.with_extension("tmp");
    {
        let mut file = File::create(&temporary)?;
        file.write_all(contents)?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}

fn append_record(path: &Path, payload: &[u8]) -> Result<(), StoreError> {
    let length = u32::try_from(payload.len()).map_err(|_| {
        StoreError::Decode(CryptoError::new(
            crypto::CryptoErrorKind::FieldTooLong,
            "record does not fit a u32 length",
        ))
    })?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&length.to_le_bytes())?;
    file.write_all(payload)?;
    Ok(())
}

/// Decodes one `(round, unix seconds)` clock record.
fn clock_record(bytes: &[u8]) -> Result<(u64, u64), CryptoError> {
    if bytes.len() != 16 {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::TruncatedInput,
            format!("clock record is {} bytes, expected 16", bytes.len()),
        ));
    }
    let mut round = [0u8; 8];
    round.copy_from_slice(&bytes[..8]);
    let mut at = [0u8; 8];
    at.copy_from_slice(&bytes[8..]);
    Ok((u64::from_le_bytes(round), u64::from_le_bytes(at)))
}

/// Reads length-prefixed records, ignoring a torn tail.
fn read_records<T>(
    path: &Path,
    decode: impl Fn(&[u8]) -> Result<T, CryptoError>,
) -> Result<Vec<T>, StoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;

    let mut records = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let length = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        let start = cursor + 4;
        // A record the writer never finished is a torn tail, not corruption.
        let Some(end) = start.checked_add(length) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        records.push(decode(&bytes[start..end])?);
        cursor = end;
    }
    Ok(records)
}

/// One record in the local fence-share log.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FenceShareRecord {
    /// A share this node signed for a proposed fence.
    Signed(FenceCertificate),
    /// A tombstone for a proposal the node abandoned.
    Cleared(Vec<u8>),
}

fn encode_fence_share(record: &FenceShareRecord) -> Result<Vec<u8>, StoreError> {
    let mut encoder = Encoder::with_capacity(64);
    encoder.put_u16(FENCE_SHARES_VERSION);
    match record {
        FenceShareRecord::Signed(certificate) => {
            encoder.put_u8(FENCE_SHARE_SIGNED);
            encoder.put_bytes(&certificate.encode()?)?;
        }
        FenceShareRecord::Cleared(validator) => {
            encoder.put_u8(FENCE_SHARE_CLEARED);
            encoder.put_bytes(validator)?;
        }
    }
    Ok(encoder.finish())
}

fn decode_fence_share(bytes: &[u8]) -> Result<FenceShareRecord, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u16()?;
    if version != FENCE_SHARES_VERSION {
        return Err(CryptoError::new(
            crypto::CryptoErrorKind::MalformedCertificate,
            format!("unsupported fence share version {version}"),
        ));
    }
    let record = match decoder.read_u8()? {
        FENCE_SHARE_SIGNED => {
            FenceShareRecord::Signed(FenceCertificate::decode(decoder.read_bytes()?)?)
        }
        FENCE_SHARE_CLEARED => FenceShareRecord::Cleared(decoder.read_bytes()?.to_vec()),
        other => {
            return Err(CryptoError::new(
                crypto::CryptoErrorKind::MalformedCertificate,
                format!("unknown fence share record {other}"),
            ));
        }
    };
    decoder.finish()?;
    Ok(record)
}

/// Reduces a fence log to one certificate per validator, keeping the lowest
/// starting round (the promise the DAG enforces).
fn lowest_fences(records: Vec<FenceCertificate>) -> Vec<FenceCertificate> {
    let mut by_validator: BTreeMap<Vec<u8>, FenceCertificate> = BTreeMap::new();
    for certificate in records {
        let validator = certificate.fence.validator_id.clone();
        match by_validator.get(&validator) {
            Some(existing) if existing.fence.from_round <= certificate.fence.from_round => {}
            _ => {
                by_validator.insert(validator, certificate);
            }
        }
    }
    by_validator.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::registry::ALG_ED25519;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
    use validator::{
        Fence, FenceCertificate, NO_EXPIRY, NoVoteAttestation, RoundSkip, RoundSkipProof,
        SetChange, ValidatorKey, ValidatorRecord, ValidatorSet, VertexId,
    };

    fn slot_decision(round: u64) -> validator::SlotDecision {
        validator::SlotDecision {
            chain_id: b"chain".to_vec(),
            validator_set_id: [1; 32],
            epoch: 0,
            round,
            previous: [0; 32],
            before_len: 0,
            before_root: [0; 32],
            after_len: 0,
            after_root: [0; 32],
            outcome: validator::SlotOutcome::Skip {
                leader_author: b"leader".to_vec(),
            },
        }
    }

    // Inactive primitive harness only: these helpers are not live consensus wiring.
    fn slot_decision_signing_fixture() -> (ValidatorSet, Vec<Vec<u8>>, [validator::SlotDecision; 2])
    {
        use crypto::scheme::Ed25519Scheme;
        let mut keys = Vec::new();
        let validators = (0..4u8)
            .map(|index| {
                let seed = [index + 1; 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public.as_slice()].concat());
                ValidatorRecord {
                    validator_id: vec![index],
                    keys: vec![ValidatorKey {
                        key_id: vec![index],
                        algorithm_id: ALG_ED25519,
                        public_key: public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: NO_EXPIRY,
                    }],
                }
            })
            .collect();
        let set = ValidatorSet {
            epoch: 2,
            validators,
        };
        set.validate().unwrap();
        assert_eq!(set.quorum_size(), 3);
        assert_eq!(set.max_faulty(), 1);
        let mut commit = slot_decision(7);
        commit.validator_set_id = set.id().unwrap();
        commit.epoch = set.epoch;
        commit.previous = [1; 32];
        commit.before_len = 3;
        commit.before_root = [2; 32];
        commit.after_len = 4;
        commit.after_root = [3; 32];
        commit.outcome = validator::SlotOutcome::Commit {
            leader: VertexId {
                round: 7,
                author: vec![0],
                digest: [4; 32],
            },
        };
        let mut skip = commit.clone();
        skip.after_len = skip.before_len;
        skip.after_root = skip.before_root;
        skip.outcome = validator::SlotOutcome::Skip {
            leader_author: vec![0],
        };
        commit.validate(&set).unwrap();
        skip.validate(&set).unwrap();
        assert_ne!(commit.id().unwrap(), skip.id().unwrap());
        (set, keys, [commit, skip])
    }

    fn slot_decision_raw_signature(
        decision: &validator::SlotDecision,
        set: &ValidatorSet,
        keys: &[Vec<u8>],
        index: usize,
    ) -> validator::ValidatorSignature {
        use crypto::scheme::Ed25519Scheme;
        let record = &set.validators[index];
        validator::ValidatorSignature {
            validator_id: record.validator_id.clone(),
            key_id: record.keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&keys[index], &decision.signing_payload().unwrap())
                .unwrap(),
        }
    }

    fn slot_decision_validate_lock_then_sign(
        store: &Store,
        decision: &validator::SlotDecision,
        set: &ValidatorSet,
        keys: &[Vec<u8>],
        index: usize,
    ) -> Result<validator::ValidatorSignature, StoreError> {
        decision.validate(set)?;
        store.lock_slot_decision(decision)?;
        Ok(slot_decision_raw_signature(decision, set, keys, index))
    }

    #[test]
    fn slot_decision_cross_layer_all_first_votes_prevent_conflicting_quorums() {
        let (set, keys, decisions) = slot_decision_signing_fixture();
        // All 16 first-vote assignments for four initially store-backed voters.
        // Index 3 subsequently becomes Byzantine and bypasses its store entirely.
        for pattern in 0..16usize {
            let directories: Vec<_> = (0..4).map(|_| TempDir::new()).collect();
            let mut certificates =
                decisions
                    .clone()
                    .map(|decision| validator::SlotDecisionCertificate {
                        decision,
                        signatures: Vec::new(),
                    });
            for (index, directory) in directories.iter().enumerate() {
                let choice = (pattern >> index) & 1;
                let store = Store::open(&directory.0).unwrap();
                let signature = slot_decision_validate_lock_then_sign(
                    &store,
                    &decisions[choice],
                    &set,
                    &keys,
                    index,
                )
                .unwrap();
                certificates[choice].signatures.push(signature);
                drop(store);
                if index < 3 {
                    let reopened = Store::open(&directory.0).unwrap();
                    assert!(
                        slot_decision_validate_lock_then_sign(
                            &reopened,
                            &decisions[1 - choice],
                            &set,
                            &keys,
                            index,
                        )
                        .is_err(),
                        "pattern {pattern:04b}, honest validator {index} must not double sign after reopen"
                    );
                    assert_eq!(
                        reopened.slot_decision_locks().unwrap(),
                        vec![decisions[choice].clone()]
                    );
                    // Exact retries remain usable, not just conflict-rejecting.
                    let retry = slot_decision_validate_lock_then_sign(
                        &reopened,
                        &decisions[choice],
                        &set,
                        &keys,
                        index,
                    )
                    .unwrap();
                    assert_eq!(
                        retry,
                        certificates[choice].signatures.last().unwrap().clone()
                    );
                }
            }
            let byzantine_choice = (pattern >> 3) & 1;
            certificates[1 - byzantine_choice]
                .signatures
                .push(slot_decision_raw_signature(
                    &decisions[1 - byzantine_choice],
                    &set,
                    &keys,
                    3,
                ));
            let valid = certificates.each_ref().map(|certificate| {
                let verified = certificate
                    .verify(&certificate.decision.chain_id, &set)
                    .is_ok();
                assert_eq!(
                    verified,
                    certificate.signatures.len() >= 3,
                    "pattern {pattern:04b}"
                );
                verified
            });
            assert!(
                !(valid[0] && valid[1]),
                "conflicting QCs for pattern {pattern:04b}"
            );
            // With the Byzantine signature on both sides, the honest majority
            // always completes exactly one QC: avoid a vacuous all-invalid test.
            assert!(valid[0] || valid[1], "no QC for pattern {pattern:04b}");
        }
    }

    #[test]
    fn slot_decision_cross_layer_split_honest_votes_and_withholding_stall() {
        let (set, keys, decisions) = slot_decision_signing_fixture();
        // Exercise every 2+1 honest split; the fourth independent store belongs
        // to a withholding Byzantine voter. This demonstrates lack of liveness,
        // not an unlock rule or an active live consensus fix.
        for pattern in 1..7usize {
            let directories: Vec<_> = (0..4).map(|_| TempDir::new()).collect();
            let mut certificates =
                decisions
                    .clone()
                    .map(|decision| validator::SlotDecisionCertificate {
                        decision,
                        signatures: Vec::new(),
                    });
            for (index, directory) in directories.iter().enumerate() {
                let store = Store::open(&directory.0).unwrap();
                if index == 3 {
                    assert!(store.slot_decision_locks().unwrap().is_empty());
                    continue;
                }
                let choice = (pattern >> index) & 1;
                certificates[choice].signatures.push(
                    slot_decision_validate_lock_then_sign(
                        &store,
                        &decisions[choice],
                        &set,
                        &keys,
                        index,
                    )
                    .unwrap(),
                );
                drop(store);
                let reopened = Store::open(&directory.0).unwrap();
                assert!(
                    slot_decision_validate_lock_then_sign(
                        &reopened,
                        &decisions[1 - choice],
                        &set,
                        &keys,
                        index,
                    )
                    .is_err()
                );
            }
            let mut counts = certificates
                .each_ref()
                .map(|certificate| certificate.signatures.len());
            counts.sort();
            assert_eq!(counts, [1, 2], "pattern {pattern:03b}");
            for certificate in certificates {
                assert!(
                    certificate
                        .verify(&certificate.decision.chain_id, &set)
                        .is_err(),
                    "withholding must prevent either QC for pattern {pattern:03b}"
                );
            }
        }
    }

    #[test]
    fn slot_decision_reopen_conflicts_and_independent_keys() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let decision = slot_decision(1);
        store.lock_slot_decision(&decision).unwrap();
        let bytes = fs::read(dir.0.join(slot_decision_journal::FILE)).unwrap();
        store.lock_slot_decision(&decision).unwrap();
        assert_eq!(
            fs::read(dir.0.join(slot_decision_journal::FILE)).unwrap(),
            bytes
        );
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        for variant in 0..4 {
            let mut conflict = decision.clone();
            match variant {
                0 => conflict.previous = [9; 32],
                1 => conflict.validator_set_id = [9; 32],
                2 => conflict.epoch += 1,
                _ => {
                    conflict.outcome = validator::SlotOutcome::Skip {
                        leader_author: b"other".to_vec(),
                    }
                }
            }
            assert!(store.lock_slot_decision(&conflict).is_err());
        }
        store.lock_slot_decision(&slot_decision(2)).unwrap();
        let mut other_chain = decision.clone();
        other_chain.chain_id = b"other".to_vec();
        store.lock_slot_decision(&other_chain).unwrap();
        assert_eq!(store.slot_decision_locks().unwrap().len(), 3);
    }

    #[test]
    fn slot_decision_torn_and_corrupt_fail_closed() {
        for tail in [vec![1], vec![9, 0, 0, 0, 1], vec![0, 0, 0, 0]] {
            let dir = TempDir::new();
            let store = Store::open(&dir.0).unwrap();
            store.lock_slot_decision(&slot_decision(1)).unwrap();
            let path = dir.0.join(slot_decision_journal::FILE);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&tail)
                .unwrap();
            let damaged = fs::read(&path).unwrap();
            assert!(store.slot_decision_locks().is_err());
            assert!(store.lock_slot_decision(&slot_decision(1)).is_err());
            assert!(store.lock_slot_decision(&slot_decision(2)).is_err());
            assert_eq!(fs::read(&path).unwrap(), damaged);
            drop(store);
            assert!(Store::open(&dir.0).is_err());
        }
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.lock_slot_decision(&slot_decision(1)).unwrap();
        let path = dir.0.join(slot_decision_journal::FILE);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(store.slot_decision_locks().is_err());
        drop(store);
        assert!(Store::open(&dir.0).is_err());
    }

    #[test]
    fn slot_decision_stage_and_prune_preserve_promises() {
        let dir = TempDir::new();
        let mut store = Store::open(&dir.0).unwrap();
        store.lock_slot_decision(&slot_decision(1)).unwrap();
        {
            let stage = store.stage().unwrap();
            assert!(
                !stage
                    .store()
                    .path()
                    .join(slot_decision_journal::FILE)
                    .exists()
            );
            stage.store().lock_slot_decision(&slot_decision(2)).unwrap();
        }
        let stage = store.stage().unwrap();
        stage.store().lock_slot_decision(&slot_decision(3)).unwrap();
        stage.activate().unwrap();
        store.prune_below(100, 1).unwrap();
        assert_eq!(store.slot_decision_locks().unwrap().len(), 3);
        drop(store);
        assert_eq!(
            Store::open(&dir.0)
                .unwrap()
                .slot_decision_locks()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn slot_decision_clone_conflicts_serialize() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|epoch| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut decision = slot_decision(1);
                    decision.epoch = epoch;
                    barrier.wait();
                    store.lock_slot_decision(&decision).is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .filter_map(|h| h.join().unwrap().then_some(()))
                .count(),
            1
        );
        assert_eq!(store.slot_decision_locks().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn slot_decision_symlink_rejected() {
        let dir = TempDir::new();
        let target = dir.0.join("target");
        fs::write(&target, b"untouched").unwrap();
        let store = Store::open(&dir.0).unwrap();
        std::os::unix::fs::symlink(&target, dir.0.join(slot_decision_journal::FILE)).unwrap();
        assert!(store.slot_decision_locks().is_err());
        assert!(store.lock_slot_decision(&slot_decision(1)).is_err());
        drop(store);
        assert!(Store::open(&dir.0).is_err());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }

    #[test]
    fn staged_generations_publish_and_clones_follow() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        owner.put_batch(&batch(1)).unwrap();
        let logical = owner.path().to_path_buf();
        {
            let stage = owner.stage().unwrap();
            stage.store().put_batch(&batch(2)).unwrap();
            assert_eq!(fs::read_dir(&logical).unwrap().count(), 3);
            let stage_path = stage.store().path().to_path_buf();
            assert!(Store::open(&logical).is_err());
            assert!(
                stage_path.is_dir(),
                "failed second open must not clean a live stage"
            );
            assert!(!stage_path.join(".lock").exists());
        }
        // An abandoned generation as left by process loss, without leaking a lock FD.
        fs::create_dir(logical.join("generation-888")).unwrap();
        fs::copy(
            owner.path_of(BATCHES_FILE),
            logical.join("generation-888/batches.log"),
        )
        .unwrap();
        drop(owner);
        let mut owner = Store::open(&logical).unwrap();
        assert!(!logical.join("generation-888").exists());
        assert_eq!(owner.batches().unwrap().len(), 1);
        let stage = owner.stage().unwrap();
        stage.store().put_batch(&batch(2)).unwrap();
        stage.activate().unwrap();
        assert!(Store::open(&logical).is_err());
        assert_eq!(owner.batches().unwrap().len(), 2);
        // A clone of this owner shares routing, unlike independently opened handles.
        let clone = owner.clone();
        let stage = owner.stage().unwrap();
        stage.store().put_batch(&batch(3)).unwrap();
        stage.activate().unwrap();
        assert_eq!(clone.batches().unwrap().len(), 3);
        assert_eq!(owner.path(), logical);
        assert_eq!(
            owner.disk_bytes().unwrap(),
            directory_bytes(&logical).unwrap()
        );
        assert_eq!(
            fs::read_dir(&logical)
                .unwrap()
                .filter(|e| generation_name(e.as_ref().unwrap().file_name().to_str().unwrap()))
                .count(),
            1
        );
        drop(clone);
    }

    #[test]
    fn staged_drop_and_failed_write_leave_old_store_untouched() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        owner.put_batch(&batch(1)).unwrap();
        {
            let stage = owner.stage().unwrap();
            fs::create_dir(stage.store().path_of(ROOTS_FILE)).unwrap();
            assert!(
                stage
                    .store()
                    .put_roots(Roots {
                        commit_root: [1; 32],
                        state_root: [2; 32]
                    })
                    .is_err()
            );
        }
        assert!(owner.roots().unwrap().is_none());
        drop(owner);
        assert_eq!(Store::open(&dir.0).unwrap().batches().unwrap().len(), 1);
    }

    #[test]
    fn staged_torn_tail_is_trimmed_before_append() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        owner.put_batch(&batch(1)).unwrap();
        OpenOptions::new()
            .append(true)
            .open(owner.path_of(BATCHES_FILE))
            .unwrap()
            .write_all(&[255, 255])
            .unwrap();
        let original = fs::read(owner.path_of(BATCHES_FILE)).unwrap();
        let stage = owner.stage().unwrap();
        stage.store().put_batch(&batch(2)).unwrap();
        assert_eq!(stage.store().batches().unwrap().len(), 2);
        stage.activate().unwrap();
        assert_eq!(owner.batches().unwrap().len(), 2);
        assert!(original.ends_with(&[255, 255]));
    }

    #[test]
    fn invalid_current_never_falls_back() {
        for pointer in [
            "",
            "../generation-1",
            "generation-1/",
            "generation-1\n",
            "generation-999",
        ] {
            let dir = TempDir::new();
            fs::write(dir.0.join("CURRENT"), pointer).unwrap();
            assert!(Store::open(&dir.0).is_err(), "pointer {pointer:?}");
        }
    }

    #[test]
    fn staged_snapshot_and_vertex_cuts_preserve_auxiliary_records() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        let old = live_snapshot_fixture();
        let mut new = old.clone();
        new.round += 10;
        new.state = b"new encoded state".to_vec();
        let first = vertex(1, &batch(1));
        let second = vertex(2, &batch(2));
        owner.put_live_snapshot(&old).unwrap();
        owner.append_vertex(&first).unwrap();
        owner.bind_genesis(&[42; 32]).unwrap();
        owner.put_shard(&[7; 32], 2, b"shard bytes").unwrap();
        owner.put_fence_share(&fence_certificate()).unwrap();
        owner.clear_fence_share(b"val-0").unwrap();
        owner.record_clock(1, 1234).unwrap();
        let preserved: Vec<_> = [GENESIS_FILE, SHARDS_FILE, FENCE_SHARES_FILE, CLOCK_FILE]
            .iter()
            .map(|name| (*name, fs::read(owner.path_of(name)).unwrap()))
            .collect();
        let clone = owner.clone();
        let old_snapshot_bytes = fs::read(owner.path_of(LIVE_SNAPSHOT_FILE)).unwrap();
        {
            let stage = owner.stage().unwrap();
            stage.store().put_live_snapshot(&new).unwrap();
            stage.store().append_vertex(&second).unwrap();
            assert_eq!(stage.store().live_snapshot().unwrap(), Some(new.clone()));
            assert_eq!(
                stage.store().vertices().unwrap(),
                vec![first.clone(), second.clone()]
            );
            // Inspect the logical root without opening a second cleanup-capable handle.
            assert!(!dir.0.join("CURRENT").exists());
            assert_eq!(
                fs::read(dir.0.join(LIVE_SNAPSHOT_FILE)).unwrap(),
                old_snapshot_bytes
            );
        }
        assert!(Store::open(&dir.0).is_err());
        assert_eq!(owner.live_snapshot().unwrap(), Some(old.clone()));
        assert_eq!(owner.vertices().unwrap(), vec![first.clone()]);
        let stage = owner.stage().unwrap();
        stage.store().put_live_snapshot(&new).unwrap();
        stage.store().append_vertex(&second).unwrap();
        stage.activate().unwrap();
        assert_eq!(clone.live_snapshot().unwrap(), Some(new.clone()));
        assert_eq!(
            clone.vertices().unwrap(),
            vec![first.clone(), second.clone()]
        );
        drop(clone);
        drop(owner);
        let reopened = Store::open(&dir.0).unwrap();
        assert_eq!(reopened.live_snapshot().unwrap(), Some(new));
        assert_eq!(reopened.vertices().unwrap(), vec![first, second]);
        assert_eq!(reopened.genesis().unwrap(), Some([42; 32]));
        assert_eq!(reopened.shards().unwrap()[0].bytes, b"shard bytes");
        assert!(reopened.fence_shares().unwrap().is_empty());
        for (name, bytes) in preserved {
            assert_eq!(
                fs::read(reopened.path_of(name)).unwrap(),
                bytes,
                "preserve {name} verbatim"
            );
        }
    }

    #[test]
    fn complete_corrupt_log_rejects_stage_without_changing_active() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        owner.put_live_snapshot(&live_snapshot_fixture()).unwrap();
        owner.append_vertex(&vertex(1, &batch(1))).unwrap();
        append_record(&owner.path_of(VERTICES_FILE), b"invalid complete vertex").unwrap();
        let before = fs::read(owner.path_of(VERTICES_FILE)).unwrap();
        assert!(matches!(owner.stage(), Err(StoreError::Decode(_))));
        assert_eq!(fs::read(owner.path_of(VERTICES_FILE)).unwrap(), before);
        assert_eq!(
            owner.live_snapshot().unwrap(),
            Some(live_snapshot_fixture())
        );
        assert!(!dir.0.join("CURRENT").exists());
        assert!(
            !fs::read_dir(&dir.0)
                .unwrap()
                .any(|entry| generation_name(entry.unwrap().file_name().to_str().unwrap()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_pointers_and_generations_are_rejected_without_traversal() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        let outside = TempDir::new();
        fs::write(outside.0.join("pointer"), "generation-1").unwrap();
        fs::write(outside.0.join("keep"), b"untouched").unwrap();
        symlink(outside.0.join("pointer"), dir.0.join("CURRENT")).unwrap();
        assert!(Store::open(&dir.0).is_err());
        fs::remove_file(dir.0.join("CURRENT")).unwrap();
        symlink(&outside.0, dir.0.join("generation-1")).unwrap();
        fs::write(dir.0.join("CURRENT"), "generation-1").unwrap();
        assert!(Store::open(&dir.0).is_err());
        fs::remove_file(dir.0.join("generation-1")).unwrap();
        fs::create_dir(dir.0.join("generation-1")).unwrap();
        symlink(
            outside.0.join("keep"),
            dir.0.join("generation-1/vertices.log"),
        )
        .unwrap();
        assert!(Store::open(&dir.0).is_err());
        assert_eq!(fs::read(outside.0.join("keep")).unwrap(), b"untouched");
    }

    #[test]
    fn cleanup_failure_does_not_reject_publication_or_remove_unrelated_names() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        owner.put_live_snapshot(&live_snapshot_fixture()).unwrap();
        // An owned-looking regular file cannot be removed as a generation.
        fs::write(dir.0.join("generation-999"), b"cleanup obstacle").unwrap();
        fs::write(dir.0.join("notes"), b"keep file").unwrap();
        fs::create_dir(dir.0.join("generation-not-owned")).unwrap();
        fs::write(dir.0.join("generation-not-owned/keep"), b"keep directory").unwrap();
        let stage = owner.stage().unwrap();
        stage.store().append_vertex(&vertex(2, &batch(2))).unwrap();
        stage.activate().unwrap();
        drop(owner);
        let reopened = Store::open(&dir.0).unwrap();
        assert_eq!(reopened.vertices().unwrap().len(), 1);
        assert_eq!(
            reopened.live_snapshot().unwrap(),
            Some(live_snapshot_fixture())
        );
        assert_eq!(
            fs::read(dir.0.join("generation-999")).unwrap(),
            b"cleanup obstacle"
        );
        assert_eq!(fs::read(dir.0.join("notes")).unwrap(), b"keep file");
        assert_eq!(
            fs::read(dir.0.join("generation-not-owned/keep")).unwrap(),
            b"keep directory"
        );
    }

    #[test]
    fn published_generation_survives_poisoned_routing_lock() {
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        let stage = owner.stage().unwrap();
        stage
            .store()
            .put_live_snapshot(&live_snapshot_fixture())
            .unwrap();
        let active = Arc::clone(&stage.owner.active);
        let _ = std::thread::spawn(move || {
            let _guard = active.write().unwrap();
            panic!("poison routing lock for publication regression test");
        })
        .join();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.activate())).is_err()
        );
        drop(owner);
        assert_eq!(
            Store::open(&dir.0).unwrap().live_snapshot().unwrap(),
            Some(live_snapshot_fixture())
        );
    }

    #[test]
    fn clone_retains_exclusive_directory_lock() {
        let dir = TempDir::new();
        let owner = Store::open(&dir.0).unwrap();
        let clone = owner.clone();
        drop(owner);
        let error = Store::open(&dir.0).unwrap_err();
        assert!(matches!(&error, StoreError::Io(_)));
        assert!(error.to_string().contains(&dir.0.display().to_string()));
        assert!(error.to_string().contains("close other store handles"));
        drop(clone);
        let reopened = Store::open(&dir.0).unwrap();
        assert!(dir.0.join(".lock").is_file());
        drop(reopened);
        assert!(dir.0.join(".lock").is_file(), "never unlink the lock inode");
    }

    #[test]
    fn exclusive_lock_excludes_subprocess() {
        const CHILD_ROOT: &str = "KARSA_STORE_LOCK_TEST_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            assert!(matches!(
                Store::open(PathBuf::from(root)),
                Err(StoreError::Io(_))
            ));
            return;
        }
        let dir = TempDir::new();
        let mut owner = Store::open(&dir.0).unwrap();
        let stage = owner.stage().unwrap();
        let staged_path = stage.store().path().to_path_buf();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::exclusive_lock_excludes_subprocess",
                "--nocapture",
            ])
            .env(CHILD_ROOT, &dir.0)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("lock subprocess exceeded 15 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(staged_path.is_dir());
        stage.activate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        let outside = TempDir::new();
        let target = outside.0.join("keep");
        fs::write(&target, b"do not truncate").unwrap();
        symlink(&target, dir.0.join(".lock")).unwrap();
        assert!(Store::open(&dir.0).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do not truncate");
        fs::remove_file(dir.0.join(".lock")).unwrap();
        fs::create_dir(dir.0.join(".lock")).unwrap();
        assert!(Store::open(&dir.0).is_err());
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A per-test directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("karsa-store-{}-{unique}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn transition_certificate() -> TransitionCertificate {
        let set = |epoch: u64, count: usize| ValidatorSet {
            epoch,
            validators: (0..count)
                .map(|index| ValidatorRecord {
                    validator_id: format!("val-{index}").into_bytes(),
                    keys: vec![ValidatorKey {
                        key_id: format!("val-{index}-k0").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: vec![u8::try_from(index + 1).unwrap(); 32],
                        activation_epoch: 0,
                        retirement_epoch: NO_EXPIRY,
                    }],
                })
                .collect(),
        };
        let old = set(1, 1);
        let new = set(2, 2);
        let change = SetChange::new(b"karsa-store-1".to_vec(), &old, &new).unwrap();
        TransitionCertificate {
            change,
            new_set: new,
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        }
    }

    fn fence_certificate() -> FenceCertificate {
        FenceCertificate {
            fence: Fence::new(b"karsa-store-1".to_vec(), 7, b"val-0".to_vec()),
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        }
    }

    fn batch(sequence: u64) -> Batch {
        Batch::new(vec![Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: b"karsa-store-1".to_vec(),
            sender: b"alice".to_vec(),
            sequence,
            fee: 1,
            expiration: 100,
            policy_version: 1,
            payload: vec![sequence as u8],
            authorization: Vec::new(),
        }])
    }

    #[test]
    fn an_empty_store_reads_back_empty() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.vertices().unwrap().is_empty());
        assert!(store.batches().unwrap().is_empty());
        assert_eq!(store.roots().unwrap(), None);
    }

    #[test]
    fn batches_round_trip_and_deduplicate() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.put_batch(&batch(1)).unwrap();
        store.put_batch(&batch(2)).unwrap();
        store.put_batch(&batch(1)).unwrap();

        let read = store.batches().unwrap();
        assert_eq!(read.len(), 2, "the repeated batch is stored once");
        assert_eq!(read[0], batch(1));
        assert_eq!(read[1], batch(2));
    }

    #[test]
    fn appended_data_survives_reopening() {
        let dir = TempDir::new();
        {
            let store = Store::open(&dir.0).unwrap();
            store.put_batch(&batch(7)).unwrap();
            store
                .put_roots(Roots {
                    commit_root: [1u8; 32],
                    state_root: [2u8; 32],
                })
                .unwrap();
        }

        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.batches().unwrap(), vec![batch(7)]);
        assert_eq!(
            store.roots().unwrap(),
            Some(Roots {
                commit_root: [1u8; 32],
                state_root: [2u8; 32],
            })
        );
    }

    #[test]
    fn a_torn_tail_is_ignored_not_reported() {
        let dir = TempDir::new();
        {
            let store = Store::open(&dir.0).unwrap();
            store.put_batch(&batch(1)).unwrap();
            store.put_batch(&batch(2)).unwrap();
        }

        // Cut the last record in half, as a crash mid-append would.
        let path = dir.0.join(BATCHES_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 3);
        fs::write(&path, &bytes).unwrap();

        let store = Store::open(&dir.0).unwrap();
        assert_eq!(
            store.batches().unwrap(),
            vec![batch(1)],
            "the incomplete record is invisible and the rest survives"
        );
    }

    #[test]
    fn a_complete_but_corrupt_record_is_an_error() {
        let dir = TempDir::new();
        {
            let store = Store::open(&dir.0).unwrap();
            store.put_batch(&batch(1)).unwrap();
        }

        let path = dir.0.join(BATCHES_FILE);
        let mut bytes = fs::read(&path).unwrap();
        // Flip a payload byte, keeping the record's length intact.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();

        let store = Store::open(&dir.0).unwrap();
        assert!(matches!(store.batches(), Err(StoreError::Decode(_))));
    }

    #[test]
    fn a_snapshot_round_trips() {
        let dir = TempDir::new();
        {
            let store = Store::open(&dir.0).unwrap();
            store.put_snapshot(4, b"encoded state").unwrap();
        }
        let store = Store::open(&dir.0).unwrap();
        assert_eq!(
            store.snapshot().unwrap(),
            Some(Snapshot {
                round: 4,
                state: b"encoded state".to_vec(),
            })
        );
    }

    #[test]
    fn a_live_snapshot_round_trips() {
        let dir = TempDir::new();
        let snapshot = live_snapshot_fixture();
        {
            let store = Store::open(&dir.0).unwrap();
            store.put_live_snapshot(&snapshot).unwrap();
        }
        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.live_snapshot().unwrap(), Some(snapshot));
    }

    fn live_snapshot_fixture() -> LiveSnapshot {
        let header = Header::genesis(b"karsa-store-1".to_vec(), 0, [1; 32], [2; 32]);
        let first = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [3; 32],
        };
        let second = VertexId {
            round: 2,
            author: b"val-1".to_vec(),
            digest: [4; 32],
        };
        LiveSnapshot {
            round: 7,
            floor: Some(5),
            cursor: 8,
            applied: 3,
            state: b"encoded state".to_vec(),
            order: vec![second.clone()],
            order_len: 2,
            prefix: CommitFrontier::from_order(&[first]),
            header: header.clone(),
            certificate: Certificate {
                chain_id: header.chain_id.clone(),
                epoch: 0,
                round: 0,
                vertex_id: header.id().unwrap().to_vec(),
                validator_set_id: b"set".to_vec(),
                signer_bitmap: vec![0b1],
                signatures: vec![vec![9u8; 64]],
            },
            transition: Some(transition_certificate()),
            fences: vec![fence_certificate()],
        }
    }

    #[test]
    fn a_version_three_live_snapshot_keeps_its_transition_and_has_no_fences() {
        let dir = TempDir::new();
        let header = Header::genesis(b"karsa-store-1".to_vec(), 0, [1; 32], [2; 32]);
        let certificate = Certificate {
            chain_id: header.chain_id.clone(),
            epoch: 0,
            round: 0,
            vertex_id: header.id().unwrap().to_vec(),
            validator_set_id: b"set".to_vec(),
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        };
        let transition = transition_certificate();
        let mut encoder = Encoder::with_capacity(256);
        encoder.put_u16(LIVE_SNAPSHOT_VERSION_TRANSITION);
        encoder.put_u64(7);
        encoder.put_u8(0);
        encoder.put_u64(8);
        encoder.put_u64(3);
        encoder.put_bytes(b"encoded state").unwrap();
        encoder.put_u64(0);
        encoder.put_u64(0);
        encoder.put_u32(0);
        encoder.put_u32(0);
        encoder.put_bytes(&header.encode().unwrap()).unwrap();
        encoder.put_bytes(&certificate.encode().unwrap()).unwrap();
        encoder.put_u8(1);
        encoder.put_bytes(&transition.encode().unwrap()).unwrap();
        fs::write(dir.0.join(LIVE_SNAPSHOT_FILE), encoder.as_slice()).unwrap();

        let store = Store::open(&dir.0).unwrap();
        let read = store.live_snapshot().unwrap().unwrap();
        assert_eq!(read.transition, Some(transition));
        assert!(read.fences.is_empty());
    }

    fn round_skip_proof(round: u64, digest: u8) -> RoundSkipProof {
        let leader = VertexId {
            round,
            author: b"val-0".to_vec(),
            digest: [digest; 32],
        };
        RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(b"karsa-store-1".to_vec(), leader),
                signer_bitmap: vec![0u8; 1],
                signatures: Vec::new(),
            },
            votes: Vec::new(),
            non_votes: Vec::new(),
            fenced_absent: Vec::new(),
            missing: vec![b"val-1".to_vec()],
        }
    }

    #[test]
    fn round_skips_round_trip_and_keep_one_proof_per_round() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.round_skips().unwrap().is_empty());

        let proof = round_skip_proof(7, 1);
        store.put_round_skip(&proof).unwrap();
        store.put_round_skip(&proof).unwrap();
        assert_eq!(store.round_skips().unwrap(), vec![proof.clone()]);

        let later = round_skip_proof(9, 2);
        store.put_round_skip(&later).unwrap();
        let proofs = store.round_skips().unwrap();
        assert_eq!(proofs.len(), 2);
        assert!(proofs.contains(&later));

        // A second, different proof for the same round would name another leader.
        let conflicting = round_skip_proof(7, 3);
        assert!(store.put_round_skip(&conflicting).is_err());
    }

    #[test]
    fn fences_round_trip_and_keep_the_lowest_round() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.fences().unwrap().is_empty());
        let certificate = fence_certificate();
        store.put_fence(&certificate).unwrap();
        store.put_fence(&certificate).unwrap();
        assert_eq!(store.fences().unwrap(), vec![certificate.clone()]);

        let mut second = fence_certificate();
        second.fence.validator_id = b"val-1".to_vec();
        second.fence.from_round = 9;
        store.put_fence(&second).unwrap();
        let fences = store.fences().unwrap();
        assert_eq!(fences.len(), 2);
        assert!(fences.contains(&second));

        // A lower starting round is the stricter promise and replaces the entry.
        let mut lower = fence_certificate();
        lower.fence.from_round = 5;
        store.put_fence(&lower).unwrap();
        let fences = store.fences().unwrap();
        assert_eq!(fences.len(), 2);
        assert!(fences.iter().any(|fence| fence.fence.from_round == 5));
        assert!(fences.iter().all(|fence| fence.fence.from_round != 7));

        // A higher round is weaker, so it is ignored rather than appended forever.
        let mut higher = fence_certificate();
        higher.fence.from_round = 99;
        store.put_fence(&higher).unwrap();
        assert!(
            store
                .fences()
                .unwrap()
                .iter()
                .any(|fence| fence.fence.from_round == 5)
        );
    }

    #[test]
    fn a_legacy_single_fence_is_read() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let certificate = fence_certificate();
        fs::write(dir.0.join("fence"), certificate.encode().unwrap()).unwrap();
        assert_eq!(store.fences().unwrap(), vec![certificate.clone()]);

        // Appending a second validator must not hide the legacy record.
        let mut second = fence_certificate();
        second.fence.validator_id = b"val-1".to_vec();
        store.put_fence(&second).unwrap();
        let fences = store.fences().unwrap();
        assert_eq!(fences.len(), 2);
        assert!(fences.contains(&certificate));
        assert!(fences.contains(&second));
    }

    #[test]
    fn a_local_fence_share_round_trips_and_a_clear_removes_it() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.fence_shares().unwrap().is_empty());

        let certificate = fence_certificate();
        store.put_fence_share(&certificate).unwrap();
        store.put_fence_share(&certificate).unwrap();
        assert_eq!(store.fence_shares().unwrap(), vec![certificate.clone()]);

        // A lower starting round is the stricter promise and replaces the entry.
        let mut lower = fence_certificate();
        lower.fence.from_round = 5;
        store.put_fence_share(&lower).unwrap();
        assert_eq!(store.fence_shares().unwrap(), vec![lower.clone()]);

        // A higher one is weaker, so it is ignored rather than appended forever.
        let mut higher = fence_certificate();
        higher.fence.from_round = 99;
        store.put_fence_share(&higher).unwrap();
        assert_eq!(store.fence_shares().unwrap(), vec![lower.clone()]);

        let mut second = fence_certificate();
        second.fence.validator_id = b"val-1".to_vec();
        second.fence.from_round = 9;
        store.put_fence_share(&second).unwrap();
        assert_eq!(store.fence_shares().unwrap().len(), 2);

        store.clear_fence_share(b"val-0").unwrap();
        assert_eq!(store.fence_shares().unwrap(), vec![second.clone()]);

        // A later proposal for the same validator re-adds it after the tombstone.
        store.put_fence_share(&certificate).unwrap();
        assert_eq!(store.fence_shares().unwrap().len(), 2);
    }

    #[test]
    fn a_set_change_round_trips_and_cannot_be_replaced() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.set_change().unwrap(), None);
        let certificate = transition_certificate();
        store.put_set_change(&certificate).unwrap();
        store.put_set_change(&certificate).unwrap();
        assert_eq!(store.set_change().unwrap(), Some(certificate.clone()));

        let mut different = certificate;
        different.change.activation_epoch += 1;
        assert!(store.put_set_change(&different).is_err());
    }

    #[test]
    fn a_legacy_live_snapshot_is_read_as_a_full_order() {
        let dir = TempDir::new();
        let header = Header::genesis(b"karsa-store-1".to_vec(), 0, [1; 32], [2; 32]);
        let order = [
            VertexId {
                round: 1,
                author: b"val-0".to_vec(),
                digest: [3; 32],
            },
            VertexId {
                round: 2,
                author: b"val-1".to_vec(),
                digest: [4; 32],
            },
        ];
        let certificate = Certificate {
            chain_id: header.chain_id.clone(),
            epoch: 0,
            round: 0,
            vertex_id: header.id().unwrap().to_vec(),
            validator_set_id: b"set".to_vec(),
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        };
        let mut encoder = Encoder::with_capacity(256);
        encoder.put_u16(LIVE_SNAPSHOT_VERSION_FULL);
        encoder.put_u64(7);
        encoder.put_u8(1);
        encoder.put_u64(5);
        encoder.put_u64(8);
        encoder.put_u64(3);
        encoder.put_bytes(b"encoded state").unwrap();
        encoder.put_u32(2);
        for id in &order {
            encoder.put_u64(id.round);
            encoder.put_bytes(&id.author).unwrap();
            encoder.put_bytes(&id.digest).unwrap();
        }
        encoder.put_bytes(&header.encode().unwrap()).unwrap();
        encoder.put_bytes(&certificate.encode().unwrap()).unwrap();
        fs::write(dir.0.join(LIVE_SNAPSHOT_FILE), encoder.as_slice()).unwrap();

        let store = Store::open(&dir.0).unwrap();
        let read = store.live_snapshot().unwrap().unwrap();
        assert_eq!(read.order, order);
        assert_eq!(read.order_len, 2);
        assert!(read.prefix.is_empty());
    }

    fn vertex(round: u64, batch: &Batch) -> Vertex {
        // The store only encodes and decodes, so a placeholder signature is enough
        // here; verification is the DAG's job, not the store's.
        Vertex {
            chain_id: b"karsa-store-1".to_vec(),
            epoch: 1,
            round,
            author: b"val-0".to_vec(),
            payload_hash: batch.digest().unwrap(),
            references: Vec::new(),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn pruning_keeps_only_the_tail_and_the_batches_it_names() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        for round in 0..4u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
        }
        assert_eq!(store.vertices().unwrap().len(), 4);
        assert_eq!(store.batches().unwrap().len(), 4);

        let report = store.prune_below(1, 0).unwrap();
        assert_eq!(report.vertices, 2, "rounds 0 and 1 are dropped");
        assert_eq!(report.batches_dropped, 2, "nothing is kept in the tail");
        assert!(report.bytes_freed > 0);

        let kept: Vec<u64> = store
            .vertices()
            .unwrap()
            .iter()
            .map(|vertex| vertex.round)
            .collect();
        assert_eq!(kept, vec![2, 3]);

        let batches = store.batches().unwrap();
        assert_eq!(batches.len(), 2, "only named batches survive");
        assert_eq!(batches, vec![batch(3), batch(4)]);
    }

    #[test]
    fn shards_round_trip_and_the_last_write_wins() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let digest = [5u8; 32];
        store.put_shard(&digest, 0, b"first").unwrap();
        store.put_shard(&digest, 1, b"second").unwrap();
        store.put_shard(&digest, 0, b"replacement").unwrap();

        let shards = store.shards().unwrap();
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].bytes, b"replacement");
        assert_eq!(shards[1].bytes, b"second");
        assert_eq!(shards[0].digest, digest);
    }

    #[test]
    fn shards_survive_pruning_because_batches_do_not() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let payload = batch(1);
        let digest = payload.digest().unwrap();
        store.put_batch(&payload).unwrap();
        store.put_shard(&digest, 3, b"a shard").unwrap();
        store.append_vertex(&vertex(0, &payload)).unwrap();

        let report = store.prune_below(0, 1).unwrap();
        assert_eq!(report.batches_dropped, 1);
        assert!(store.batches().unwrap().is_empty(), "the batch is gone");
        assert_eq!(store.shards().unwrap().len(), 1, "the shard remains");
    }

    #[test]
    fn a_payload_without_a_shard_is_never_dropped() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let payload = batch(1);
        store.put_batch(&payload).unwrap();
        store.append_vertex(&vertex(0, &payload)).unwrap();

        // Simulate a node that is not part of the erasure set: it holds no shard,
        // so deleting this batch would destroy the only copy it knows about.
        let report = store.prune_below(0, 1).unwrap();
        assert_eq!(report.vertices, 1, "metadata still goes");
        assert_eq!(report.batches_dropped, 0);
        assert_eq!(report.batches_held, 1);
        assert_eq!(store.batches().unwrap(), vec![payload]);
    }

    #[test]
    fn a_checkpoint_prune_drops_everything_below_its_floor() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        for round in 0..6u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
            store
                .put_header(&header(round), &certificate(round))
                .unwrap();
        }
        store
            .put_live_snapshot(&LiveSnapshot {
                round: 4,
                floor: Some(3),
                cursor: 5,
                applied: 40,
                state: b"state".to_vec(),
                order: Vec::new(),
                order_len: 0,
                prefix: CommitFrontier::empty(),
                header: header(4),
                certificate: certificate(4),
                transition: None,
                fences: Vec::new(),
            })
            .unwrap();

        let report = store.prune_to_checkpoint(0).unwrap();
        assert_eq!(report.vertices, 4, "rounds 0 through 3 are covered");
        assert_eq!(report.headers, 4, "heights below the anchor are gone");
        assert!(report.bytes_freed > 0);

        let kept: Vec<u64> = store
            .vertices()
            .unwrap()
            .iter()
            .map(|vertex| vertex.round)
            .collect();
        assert_eq!(kept, vec![4, 5]);
        assert_eq!(
            store.batches().unwrap(),
            vec![batch(5), batch(6)],
            "only payloads a kept vertex names survive"
        );
        let heights: Vec<u64> = store
            .headers()
            .unwrap()
            .iter()
            .map(|record| record.header.height)
            .collect();
        assert_eq!(
            heights,
            vec![4, 5],
            "the anchor's own header stays so a restart and an audit see it"
        );
    }

    #[test]
    fn a_checkpoint_without_a_floor_drops_nothing() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        for round in 0..3u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
            store
                .put_header(&header(round), &certificate(round))
                .unwrap();
        }
        store
            .put_live_snapshot(&LiveSnapshot {
                round: 2,
                floor: None,
                cursor: 3,
                applied: 20,
                state: b"state".to_vec(),
                order: Vec::new(),
                order_len: 0,
                prefix: CommitFrontier::empty(),
                header: header(2),
                certificate: certificate(2),
                transition: None,
                fences: Vec::new(),
            })
            .unwrap();

        let report = store.prune_to_checkpoint(0).unwrap();
        assert_eq!(report, PruneReport::default());
        assert_eq!(store.vertices().unwrap().len(), 3);
        assert_eq!(store.headers().unwrap().len(), 3);
    }

    #[test]
    fn an_unsharded_payload_stays_inside_the_window() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let kept = batch(9);
        let digest = kept.digest().unwrap();
        store.put_batch(&kept).unwrap();
        store.put_shard(&digest, 0, b"a shard").unwrap();
        store.append_vertex(&vertex(5, &kept)).unwrap();

        // Pruning at round 4 leaves the vertex at round 5, so its payload is
        // inside the window even though a shard would allow dropping it.
        let report = store.prune_below(4, 1).unwrap();
        assert_eq!(report.batches_dropped, 0);
        assert_eq!(store.batches().unwrap(), vec![kept]);
    }

    fn header(height: u64) -> Header {
        Header {
            chain_id: b"karsa-store-1".to_vec(),
            epoch: 1,
            height,
            round: height,
            state_root: [u8::try_from(height).unwrap(); 32],
            dag_root: [7u8; 32],
            previous: [0u8; 32],
            applied: height * 10,
        }
    }

    fn certificate(height: u64) -> Certificate {
        Certificate {
            chain_id: b"karsa-store-1".to_vec(),
            epoch: 1,
            round: height,
            vertex_id: header(height).id().unwrap().to_vec(),
            validator_set_id: b"set".to_vec(),
            signer_bitmap: validator::bitmap_of(4, 3),
            signatures: vec![vec![0u8; 64]; 3],
        }
    }

    #[test]
    fn certified_headers_round_trip_and_the_last_write_per_height_wins() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.put_header(&header(1), &certificate(1)).unwrap();
        store.put_header(&header(2), &certificate(2)).unwrap();
        store.put_header(&header(2), &certificate(2)).unwrap();

        let read = store.headers().unwrap();
        assert_eq!(read.len(), 2, "one row per height, ordered");
        assert_eq!(read[0].header, header(1));
        assert_eq!(read[1].header, header(2));
        assert_eq!(read[1].certificate, certificate(2));
    }

    #[test]
    fn truncating_headers_keeps_the_provable_prefix_on_disk() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        for height in 1..=5u64 {
            store
                .put_header(&header(height), &certificate(height))
                .unwrap();
        }

        let dropped = store.truncate_headers(3).unwrap();
        assert_eq!(dropped, 2);
        let read = store.headers().unwrap();
        assert_eq!(read.len(), 3, "heights above the bound are gone");
        assert_eq!(read[2].header, header(3));

        // A rewrite is visible to a reopen, not just to the live handle.
        drop(store);
        let reopened = Store::open(&dir.0).unwrap();
        assert_eq!(reopened.headers().unwrap().len(), 3);
        assert_eq!(reopened.truncate_headers(3).unwrap(), 0);
    }

    #[test]
    fn a_genesis_header_round_trips() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.genesis_header().unwrap().is_none());

        store.put_genesis_header(&header(0)).unwrap();
        assert_eq!(store.genesis_header().unwrap(), Some(header(0)));

        // The file is replaced atomically and survives a reopen.
        drop(store);
        let reopened = Store::open(&dir.0).unwrap();
        assert_eq!(reopened.genesis_header().unwrap(), Some(header(0)));
    }

    #[test]
    fn a_genesis_state_round_trips() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.genesis_state().unwrap().is_none());

        store.put_genesis_state(b"state-bytes").unwrap();
        assert_eq!(
            store.genesis_state().unwrap(),
            Some(b"state-bytes".to_vec())
        );

        drop(store);
        let reopened = Store::open(&dir.0).unwrap();
        assert_eq!(
            reopened.genesis_state().unwrap(),
            Some(b"state-bytes".to_vec())
        );
    }

    #[test]
    fn a_truncated_header_record_is_an_error_not_an_empty_store() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.put_header(&header(1), &certificate(1)).unwrap();

        // Claim a header body longer than the record holds.
        let path = dir.0.join(HEADERS_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let start: usize = 4;
        bytes[start..start + 4].copy_from_slice(&9_999u32.to_le_bytes());
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(store.headers(), Err(StoreError::Decode(_))));
    }

    #[test]
    fn a_store_remembers_which_chain_it_belongs_to() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.genesis().unwrap(), None, "a fresh store is unbound");

        let chain = [7u8; 32];
        store.bind_genesis(&chain).unwrap();
        assert_eq!(store.genesis().unwrap(), Some(chain));

        // Binding again to the same chain is harmless, and survives reopening.
        store.bind_genesis(&chain).unwrap();
        drop(store);
        let reopened = Store::open(&dir.0).unwrap();
        reopened.require_genesis(&chain).unwrap();
    }

    #[test]
    fn a_store_refuses_another_chain() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.bind_genesis(&[1u8; 32]).unwrap();

        assert!(matches!(
            store.bind_genesis(&[2u8; 32]),
            Err(StoreError::ChainMismatch { .. })
        ));
        assert!(matches!(
            store.require_genesis(&[2u8; 32]),
            Err(StoreError::ChainMismatch { .. })
        ));
        // The original binding is untouched by the refusals.
        assert_eq!(store.genesis().unwrap(), Some([1u8; 32]));
    }

    #[test]
    fn an_unbound_store_is_accepted_by_require_genesis() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.require_genesis(&[9u8; 32]).unwrap();
    }

    #[test]
    fn a_truncated_genesis_record_is_an_error() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        fs::write(dir.0.join(GENESIS_FILE), [0u8; 20]).unwrap();
        assert!(matches!(store.genesis(), Err(StoreError::Decode(_))));
    }

    #[test]
    fn the_roots_record_rejects_an_unknown_version() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut record = vec![9u8, 9u8];
        record.extend_from_slice(&[0u8; 64]);
        fs::write(dir.0.join(ROOTS_FILE), record).unwrap();

        assert!(matches!(store.roots(), Err(StoreError::Decode(_))));
    }

    /// Six rounds, each with its own shard so every payload may be dropped, and a
    /// snapshot at the newest round so the replay anchor covers all of them.
    fn six_rounds(store: &Store) {
        for round in 0..6u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            let digest = payload.digest().unwrap();
            store.put_shard(&digest, 0, b"s").unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
        }
        store.put_snapshot(5, b"state").unwrap();
    }

    #[test]
    fn age_pruning_drops_rounds_older_than_the_window() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);
        let day = 86_400u64;
        for round in 0..6u64 {
            store.record_clock(round, round * 2 * day + 2).unwrap();
        }

        // Four days back from day ten lands between the samples for rounds 2 and 3.
        let now = 10 * day + 1;
        let policy = Retention {
            days: 4,
            max_bytes: 0,
        };
        let plan = store.plan(policy, now, 1).unwrap();
        assert_eq!(plan.age_cutoff, Some(2));
        assert_eq!(plan.size_cutoff, None);
        assert_eq!(plan.cutoff, Some(2));

        let report = store.prune(policy, now, 1).unwrap();
        assert_eq!(
            report.vertices, 3,
            "rounds 0, 1, and 2 are older than four days"
        );
        let kept: Vec<u64> = store
            .vertices()
            .unwrap()
            .iter()
            .map(|vertex| vertex.round)
            .collect();
        assert_eq!(kept, vec![3, 4, 5]);
    }

    #[test]
    fn without_clock_samples_age_prunes_nothing() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);

        let policy = Retention {
            days: 1,
            max_bytes: 0,
        };
        let plan = store.plan(policy, 30 * 86_400, 1).unwrap();
        assert_eq!(
            plan.age_cutoff, None,
            "an unknown age must not empty the store"
        );
        assert_eq!(plan.cutoff, None);
        assert_eq!(store.prune(policy, 30 * 86_400, 1).unwrap().vertices, 0);
        assert_eq!(store.vertices().unwrap().len(), 6);
    }

    #[test]
    fn the_disk_cap_prunes_until_the_store_fits() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);

        let cap = store.disk_bytes().unwrap() / 2;
        let policy = Retention {
            days: 0,
            max_bytes: cap,
        };
        let plan = store.plan(policy, 0, 1).unwrap();
        assert!(plan.disk_bytes > cap);
        let cutoff = plan
            .size_cutoff
            .expect("a cap below the current size must prune");
        assert!(cutoff < 5, "nonzero shards mean the tail is not the answer");

        let report = store.prune(policy, 0, 1).unwrap();
        assert_eq!(
            report.cap_shortfall, 0,
            "shards are small, so the cap is reachable"
        );
        assert!(store.disk_bytes().unwrap() <= cap);
        assert!(report.vertices > 0);
        assert!(report.batches_dropped > 0);
    }

    #[test]
    fn a_payload_without_a_shard_keeps_the_cap_short() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        // No shards: the batches are the only copy this node knows about.
        for round in 0..6u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
        }

        // A snapshot at the newest round, so the anchor is not what holds this back.
        store.put_snapshot(5, b"state").unwrap();
        let cap = store.disk_bytes().unwrap() / 4;
        let policy = Retention {
            days: 0,
            max_bytes: cap,
        };
        let report = store.prune(policy, 0, 1).unwrap();
        assert_eq!(report.batches_dropped, 0, "no shard backs these payloads");
        assert!(report.batches_held > 0);
        assert!(report.vertices > 0, "metadata still goes");
        assert!(
            report.cap_shortfall > 0,
            "the store cannot meet a cap the payload alone exceeds"
        );
    }

    #[test]
    fn the_earlier_window_wins_when_both_apply() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);
        let day = 86_400u64;
        for round in 0..6u64 {
            store.record_clock(round, round * 2 * day + 2).unwrap();
        }

        // Age would drop round 2; half the disk needs a deeper cut.
        let now = 10 * day + 1;
        let size_policy = Retention {
            days: 0,
            max_bytes: store.disk_bytes().unwrap() / 3,
        };
        let size_cutoff = store
            .plan(size_policy, now, 1)
            .unwrap()
            .size_cutoff
            .unwrap();
        assert!(
            size_cutoff > 2,
            "the size cap must cut deeper than age alone"
        );

        let policy = Retention {
            days: 4,
            max_bytes: size_policy.max_bytes,
        };
        assert_eq!(
            store.plan(policy, now, 1).unwrap().cutoff,
            Some(size_cutoff)
        );
    }

    #[test]
    fn pruning_keeps_one_anchor_sample_for_the_next_window() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);
        for round in 0..6u64 {
            store.record_clock(round, 1_000 + round).unwrap();
        }

        store.prune_below(2, 1).unwrap();
        store.trim_clock(2).unwrap();
        let samples = store.clock_samples().unwrap();
        assert_eq!(
            samples,
            vec![(2, 1_002), (3, 1_003), (4, 1_004), (5, 1_005)]
        );
    }

    #[test]
    fn without_a_snapshot_pruning_would_remove_the_replay_anchor() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        for round in 0..4u64 {
            let payload = batch(round + 1);
            store.put_batch(&payload).unwrap();
            store.append_vertex(&vertex(round, &payload)).unwrap();
        }

        let policy = Retention {
            days: 0,
            max_bytes: 1,
        };
        let plan = store.plan(policy, 0, 1).unwrap();
        assert_eq!(plan.snapshot_round, None);
        assert_eq!(
            plan.cutoff, None,
            "the tail would have nothing to replay onto"
        );
        let report = store.prune(policy, 0, 1).unwrap();
        assert_eq!(report.vertices, 0);
        assert_eq!(store.vertices().unwrap().len(), 4);
    }

    #[test]
    fn a_snapshot_clamps_the_cutoff_the_policy_asked_for() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        six_rounds(&store);
        // The newest snapshot covers round 2, so rounds 3..5 must stay even though
        // the disk cap would happily drop further.
        store.put_snapshot(2, b"older state").unwrap();

        let policy = Retention {
            days: 0,
            max_bytes: 1,
        };
        let plan = store.plan(policy, 0, 1).unwrap();
        assert_eq!(plan.size_cutoff, Some(5));
        assert_eq!(plan.cutoff, Some(2));

        let report = store.prune(policy, 0, 1).unwrap();
        assert_eq!(report.vertices, 3);
        assert!(
            report.cap_shortfall > 0,
            "the cap cannot be met above the snapshot"
        );
        let kept: Vec<u64> = store
            .vertices()
            .unwrap()
            .iter()
            .map(|vertex| vertex.round)
            .collect();
        assert_eq!(kept, vec![3, 4, 5]);
    }

    #[test]
    fn a_clock_sample_for_an_earlier_round_is_ignored() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        store.record_clock(500, 1_000).unwrap();
        store.record_clock(0, 2_000).unwrap();
        assert_eq!(store.clock_samples().unwrap(), vec![(500, 1_000)]);
    }
}
