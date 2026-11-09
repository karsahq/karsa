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
//! Nothing here fsyncs on every append: durability of the last record is the
//! caller's tradeoff, and `Store::sync` exists for callers that want it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crypto::CryptoError;
use tx::batch::Batch;
use validator::{Certificate, Header, Vertex};

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

/// What one pruning pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Vertices removed from the log.
    pub vertices: usize,
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
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens (and creates) a store directory.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the directory cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The directory this store writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    fn path_of(&self, name: &str) -> PathBuf {
        self.root.join(name)
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
        append_record(&self.path_of(HEADERS_FILE), &record)?;
        Ok(())
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

    /// Writes a state snapshot taken at `round`, replacing any previous one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on write failure, [`StoreError::Decode`] when the state
    /// does not fit the record length field.
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
    /// Both logs are rewritten through a temporary file and renamed into place, so a
    /// crash leaves either the old log or the new one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on read or write failure, [`StoreError::Decode`] when a
    /// record does not decode.
    pub fn prune_below(&self, round: u64, min_shards: usize) -> Result<PruneReport, StoreError> {
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

        let mut after: u64 = 0;
        for name in [VERTICES_FILE, BATCHES_FILE] {
            let path = self.path_of(name);
            if path.exists() {
                after += fs::metadata(&path)?.len();
            }
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
        let mut total = 0u64;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
        Ok(total)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};

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
    fn a_genesis_header_round_trips() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.genesis_header().unwrap().is_none());

        store.put_genesis_header(&header(0)).unwrap();
        assert_eq!(store.genesis_header().unwrap(), Some(header(0)));

        // The file is replaced atomically and survives a reopen.
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
