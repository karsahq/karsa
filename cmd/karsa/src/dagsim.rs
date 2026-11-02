//! Deterministic in-process DAG simulator.
//!
//! Runs the rules from `validator::Dag` against fixed scenarios so they are
//! observable: a supermajority of votes commits, a supermajority of observed
//! non-votes skips, a partially observed round stays undecided, and a later
//! committed anchor resolves an earlier slot. No networking and no timing: the
//! same input always produces the same output.

use std::error::Error;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use validator::{
    Dag, Decision, NO_EXPIRY, Pacemaker, PacemakerConfig, Step, ValidatorKey, ValidatorRecord,
    ValidatorSet, Vertex, VertexId,
};

const CHAIN_ID: &[u8] = b"karsa-dagsim-1";
const EPOCH: u64 = 1;
/// Round 0 is genesis and needs no references, so the first leader is here.
const LEADER_ROUND: u64 = 1;

struct Sim {
    keys: Vec<Vec<u8>>,
    dag: Dag,
}

impl Sim {
    fn new(validators: usize) -> Result<Self, crypto::CryptoError> {
        let mut keys = Vec::with_capacity(validators);
        let mut records = Vec::with_capacity(validators);
        for index in 0..validators {
            // Two bytes of index: distinct for any realistic committee size.
            let mut seed = [0u8; 32];
            seed[0] = u8::try_from(index & 0xff).unwrap_or(0);
            seed[1] = u8::try_from((index >> 8) & 0xff).unwrap_or(0);
            let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
            let mut private_key = Vec::with_capacity(64);
            private_key.extend_from_slice(&seed);
            private_key.extend_from_slice(&public_key);
            records.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: public_key.to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            keys.push(private_key);
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators: records,
        };
        set.validate()?;
        let dag = Dag::new(set);
        Ok(Self { keys, dag })
    }

    fn count(&self) -> usize {
        self.dag.set().validators.len()
    }

    fn quorum(&self) -> usize {
        self.dag.set().quorum_size()
    }

    fn leader_index(&self, round: u64) -> usize {
        usize::try_from(round).unwrap_or(0) % self.count()
    }

    fn vertex(
        &self,
        author: usize,
        round: u64,
        references: Vec<VertexId>,
    ) -> Result<Vertex, crypto::CryptoError> {
        let mut vertex = Vertex {
            chain_id: CHAIN_ID.to_vec(),
            epoch: EPOCH,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash: [u8::try_from(author + 1).unwrap_or(u8::MAX); 32],
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload()?;
        vertex.signature = Ed25519Scheme.sign(&self.keys[author], &payload)?;
        Ok(vertex)
    }

    fn insert(&mut self, vertex: Vertex) -> Result<VertexId, crypto::CryptoError> {
        self.dag.insert(vertex)
    }

    /// Inserts one vertex per validator, all with the same references.
    fn fill_round(
        &mut self,
        round: u64,
        references: &[VertexId],
    ) -> Result<(), crypto::CryptoError> {
        self.fill_round_except(round, references, &[])
    }

    /// Inserts one vertex per validator except the listed authors.
    fn fill_round_except(
        &mut self,
        round: u64,
        references: &[VertexId],
        absent: &[usize],
    ) -> Result<(), crypto::CryptoError> {
        for author in 0..self.count() {
            if absent.contains(&author) {
                continue;
            }
            let vertex = self.vertex(author, round, references.to_vec())?;
            self.insert(vertex)?;
        }
        Ok(())
    }

    fn ids(&self, round: u64) -> Vec<VertexId> {
        self.ids_where(round, |_| true)
    }

    /// Ids of every vertex in `round` except that round's leader.
    fn ids_without_leader(&self, round: u64) -> Vec<VertexId> {
        let leader = self.leader_index(round);
        self.ids_where(round, |author| author != leader)
    }

    fn ids_where(&self, round: u64, keep: impl Fn(usize) -> bool) -> Vec<VertexId> {
        let mut ids = Vec::new();
        for author in 0..self.count() {
            if !keep(author) {
                continue;
            }
            let key = format!("val-{author}");
            if let Some(vertex) = self.dag.get(round, key.as_bytes())
                && let Ok(id) = vertex.id()
            {
                ids.push(id);
            }
        }
        ids
    }

    /// Genesis round plus the first leader round, both complete.
    fn bootstrap(&mut self) -> Result<(), crypto::CryptoError> {
        self.fill_round(0, &[])?;
        let genesis = self.ids(0);
        self.fill_round(LEADER_ROUND, &genesis)
    }
}

/// One scenario's outcome, ready to print.
struct Outcome {
    decision: &'static str,
    committed: usize,
    detail: String,
}

fn describe(decision: &Decision) -> &'static str {
    match decision {
        Decision::Commit(_) => "commit",
        Decision::Skip => "skip",
        Decision::Undecided => "undecided",
    }
}

fn committed_count(decision: &Decision) -> usize {
    match decision {
        Decision::Commit(history) => history.len(),
        _ => 0,
    }
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn outcome(decision: Decision, detail: impl Into<String>) -> Outcome {
    Outcome {
        decision: describe(&decision),
        committed: committed_count(&decision),
        detail: detail.into(),
    }
}

pub fn run(validators: usize) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("--validators must be at least 4 so that a quorum is not everyone".into());
    }

    println!("== DAG simulator ==");
    println!("  validators:    {validators}");
    println!(
        "  supermajority: {} of {validators}",
        validators * 2 / 3 + 1
    );
    println!(
        "  rounds:        genesis 0, leader {LEADER_ROUND}, votes {}",
        LEADER_ROUND + 1
    );
    println!();

    let scenarios = vec![
        ("all validators vote", all_vote(validators)?),
        ("one validator silent", one_silent(validators)?),
        ("half the validators silent", half_silent(validators)?),
        ("supermajority of non-votes", non_vote_quorum(validators)?),
        ("leader never received", missing_leader(validators)?),
        ("one author submits twice", duplicate_author(validators)?),
        ("leader with full history", with_history(validators)?),
    ];

    println!(
        "  {}  {}  {}  detail",
        pad("scenario", 28),
        pad("decision", 10),
        pad("committed", 10)
    );
    for scenario in &scenarios {
        println!(
            "  {}  {}  {}  {}",
            pad(scenario.0, 28),
            pad(scenario.1.decision, 10),
            pad(&scenario.1.committed.to_string(), 10),
            scenario.1.detail
        );
    }

    println!();
    print!("  shape rule: ");
    match violated_shape(validators) {
        Ok(()) => println!("accepted (unexpected)"),
        Err(error) => println!("rejected, code {} {}", error.code(), error.kind()),
    }
    print!("  missing ancestor: ");
    match missing_ancestor(validators) {
        Ok(()) => println!("accepted (unexpected)"),
        Err(error) => println!("rejected, code {} {}", error.code(), error.kind()),
    }

    println!();
    println!("== Indirect rule: deciding an earlier slot through a committed anchor ==");
    for (label, anchored) in [
        ("leader inside the anchor history", true),
        ("no path from the committed anchor", false),
    ] {
        let outcome = indirect(validators, anchored)?;
        println!(
            "  {}  decision {:<10} committed {}  skipped {}",
            pad(label, 36),
            outcome.decision,
            outcome.committed,
            outcome.skipped
        );
        println!(
            "  {}  anchor one round too recent: {}",
            pad("", 36),
            outcome.too_recent
        );
    }

    println!();
    println!("== Pacemaker: deciding rounds forward without a clock ==");
    let scenarios = [
        ("every round fills", 8u64, Vec::new()),
        (
            "leader of round 5 absent",
            8u64,
            vec![(5u64, usize::try_from(5u64).unwrap_or(0) % validators)],
        ),
        ("nothing arrives after genesis", 0u64, Vec::new()),
    ];
    println!("  ticks per scenario: 5, timeout 3 ticks, anchor must be 2 rounds ahead");
    println!();
    println!(
        "  {}  {}  {}  {}  {}  detail",
        pad("scenario", 30),
        pad("cursor", 7),
        pad("commits", 8),
        pad("skips", 6),
        pad("timeouts", 9)
    );
    for (label, upto, absent) in &scenarios {
        let run = pacemaker_run(validators, *upto, absent, 5)?;
        println!(
            "  {}  {}  {}  {}  {}  {}",
            pad(label, 30),
            pad(&run.cursor.to_string(), 7),
            pad(&run.commits.to_string(), 8),
            pad(&run.skips.to_string(), 6),
            pad(&run.timeouts.to_string(), 9),
            run.detail
        );
    }

    println!();
    println!(
        "  deterministic: {} (same input, same decision)",
        all_vote(validators)?.decision == all_vote(validators)?.decision
    );
    println!();
    println!("  Not modelled: waves or pipelining, asynchrony, networking, and execution.");

    Ok(())
}

/// One pacemaker run, summarised.
struct PacemakerOutcome {
    cursor: u64,
    commits: usize,
    skips: usize,
    timeouts: u64,
    detail: String,
}

/// Builds rounds `0..=upto`, omitting the listed `(round, author)` pairs, then
/// drives the pacemaker for a fixed number of logical ticks.
fn pacemaker_run(
    validators: usize,
    upto: u64,
    absent: &[(u64, usize)],
    ticks: usize,
) -> Result<PacemakerOutcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    for round in 0..=upto {
        let references = if round == 0 {
            Vec::new()
        } else {
            sim.ids(round - 1)
        };
        let skip: Vec<usize> = absent
            .iter()
            .filter(|(at, _)| *at == round)
            .map(|(_, author)| *author)
            .collect();
        sim.fill_round_except(round, &references, &skip)?;
    }

    let mut pacemaker = Pacemaker::new(PacemakerConfig { timeout_ticks: 3 }, LEADER_ROUND);
    let mut commits = 0usize;
    let mut skips = 0usize;
    for _ in 0..ticks {
        if let Step::Advanced {
            commits: new_commits,
            skips: new_skips,
            ..
        } = pacemaker.tick(&mut sim.dag)?
        {
            commits += new_commits;
            skips += new_skips;
        }
    }

    let detail = match sim.dag.skipped().first() {
        Some(skipped) => format!(
            "skipped {}@{} (vertex never received: {})",
            String::from_utf8_lossy(&skipped.author),
            skipped.round,
            skipped.digest.is_none()
        ),
        None => format!(
            "{} rounds held, {} committed",
            sim.dag.highest_round().map_or(0, |round| round + 1),
            sim.dag.order().len()
        ),
    };

    Ok(PacemakerOutcome {
        cursor: pacemaker.cursor(),
        commits,
        skips,
        timeouts: pacemaker.timeouts(),
        detail,
    })
}

fn all_vote(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    sim.fill_round(LEADER_ROUND + 1, &votes)?;
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(
        decision,
        "every vote references the leader and a quorum of the previous round",
    ))
}

fn one_silent(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    for author in 0..validators - 1 {
        let vertex = sim.vertex(author, LEADER_ROUND + 1, votes.clone())?;
        sim.insert(vertex)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(
        decision,
        format!("{} votes, one absent", validators - 1),
    ))
}

fn half_silent(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    let voting = validators / 2;
    for author in 0..voting {
        let vertex = sim.vertex(author, LEADER_ROUND + 1, votes.clone())?;
        sim.insert(vertex)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(
        decision,
        format!("{voting} votes, absence is not evidence"),
    ))
}

fn non_vote_quorum(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let without_leader = sim.ids_without_leader(LEADER_ROUND);
    let quorum = sim.quorum();
    for author in 0..quorum {
        let vertex = sim.vertex(author, LEADER_ROUND + 1, without_leader.clone())?;
        sim.insert(vertex)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(decision, format!("{quorum} observed non-votes")))
}

fn missing_leader(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.fill_round(0, &[])?;
    let genesis = sim.ids(0);
    let leader = sim.leader_index(LEADER_ROUND);
    for author in 0..validators {
        if author == leader {
            continue;
        }
        let vertex = sim.vertex(author, LEADER_ROUND, genesis.clone())?;
        sim.insert(vertex)?;
    }
    let present = sim.ids(LEADER_ROUND);
    sim.fill_round(LEADER_ROUND + 1, &present)?;
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(decision, "no leader vertex to decide"))
}

fn duplicate_author(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    for _ in 0..2 {
        let vertex = sim.vertex(0, LEADER_ROUND + 1, votes.clone())?;
        sim.insert(vertex)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(decision, "one author cannot make a quorum alone"))
}

fn with_history(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    sim.fill_round(LEADER_ROUND + 1, &votes)?;
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    Ok(outcome(
        decision,
        "the leader plus the genesis round it references",
    ))
}

/// A round-1 vertex that references too few previous-round authors.
fn violated_shape(validators: usize) -> Result<(), crypto::CryptoError> {
    let mut sim = Sim::new(validators)?;
    sim.fill_round(0, &[])?;
    let genesis = sim.ids(0);
    let short = genesis[..sim.quorum() - 1].to_vec();
    let vertex = sim.vertex(0, LEADER_ROUND, short)?;
    sim.insert(vertex)?;
    Ok(())
}

/// A leader that references a vertex nobody holds.
fn missing_ancestor(validators: usize) -> Result<(), crypto::CryptoError> {
    let mut sim = Sim::new(validators)?;
    sim.fill_round(0, &[])?;
    let genesis = sim.ids(0);
    let leader = sim.leader_index(LEADER_ROUND);
    for author in 0..validators {
        let mut references = genesis.clone();
        if author == leader {
            references.truncate(sim.quorum());
            references.push(VertexId {
                round: 0,
                author: b"val-unknown".to_vec(),
                digest: [9u8; 32],
            });
        }
        let vertex = sim.vertex(author, LEADER_ROUND, references)?;
        sim.insert(vertex)?;
    }
    let votes = sim.ids(LEADER_ROUND);
    sim.fill_round(LEADER_ROUND + 1, &votes)?;
    sim.dag.try_commit(LEADER_ROUND)?;
    Ok(())
}

/// One indirect-decision run: an earlier slot decided through a committed anchor.
struct IndirectOutcome {
    decision: &'static str,
    committed: usize,
    skipped: usize,
    too_recent: &'static str,
}

fn indirect(validators: usize, anchored: bool) -> Result<IndirectOutcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.bootstrap()?;
    let votes = sim.ids(LEADER_ROUND);
    let without_leader = sim.ids_without_leader(LEADER_ROUND);

    // Round 2: the anchored case has two voters, the unanchored case none.
    for author in 0..validators {
        let references = if anchored && author < 2 {
            votes.clone()
        } else {
            without_leader.clone()
        };
        let vertex = sim.vertex(author, LEADER_ROUND + 1, references)?;
        sim.insert(vertex)?;
    }

    // Rounds 3 and 4 carry the anchor: round 4 commits the round-3 leader.
    let round_two = sim.ids(LEADER_ROUND + 1);
    sim.fill_round(LEADER_ROUND + 2, &round_two)?;
    let anchor = sim
        .dag
        .leader(LEADER_ROUND + 2)
        .expect("the round-3 leader was inserted")
        .id()?;
    let round_three = sim.ids(LEADER_ROUND + 2);
    sim.fill_round(LEADER_ROUND + 3, &round_three)?;
    sim.dag.try_commit(LEADER_ROUND + 2)?;

    // An anchor only one round later has not had the round a quorum path needs.
    let one_round_later = sim
        .dag
        .leader(LEADER_ROUND + 1)
        .expect("the round-2 leader was inserted")
        .id()?;
    let too_recent = describe(
        &sim.dag
            .try_indirect_decide(LEADER_ROUND, &one_round_later)?,
    );

    let decision = sim.dag.try_indirect_decide(LEADER_ROUND, &anchor)?;
    Ok(IndirectOutcome {
        decision: describe(&decision),
        committed: committed_count(&decision),
        skipped: sim.dag.skipped().len(),
        too_recent,
    })
}
