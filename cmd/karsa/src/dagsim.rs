//! Deterministic in-process DAG simulator.
//!
//! Runs the direct commit rule from `validator::Dag` against fixed scenarios so
//! the rules are observable: a supermajority of votes commits, a supermajority of
//! observed non-votes skips, and anything else stays undecided. No networking and
//! no timing: the same input always produces the same output.

use std::error::Error;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use validator::{
    Dag, Decision, NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, Vertex, VertexId,
};

const CHAIN_ID: &[u8] = b"karsa-dagsim-1";
const EPOCH: u64 = 1;
const LEADER_ROUND: u64 = 7;

struct Sim {
    keys: Vec<Vec<u8>>,
    dag: Dag,
}

impl Sim {
    fn new(validators: usize) -> Result<Self, Box<dyn Error>> {
        let mut keys = Vec::with_capacity(validators);
        let mut records = Vec::with_capacity(validators);
        for index in 0..validators {
            let seed = [u8::try_from(index + 1)?; 32];
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

    fn vertex(
        &self,
        author: usize,
        round: u64,
        references: Vec<VertexId>,
    ) -> Result<Vertex, Box<dyn Error>> {
        let mut vertex = Vertex {
            chain_id: CHAIN_ID.to_vec(),
            epoch: EPOCH,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash: [u8::try_from(author + 1)?; 32],
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload()?;
        vertex.signature = Ed25519Scheme.sign(&self.keys[author], &payload)?;
        Ok(vertex)
    }

    fn insert(&mut self, vertex: Vertex) -> Result<VertexId, Box<dyn Error>> {
        Ok(self.dag.insert(vertex)?)
    }

    /// The elected leader of `round`, from the same rule the DAG uses.
    fn leader(&self, round: u64) -> Option<VertexId> {
        let index = usize::try_from(round).ok()? % self.dag.set().validators.len();
        let author = &self.dag.set().validators[index].validator_id;
        self.dag.get(round, author).and_then(|v| v.id().ok())
    }

    fn insert_leader(&mut self, references: Vec<VertexId>) -> Result<VertexId, Box<dyn Error>> {
        let index = usize::try_from(LEADER_ROUND)? % self.dag.set().validators.len();
        self.insert(self.vertex(index, LEADER_ROUND, references)?)
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

pub fn run(validators: usize) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("--validators must be at least 4 so that a quorum is not everyone".into());
    }

    println!("== DAG simulator (direct commit rule only) ==");
    println!("  validators:   {validators}");
    println!(
        "  supermajority: {} of {validators}",
        validators * 2 / 3 + 1
    );
    println!(
        "  rounds:       leader at {LEADER_ROUND}, votes at {}",
        LEADER_ROUND + 1
    );
    println!();

    let scenarios: Vec<(&str, Outcome)> = vec![
        ("all validators vote", all_vote(validators)?),
        ("one validator silent", three_of_four(validators)?),
        ("half the validators silent", half_silent(validators)?),
        ("supermajority of non-votes", non_vote_quorum(validators)?),
        ("leader never received", missing_leader(validators)?),
        ("one author submits twice", duplicate_author(validators)?),
        ("leader with two ancestors", with_history(validators)?),
    ];

    println!(
        "  {}  {}  {}  detail",
        pad("scenario", 28),
        pad("decision", 10),
        pad("committed", 10)
    );
    for (name, outcome) in &scenarios {
        println!(
            "  {}  {}  {}  {}",
            pad(name, 28),
            pad(outcome.decision, 10),
            pad(&outcome.committed.to_string(), 10),
            outcome.detail
        );
    }

    // A missing ancestor is a failure, not a decision, and it must not commit.
    let mut sim = Sim::new(validators)?;
    let phantom = VertexId {
        round: LEADER_ROUND - 1,
        author: b"val-0".to_vec(),
        digest: [7u8; 32],
    };
    sim.insert_leader(vec![phantom])?;
    let leader = sim.leader(LEADER_ROUND).expect("leader was inserted");
    for author in 0..validators {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let missing = sim.dag.try_commit(LEADER_ROUND);
    println!();
    print!("  missing ancestor: ");
    match missing {
        Ok(decision) => println!("{} (unexpected)", describe(&decision)),
        Err(error) => println!("rejected, code {} {}", error.code(), error.kind()),
    }

    // Determinism: the same scenario must produce the same commit sequence.
    let first = with_history(validators)?;
    let second = with_history(validators)?;
    println!();
    println!(
        "  deterministic: {} (same input, same decision and same committed count)",
        first.decision == second.decision && first.committed == second.committed
    );
    println!();
    println!("  Not modelled: indirect commit through an anchor, waves, a pacemaker,");
    println!("  asynchrony, networking, and execution. This decides one round at a time.");

    Ok(())
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn outcome(decision: Decision, detail: impl Into<String>) -> Result<Outcome, Box<dyn Error>> {
    let outcome = Outcome {
        decision: describe(&decision),
        committed: committed_count(&decision),
        detail: detail.into(),
    };
    Ok(outcome)
}

fn all_vote(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    let leader = sim.insert_leader(Vec::new())?;
    for author in 0..validators {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, "every vote references the leader")
}

fn three_of_four(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    let leader = sim.insert_leader(Vec::new())?;
    for author in 0..validators - 1 {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(
        decision,
        format!("{} votes, one validator absent", validators - 1),
    )
}

fn half_silent(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    let leader = sim.insert_leader(Vec::new())?;
    let voting = validators / 2;
    for author in 0..voting {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, format!("{voting} votes, absence is not evidence"))
}

fn non_vote_quorum(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    sim.insert_leader(Vec::new())?;
    let quorum = validators * 2 / 3 + 1;
    for author in 0..quorum {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, Vec::new())?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, format!("{quorum} observed non-votes"))
}

fn missing_leader(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    for author in 0..validators {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, Vec::new())?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, "no leader vertex to decide")
}

fn duplicate_author(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    let leader = sim.insert_leader(Vec::new())?;
    for _ in 0..2 {
        sim.insert(sim.vertex(0, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, "one author cannot make a quorum alone")
}

fn with_history(validators: usize) -> Result<Outcome, Box<dyn Error>> {
    let mut sim = Sim::new(validators)?;
    let ancestor_round = LEADER_ROUND - 1;
    let mut ancestors = Vec::new();
    for author in 0..2 {
        ancestors.push(sim.insert(sim.vertex(author, ancestor_round, Vec::new())?)?);
    }
    let leader = sim.insert_leader(ancestors)?;
    for author in 0..validators {
        sim.insert(sim.vertex(author, LEADER_ROUND + 1, vec![leader.clone()])?)?;
    }
    let decision = sim.dag.try_commit(LEADER_ROUND)?;
    outcome(decision, "leader plus two ancestors, committed once")
}
