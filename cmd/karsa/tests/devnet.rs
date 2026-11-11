//! A four-process devnet over real sockets.
//!
//! `scripts/devnet.sh` proves the same path by hand: generate a home, start one
//! validator process per node, submit a signed transfer, and read the same
//! result from every node. This test is the automated form of that cold run,
//! not a replacement for the longer fault and restart probes.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// The devnet the script brings up, and the smallest committee with a real
/// quorum (`n - floor(n / 3)` leaves at least one node out).
const VALIDATORS: usize = 4;

/// The binary built for this test.
const BIN: &str = env!("CARGO_BIN_EXE_karsa");

/// A devnet directory plus its four processes.
struct Devnet {
    dir: PathBuf,
    children: Vec<Child>,
}

impl Devnet {
    /// Starts one `karsa live --node-index i` process per validator.
    ///
    /// `p2p_base` is the consensus port base; `rpc_base` is the first HTTP port.
    /// The home must already contain a genesis and its keys. `extra` is appended
    /// to every process, so all validators see the same liveness policy.
    fn start(dir: PathBuf, p2p_base: u16, rpc_base: u16) -> Self {
        Self::start_with(dir, p2p_base, rpc_base, &[])
    }

    fn start_with(dir: PathBuf, p2p_base: u16, rpc_base: u16, extra: &[&str]) -> Self {
        let mut children = Vec::with_capacity(VALIDATORS);
        for index in 0..VALIDATORS {
            let log =
                File::create(dir.join(format!("val-{index}.log"))).expect("create a validator log");
            let error = log.try_clone().expect("clone the validator log");
            let mut command = Command::new(BIN);
            command
                .args(["live", "--validators", &VALIDATORS.to_string()])
                .args(["--node-index", &index.to_string()])
                .args(["--port-base", &p2p_base.to_string()])
                .args(["--rpc-port", &rpc_base.to_string()])
                // The checkpoint path has its own restart test; this test is the
                // cold mesh and the gossip status, without 16-height prune work.
                .args(["--checkpoint-every", "0"])
                .args(["--timeout-seconds", "25"])
                .args(["--execute", "--home"])
                .arg(&dir)
                .arg("--store")
                .arg(dir.join("data"))
                .args(extra)
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(error));
            let child = command.spawn().expect("spawn a validator");
            children.push(child);
        }
        Self { dir, children }
    }

    /// Every log this run produced, for a failing assertion.
    fn logs(&self) -> String {
        let mut all = String::new();
        for index in 0..VALIDATORS {
            let path = self.dir.join(format!("val-{index}.log"));
            let text = fs::read_to_string(path).unwrap_or_default();
            all.push_str(&format!("--- node {index} ---\n{text}\n"));
        }
        all
    }

    /// Fails with the node logs attached.
    fn fail(&self, message: &str) -> ! {
        panic!("{message}\n{}", self.logs());
    }
}

impl Drop for Devnet {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A fresh home directory for the test.
fn test_home(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "karsa-devnet-{name}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create the test home");
    path
}

/// Finds a block of `count` consecutive loopback ports the mesh can bind.
fn free_port_block(count: usize) -> u16 {
    'search: for base in (20000u16..60000).step_by(16) {
        let mut probes = Vec::with_capacity(count);
        for offset in 0..count {
            let Ok(offset) = u16::try_from(offset) else {
                continue 'search;
            };
            let Ok(listener) = TcpListener::bind(("127.0.0.1", base + offset)) else {
                continue 'search;
            };
            probes.push(listener);
        }
        drop(probes);
        return base;
    }
    panic!("no free contiguous port block for the devnet");
}

/// One JSON response from the node's HTTP surface.
fn request(port: u16, path: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(1_000)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let body = response.split_once("\r\n\r\n")?.1;
    serde_json::from_str(body).ok()
}

/// Polls `probe` until it returns a value or `timeout` expires.
fn wait_for<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return Some(value);
        }
        sleep(Duration::from_millis(100));
    }
    None
}

#[test]
fn a_four_process_devnet_keeps_moving_after_one_validator_dies() {
    let dir = test_home("fence");
    let genesis = Command::new(BIN)
        .args(["genesis", "--home"])
        .arg(&dir)
        .arg("--init")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run karsa genesis");
    assert!(
        genesis.status.success(),
        "genesis failed: {}",
        String::from_utf8_lossy(&genesis.stderr)
    );

    let base = free_port_block(VALIDATORS * 2);
    let rpc_base = base + u16::try_from(VALIDATORS).expect("four ports fit a u16");
    let mut devnet = Devnet::start_with(
        dir.clone(),
        base,
        rpc_base,
        &["--fence-silent", "--failure-rounds", "15"],
    );

    // Start from a chain all four nodes have already agreed on: an early kill
    // leaves their cursors far apart, and a fence for one cursor's round does not
    // cover another's.
    let ready = wait_for(Duration::from_secs(15), || {
        for index in 0..VALIDATORS {
            let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
            let status = request(port, "/status")?;
            if status["head_height"].as_u64().unwrap_or(0) < 20 {
                return None;
            }
        }
        Some(())
    });
    if ready.is_none() {
        devnet.fail("the four nodes never certified twenty heights");
    }

    let before: Vec<u64> = (1..VALIDATORS)
        .map(|index| {
            let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
            request(port, "/status")
                .and_then(|status| status["head_height"].as_u64())
                .unwrap_or(0)
        })
        .collect();

    let mut killed = devnet.children.remove(0);
    killed.kill().expect("kill validator 0");
    killed.wait().expect("reap validator 0");

    // The survivors must keep certifying. A round whose leader is missing is
    // released by an anchor or by a quorum fence; this test only requires that the
    // cursor does not stay on it forever.
    let advanced = wait_for(Duration::from_secs(15), || {
        for (offset, index) in (1..VALIDATORS).enumerate() {
            let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
            let status = request(port, "/status")?;
            let head = status["head_height"].as_u64().unwrap_or(0);
            if head < before[offset].saturating_add(5) {
                return None;
            }
        }
        Some(())
    });
    if advanced.is_none() {
        devnet.fail("the survivors stopped certifying after validator 0 died");
    }

    for index in 1..VALIDATORS {
        let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
        let status = request(port, "/status")
            .unwrap_or_else(|| devnet.fail(&format!("node {index} lost /status")));
        assert_eq!(
            status["conflicts"].as_u64(),
            Some(0),
            "node {index} reported a conflict: {status}"
        );
    }
}

#[test]
fn a_four_process_devnet_finalizes_a_transfer_on_every_node() {
    let dir = test_home("cold");
    let genesis = Command::new(BIN)
        .args(["genesis", "--home"])
        .arg(&dir)
        .arg("--init")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run karsa genesis");
    assert!(
        genesis.status.success(),
        "genesis failed: {}",
        String::from_utf8_lossy(&genesis.stderr)
    );

    let base = free_port_block(VALIDATORS * 2);
    let rpc_base = base + u16::try_from(VALIDATORS).expect("four ports fit a u16");
    let devnet = Devnet::start(dir.clone(), base, rpc_base);

    // Every node must already be reading peer frames, not only serving HTTP:
    // two certified heights mean each one has processed shares from its links.
    // Sending into a half-open mesh would test the queue, not gossip.
    let ready = wait_for(Duration::from_secs(10), || {
        for index in 0..VALIDATORS {
            let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
            let status = request(port, "/status")?;
            if status["head_height"].as_u64().unwrap_or(0) < 2 {
                return None;
            }
        }
        Some(())
    });
    if ready.is_none() {
        devnet.fail("the four nodes never certified two heights");
    }

    let output = Command::new(BIN)
        .args(["send", "--home"])
        .arg(&dir)
        .args(["--rpc", &format!("127.0.0.1:{rpc_base}")])
        .args(["--from", "0", "--to", "1", "--amount", "1", "--wait"])
        .output()
        .expect("run karsa send");
    assert!(
        output.status.success(),
        "send failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        devnet.logs()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let id = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("transaction"))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| devnet.fail("the send output has no transaction id"))
        .to_string();

    let mut heights = Vec::with_capacity(VALIDATORS);
    let mut state_roots = Vec::with_capacity(VALIDATORS);
    for index in 0..VALIDATORS {
        let port = rpc_base + u16::try_from(index).expect("four ports fit a u16");
        let view = wait_for(Duration::from_secs(10), || {
            let view = request(port, &format!("/tx/{id}?proof=1"))?;
            (view["status"] == "finalized").then_some(view)
        });
        let Some(view) = view else {
            devnet.fail(&format!("node {index} never finalized {id}"));
        };
        assert_eq!(
            view["id"], id,
            "node {index} answered about another transaction: {view}"
        );
        assert!(
            view["commit_proof"].is_object(),
            "node {index} finalized without a commit proof: {view}"
        );
        heights.push(view["finalized_height"].clone());
        state_roots.push(view["state_root"].clone());

        let status = request(port, "/status")
            .unwrap_or_else(|| devnet.fail(&format!("node {index} lost /status")));
        assert_eq!(
            status["conflicts"].as_u64(),
            Some(0),
            "node {index} reported a conflict: {status}"
        );
        assert!(
            status["applied_txs"].as_u64().unwrap_or(0) >= 1,
            "node {index} applied nothing: {status}"
        );
        assert!(
            status["tracked_transactions"].as_u64().unwrap_or(0) >= 1,
            "node {index} did not track the gossiped transaction: {status}"
        );
    }

    // All four agreed on the header that finalized the transaction, not only on
    // the transaction they happened to serve. Comparing the head roots would be
    // wrong here: nodes certify at their own pace, and their heads can differ by
    // a few heights at the same instant.
    assert!(
        heights.windows(2).all(|pair| pair[0] == pair[1]),
        "nodes finalized the same transaction at different heights: {heights:?}\n{}",
        devnet.logs()
    );
    assert!(
        state_roots.windows(2).all(|pair| pair[0] == pair[1]),
        "nodes finalized the same transaction on different state roots: {state_roots:?}\n{}",
        devnet.logs()
    );
}
