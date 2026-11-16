//! Bounded volatile share routing to existing peer writer queues.

use net::wire::{self, Message};
use tokio::sync::{mpsc, watch};

use super::event_pump::PumpOutput;

/// One configured remote writer queue. The caller must exclude the local owner.
pub struct SharePeer {
    /// Caller-assigned remote peer identity for failure reporting.
    pub id: usize,
    /// Bounded control queue consumed by the existing link writer.
    pub writer: mpsc::Sender<Vec<u8>>,
}

/// Local-only result; certificates and diagnostics never become wire publications.
pub struct DispatchOutput {
    /// Original volatile output, including local shares, diagnostics and certificates.
    pub local: PumpOutput,
    /// Closed peer queues, not delivery acknowledgements for the other peers.
    pub failed_peers: Vec<usize>,
}

// False updates are not cancellation. Rechecking the current value also makes
// dropping and recreating this future in select safe after another branch wins.
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// Routes only locally generated shares, preserving bounded backpressure.
///
/// A slow peer stalls this dispatcher until cancellation or queue closure. Cancellation
/// (including sender drop) can interrupt a partially routed output; queued frames and
/// local results are volatile. There is no retry queue, exactly-once or no-loss promise.
/// Existing writers own TCP framing delivery/reconnection, not this dispatcher.
/// Dropping the local result receiver stops routing. `sent_at_nanos` is telemetry only.
pub async fn dispatch(
    mut input: mpsc::Receiver<PumpOutput>,
    peers: Vec<SharePeer>,
    local: mpsc::Sender<DispatchOutput>,
    mut cancel: watch::Receiver<bool>,
    sent_at_nanos: u64,
) {
    loop {
        if *cancel.borrow() {
            return;
        }
        let permit = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => return,
            permit = local.reserve() => match permit { Ok(p) => p, Err(_) => return },
        };
        let output = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => return,
            _ = local.closed() => return,
            output = input.recv() => match output { Some(o) => o, None => return },
        };
        let mut failed_peers = Vec::new();
        for share in &output.build.shares {
            let frame = match wire::frame(&Message::Share(share.clone()), sent_at_nanos) {
                Ok(frame) => frame,
                Err(error) => {
                    let mut output = output;
                    output.error = Some(format!("share frame encoding failed: {error}"));
                    permit.send(DispatchOutput {
                        local: output,
                        failed_peers,
                    });
                    return;
                }
            };
            for peer in &peers {
                if failed_peers.contains(&peer.id) {
                    continue;
                }
                let result = tokio::select! {
                    biased;
                    _ = cancelled(&mut cancel) => return,
                    _ = local.closed() => return,
                    result = peer.writer.send(frame.clone()) => result,
                };
                if result.is_err() {
                    failed_peers.push(peer.id);
                }
            }
        }
        permit.send(DispatchOutput {
            local: output,
            failed_peers,
        });
    }
}
