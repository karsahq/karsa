// Included in tests.rs to share the existing authenticated fixtures.

async fn driver_publish(
    output: super::event_pump::PumpOutput,
    channels: &mut [super::event_pump::PumpChannels],
    m: &Membership,
) -> Vertex {
    use super::output_dispatcher::{self, SharePeer};
    use std::sync::{Arc, atomic::AtomicU64};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        sync::{mpsc, watch},
    };
    assert!(output.error.is_none(), "{:?}", output.error);
    assert_eq!(output.carriers.len(), 1);
    let net::wire::Message::AgreementCarrier { envelope, vertices } = &output.carriers[0] else {
        panic!("carrier output")
    };
    let envelope = CarrierEnvelope::decode(envelope, &m.set).unwrap();
    let vertex = vertices
        .iter()
        .find(|v| v.id().unwrap() == *envelope.carrier())
        .unwrap()
        .clone();
    let (input, rx) = mpsc::channel(1);
    let (local, mut result) = mpsc::channel(1);
    let (cancel, cancel_rx) = watch::channel(false);
    let mut queues = Vec::new();
    let peers = (0..channels.len())
        .map(|id| {
            let (writer, rx) = mpsc::channel(1);
            queues.push(rx);
            SharePeer { id, writer }
        })
        .collect();
    let dispatcher = tokio::spawn(output_dispatcher::dispatch(rx, peers, local, cancel_rx, 7));
    input.send(output).await.unwrap();
    for (queue, channel) in queues.iter_mut().zip(channels.iter_mut()) {
        let bytes = queue.recv().await.unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut receiver, _) = listener.accept().await.unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        let (x, y) = tokio::join!(
            super::super::handshake(&mut sender, &mut a, b"live-adapter-tests"),
            super::super::handshake(&mut receiver, &mut b, b"live-adapter-tests"),
        );
        x.unwrap();
        y.unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let reader = tokio::spawn(super::super::read_peer(
            receiver,
            b,
            channel.frames.clone(),
            Arc::new(AtomicU64::new(0)),
            stop_rx,
        ));
        sender.write_all(&bytes).await.unwrap();
        let received = channel.output.recv().await.unwrap();
        assert!(received.error.is_none(), "{:?}", received.error);
        assert!(received.carriers.is_empty(), "receipt never signs");
        assert!(received.build.shares.is_empty(), "receipt never applies");
        stop.send(true).unwrap();
        reader.await.unwrap();
    }
    assert!(result.recv().await.unwrap().failed_peers.is_empty());
    cancel.send(true).unwrap();
    dispatcher.await.unwrap();
    vertex
}

async fn driver_author(
    index: usize,
    round: u64,
    vertices: &[Vertex],
    action: super::local_authoring::AuthoringAction,
    channels: &mut [super::event_pump::PumpChannels],
    m: &Membership,
) -> Vertex {
    use super::{event_pump::LocalEvent, local_authoring::AuthoringRequest};
    channels[index]
        .local
        .send(LocalEvent::Author(
            AuthoringRequest {
                round,
                vertices: vertices.to_vec(),
                action,
            }
            .into(),
        ))
        .await
        .unwrap();
    let output = channels[index].output.recv().await.unwrap();
    driver_publish(output, channels, m).await
}

#[test]
fn owned_event_pump_authors_protocol_over_tcp_then_explicitly_applies() {
    use super::{
        event_pump::{EventPump, LocalEvent},
        local_authoring::AuthoringAction,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::{Duration, Instant},
    };
    use validator::slot_agreement::AgreementPhase;
    let chain_id = b"live-adapter-tests";
    let accounts = chain::accounts(4).unwrap();
    let mut batches = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for round in 0..=2 {
        for author in 0..4 {
            let batch = chain::demo_batch(chain_id, &accounts, author, round, 1).unwrap();
            let hash = batch.digest().unwrap();
            batches.insert(hash, batch);
            hashes.insert((author, round), hash);
        }
    }
    let (m, bootstrap, request) = fixture_for_chain_with_payload(chain_id, |a, r| hashes[&(a, r)]);
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let dirs: Vec<_> = (0..3).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut channels = Vec::new();
            let mut tasks = Vec::new();
            let (cancel, stop) = tokio::sync::watch::channel(false);
            for (i, store) in stores.iter().enumerate() {
                let mut b = bootstrap.clone();
                b.agreement.local_validator = m.consensus[i].id.clone();
                let mut owner = open_event_pump_owner_index(store, &b, &m, i);
                let policy = super::pacemaker::Policy::new(
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .unwrap();
                assert!(
                    owner
                        .enable_authoring(
                            authoring_node_index(&m, &[], (i + 1) % 3),
                            policy,
                            Duration::from_millis(10)
                        )
                        .is_err(),
                    "reject mismatched pinned identity"
                );
                owner
                    .enable_authoring(
                        authoring_node_index(&m, &[], i),
                        policy,
                        Duration::from_millis(10),
                    )
                    .unwrap();
                // Opaque control classification is fixture-trusted, never inferred from network input.
                let controls: BTreeSet<_> = vertices
                    .iter()
                    .filter(|v| v.round >= 3)
                    .map(|v| v.payload_hash)
                    .chain([[4; 32], [6; 32]])
                    .collect();
                let (pump, channel) = EventPump::new(
                    owner,
                    m.clone(),
                    controls,
                    1.try_into().unwrap(),
                    16,
                    1024 * 1024,
                );
                channels.push(channel);
                tasks.push(tokio::spawn(pump.run(stop.clone())));
            }
            channels[0]
                .local
                .send(LocalEvent::Author(
                    super::local_authoring::AuthoringRequest {
                        round: 0,
                        vertices: Vec::new(),
                        action: AuthoringAction::Vote(AgreementPhase::Prevote),
                    }
                    .into(),
                ))
                .await
                .unwrap();
            let neutral = channels[0].output.recv().await.unwrap();
            assert!(neutral.error.is_none());
            assert!(
                neutral.carriers.is_empty(),
                "no vote without durable intent"
            );
            channels[0]
                .local
                .send(LocalEvent::Author(
                    super::local_authoring::AuthoringRequest {
                        round: 0,
                        vertices: vec![vertices[0].clone(); 4097],
                        action: AuthoringAction::Pol,
                    }
                    .into(),
                ))
                .await
                .unwrap();
            let rejected = channels[0].output.recv().await.unwrap();
            assert!(rejected.error.as_ref().unwrap().contains("budget"));
            assert!(rejected.carriers.is_empty());
            let prefix: Vec<_> = vertices.iter().filter(|v| v.round < 3).cloned().collect();
            let proposal = driver_author(
                0,
                3,
                &prefix,
                AuthoringAction::Proposal(lineage.entries[0].proposal.clone()),
                &mut channels,
                &m,
            )
            .await;
            let mut available: Vec<_> = vertices
                .iter()
                .filter(|v| v.round < 4 && !(v.round == 3 && v.author == proposal.author))
                .cloned()
                .collect();
            available.push(proposal.clone());
            let proposer = m
                .consensus
                .iter()
                .position(|v| v.id == lineage.entries[0].view_carrier.author)
                .unwrap();
            let candidate = validator::SlotAgreementViewCandidate::new(
                vec![],
                lineage.entries[0].proposal.clone(),
                proposal.id().unwrap(),
                AgreementView(0),
                &m.set,
            )
            .unwrap();
            let view = driver_author(
                proposer,
                4,
                &available,
                AuthoringAction::View(candidate),
                &mut channels,
                &m,
            )
            .await;
            let refs: Vec<_> = available
                .iter()
                .filter(|v| v.round == 3)
                .map(|v| v.id().unwrap())
                .collect();
            for i in 0..4 {
                if i != proposer {
                    available.push(signed(&m, i, 4, refs.clone(), [4; 32]));
                }
            }
            available.push(view);
            for (round, phase) in [(5, AgreementPhase::Prevote), (7, AgreementPhase::Precommit)] {
                let mut votes = Vec::new();
                for i in 0..3 {
                    votes.push(
                        driver_author(
                            i,
                            round,
                            &available,
                            AuthoringAction::Vote(phase),
                            &mut channels,
                            &m,
                        )
                        .await,
                    );
                }
                available.extend(votes);
                if round == 5 {
                    let pol =
                        driver_author(0, 6, &available, AuthoringAction::Pol, &mut channels, &m)
                            .await;
                    let refs: Vec<_> = available
                        .iter()
                        .filter(|v| v.round == 5)
                        .map(|v| v.id().unwrap())
                        .collect();
                    available.push(pol);
                    for i in 1..3 {
                        available.push(signed(&m, i, 6, refs.clone(), [6; 32]));
                    }
                }
            }
            let final_vertex =
                driver_author(0, 8, &available, AuthoringAction::Final, &mut channels, &m).await;
            let now = Instant::now();
            for channel in &mut channels {
                channel.local.send(LocalEvent::Tick(now)).await.unwrap();
                assert!(channel.output.recv().await.unwrap().error.is_none());
            }
            channels[0]
                .local
                .send(LocalEvent::Retry {
                    now,
                    carriers: vec![final_vertex.id().unwrap()],
                })
                .await
                .unwrap();
            let retry = channels[0].output.recv().await.unwrap();
            assert_eq!(driver_publish(retry, &mut channels, &m).await, final_vertex);
            channels[0]
                .local
                .send(LocalEvent::Retry {
                    now,
                    carriers: vec![final_vertex.id().unwrap()],
                })
                .await
                .unwrap();
            assert!(
                channels[0].output.recv().await.unwrap().carriers.is_empty(),
                "bounded retry cadence"
            );
            // Final receipt is durable decision evidence, not applied ordering or execution.
            for store in &stores {
                assert!(
                    store.slot_applications().unwrap().is_empty(),
                    "final receipt is not application"
                );
                assert!(
                    store.slot_application_requests().unwrap().is_empty(),
                    "no implicit AdvanceSlot"
                );
            }
            for channel in &mut channels {
                channel
                    .frames
                    .send(net::wire::Frame {
                        len: 0,
                        sent_at_nanos: 0,
                        message: net::wire::Message::Payload(
                            batches[&vertices[0].payload_hash].clone(),
                        ),
                    })
                    .await
                    .unwrap();
                let premature = channel.output.recv().await.unwrap();
                assert!(
                    premature
                        .error
                        .as_ref()
                        .unwrap()
                        .contains("not required by applied certified ordering"),
                    "final receipt must not admit payloads"
                );
                channel
                    .local
                    .send(LocalEvent::BuildReady { at: 40 })
                    .await
                    .unwrap();
                let output = channel.output.recv().await.unwrap();
                assert!(output.error.is_none(), "{:?}", output.error);
                assert!(
                    output.build.shares.is_empty(),
                    "final receipt did not apply slot"
                );
                channel
                    .local
                    .send(LocalEvent::ApplyCertifiedSlot { at: 41 })
                    .await
                    .unwrap();
                let output = channel.output.recv().await.unwrap();
                assert!(output.error.is_none(), "{:?}", output.error);
                assert!(
                    output.build.shares.is_empty(),
                    "applied slot waits for payloads"
                );
            }
            for store in &stores {
                assert!(
                    store.slot_applications().unwrap().is_empty(),
                    "no legacy application path"
                );
            }
            let mut shares = vec![Vec::new(); 3];
            // Only the applied certified prefix admits payloads. Unneeded ones remain errors.
            for batch in batches.values() {
                for (i, channel) in channels.iter_mut().enumerate() {
                    channel
                        .frames
                        .send(net::wire::Frame {
                            len: 0,
                            sent_at_nanos: 0,
                            message: net::wire::Message::Payload(batch.clone()),
                        })
                        .await
                        .unwrap();
                    let output = channel.output.recv().await.unwrap();
                    shares[i].extend(output.build.shares);
                }
            }
            assert!(
                !shares[0].is_empty(),
                "authored final decision executed after explicit apply"
            );
            assert_eq!(
                shares[0].iter().map(|s| &s.header).collect::<Vec<_>>(),
                shares[1].iter().map(|s| &s.header).collect::<Vec<_>>()
            );
            assert_eq!(
                shares[0].iter().map(|s| &s.header).collect::<Vec<_>>(),
                shares[2].iter().map(|s| &s.header).collect::<Vec<_>>()
            );
            cancel.send(true).unwrap();
            for task in tasks {
                let (owner, result) = task.await.unwrap();
                result.unwrap();
                assert_eq!(
                    owner
                        .finalization()
                        .execution()
                        .snapshot()
                        .applications()
                        .len(),
                    1,
                    "one authenticated application"
                );
                assert!(
                    !owner
                        .finalization()
                        .execution()
                        .snapshot()
                        .vertices()
                        .is_empty()
                );
            }
        })
        .await
        .expect("owned protocol integration timed out");
    });
}

#[test]
fn owned_publication_discovery_recovers_lost_output_and_reopen_without_signing() {
    use super::local_authoring::{AuthoringAction, AuthoringRequest};
    use std::time::{Duration, Instant};
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let prefix: Vec<_> = vertices.into_iter().filter(|v| v.round < 3).collect();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = open_event_pump_owner(&store, &bootstrap, &m);
    let anchor = owner.finalization().finalizer().head().clone();
    let policy = super::pacemaker::Policy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    owner
        .enable_authoring(authoring_node(&m, &[]), policy, Duration::from_millis(1))
        .unwrap();
    assert!(
        owner
            .enable_authoring(authoring_node(&m, &[]), policy, Duration::from_millis(1))
            .unwrap_err()
            .contains("already pinned")
    );
    let wal_path = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal_path).unwrap();
    // A valid but conflicting prefix must not be inserted when a later input is invalid.
    let poison = signed(&m, 0, 0, vec![], [99; 32]);
    let mut bad_signature = prefix[1].clone();
    bad_signature.signature[0] ^= 1;
    let foreign = signed_for_chain(&m, 1, 0, vec![], [0; 32], b"foreign-chain");
    let mut oversized_refs = prefix[0].clone();
    oversized_refs.references = vec![prefix[0].id().unwrap(); (2 * 1024 * 1024) / 48 + 1];
    let mut oversized_field = prefix[0].clone();
    oversized_field.references = vec![VertexId {
        round: 0,
        author: vec![0; crypto::encoding::MAX_FIELD_LEN + 1],
        digest: [0; 32],
    }];
    let mut large = prefix[0].clone();
    large.signature = vec![0; 750_000];
    for (inputs, expected) in [
        (vec![poison.clone(), foreign], "pinned chain"),
        (vec![poison, bad_signature], ""),
        (vec![oversized_refs], "reference list"),
        (vec![oversized_field], "codec limit"),
        (vec![large.clone(), large.clone(), large], "two MiB"),
    ] {
        let error = owner
            .author_local(AuthoringRequest {
                round: 3,
                vertices: inputs,
                action: AuthoringAction::Pol,
            })
            .unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert_eq!(
            std::fs::read(&wal_path).unwrap(),
            before,
            "invalid import cannot reserve or complete a carrier"
        );
        assert!(owner.completed_publications(0).unwrap().is_empty());
    }
    // Successful use of the entire import budget proves failed preflights consumed none.
    let mut full_budget_prefix = prefix.clone();
    full_budget_prefix.resize(4096, prefix[0].clone());
    let first = owner
        .author_local(AuthoringRequest {
            round: 3,
            vertices: full_budget_prefix,
            action: AuthoringAction::Proposal(lineage.entries[0].proposal.clone()),
        })
        .unwrap();
    assert_eq!(
        first.len(),
        1,
        "invalid imports did not poison the causal prefix"
    );
    let expected = net::wire::frame(&first[0], 0).unwrap();
    drop(first); // No retained carrier ID or envelope: discovery is the recovery path.
    let completed_wal = std::fs::read(&wal_path).unwrap();
    let ids = owner.completed_publications(0).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(owner.completed_publications(1).unwrap().is_empty());
    assert!(owner.completed_publications(usize::MAX).unwrap().is_empty());
    let retry = owner.retry_local(Instant::now(), &ids).unwrap();
    assert_eq!(net::wire::frame(&retry[0], 0).unwrap(), expected);
    assert_eq!(
        std::fs::read(&wal_path).unwrap(),
        completed_wal,
        "discovery/retry do not reserve or complete again"
    );
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let finalizer = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        bootstrap.agreement.context.chain_id().to_vec(),
        m.consensus[0].id.clone(),
        m.consensus[0].private_key.clone(),
        anchor,
        0,
    )
    .unwrap();
    let mut owner = JournaledFinalization::open(
        Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
        chain::genesis_state(&m.accounts).unwrap(),
        finalizer,
    )
    .unwrap();
    assert_eq!(
        owner.completed_publications(0).unwrap(),
        ids,
        "discovery needs no authoring setup after reopen"
    );
    owner
        .enable_authoring(
            authoring_node(&m, &prefix),
            policy,
            Duration::from_millis(1),
        )
        .unwrap();
    let rediscovered = owner.completed_publications(0).unwrap();
    let retry = owner.retry_local(Instant::now(), &rediscovered).unwrap();
    assert_eq!(net::wire::frame(&retry[0], 0).unwrap(), expected);
    assert_eq!(std::fs::read(&wal_path).unwrap(), completed_wal);
    let mut sibling = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    sibling
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: validator::slot_agreement::AgreementPhase::Prevote,
        })
        .unwrap();
    assert!(
        owner.completed_publications(0).is_err(),
        "discovery checks stale ownership"
    );
}
