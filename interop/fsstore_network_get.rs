//! STY-G1e: real Iroh GET wire bytes checked by the independent Staya Bao decoder.
//! Only ephemeral direct loopback QUIC, explicit peer and hash authorization.
//! This does NOT enable Akula user-file access, relay or crash-safe resume.

use iroh::{Endpoint, EndpointId, RelayMode, SecretKey, endpoint::presets, protocol::Router};
use iroh_blobs::{
    BlobsProtocol, Hash,
    api::blobs::BlobStatus,
    protocol::{
        ChunkRanges, ChunkRangesExt, ChunkRangesSeq, GetManyRequest, GetRequest, PushRequest,
        Request,
    },
    provider::events::{
        AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage,
        RequestMode, ThrottleMode,
    },
    store::{fs::FsStore, mem::MemStore},
};
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferError, TransferRequest,
    bao::{MAX_BAO_PROOF_BYTES, verify_bao_range},
};
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(100);
const STEP_TIMEOUT: Duration = Duration::from_secs(8);
const FIRST: std::ops::Range<u64> = 33_333..200_111;
const SECOND: std::ops::Range<u64> = 300_123..405_141;

async fn local_endpoint(secret: SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("private direct-only loopback endpoint")
}

fn deny_by_default(
    allowed_peer: EndpointId,
    permitted_hash: Hash,
) -> (EventSender, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let mask = EventMask {
        connected: ConnectMode::Intercept,
        get: RequestMode::Intercept,
        get_many: RequestMode::Disabled,
        push: RequestMode::Disabled,
        observe: ObserveMode::Intercept,
        throttle: ThrottleMode::None,
    };
    let (events, mut rx) = EventSender::channel(64, mask);
    let refused = Arc::new(AtomicUsize::new(0));
    let refused_in_worker = Arc::clone(&refused);
    let worker = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                ProviderMessage::ClientConnected(msg) => {
                    let allowed = msg.endpoint_id == Some(allowed_peer);
                    if !allowed {
                        refused_in_worker.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = msg
                        .tx
                        .send(if allowed {
                            Ok(())
                        } else {
                            Err(AbortReason::Permission)
                        })
                        .await;
                }
                ProviderMessage::GetRequestReceived(msg) => {
                    let allowed =
                        msg.request.ranges.is_blob() && msg.request.hash == permitted_hash;
                    let _ = msg
                        .tx
                        .send(if allowed {
                            Ok(())
                        } else {
                            Err(AbortReason::Permission)
                        })
                        .await;
                }
                ProviderMessage::ObserveRequestReceived(msg) => {
                    let _ = msg.tx.send(Err(AbortReason::Permission)).await;
                }
                _ => {}
            }
        }
    });
    (events, worker, refused)
}

/// Read an actual QUIC Get response, preserving all Bao proof bytes before
/// decoding. The only extra frame is Iroh's 8-byte little-endian length.
/// This is NOT a second implementation of peer auth: server events enforce it.
async fn bounded_wire_get(
    conn: &iroh::endpoint::Connection,
    hash: Hash,
    range: std::ops::Range<u64>,
) -> Result<Vec<u8>, String> {
    let get = GetRequest::blob_ranges(hash, ChunkRanges::bytes(range));
    let request = postcard::to_stdvec(&Request::Get(get))
        .map_err(|e| format!("serialize get request: {e}"))?;
    assert!(request.len() <= 1024 * 1024);
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open QUIC: {e}"))?;
    send.write_all(&request)
        .await
        .map_err(|e| format!("send GET: {e}"))?;
    send.finish().map_err(|e| format!("finish GET: {e}"))?;
    recv.read_to_end(MAX_BAO_PROOF_BYTES + 8)
        .await
        .map_err(|e| format!("read bounded GET: {e}"))
}

/// Not a peer statement: the trusted root and length come from local fixture
/// metadata, which in a production adapter must come from Akula grants.
fn verify_network_response(
    manifest: Manifest,
    range: std::ops::Range<u64>,
    wire: &[u8],
    original: &[u8],
) -> Result<(), TransferError> {
    if wire.len() < 8 {
        return Err(TransferError::CorruptData);
    }
    let size = u64::from_le_bytes(
        wire[..8]
            .try_into()
            .map_err(|_| TransferError::CorruptData)?,
    );
    if size != manifest.size {
        return Err(TransferError::CorruptData);
    }
    let requested = ByteRange::new(range.start, range.end, manifest.size)?;
    let req = TransferRequest::new(manifest, requested)?;
    let verified = verify_bao_range(&req, &wire[8..])?;
    if verified.bytes() != &original[range.start as usize..range.end as usize] {
        return Err(TransferError::CorruptData);
    }
    Ok(())
}

fn deterministic_bytes() -> Vec<u8> {
    (0..(1024 * 1024 + 137))
        .map(|i| ((i * 43 + 17) % 251) as u8)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_quic_get_bao_peer_policy_reconnect() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let root = std::env::temp_dir().join(format!(
            "staya-g1e-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "local".to_owned()),
        ));
        assert!(!root.exists(), "reject unowned reused test directory");
        fs::create_dir(&root).unwrap();

        let data = deterministic_bytes();
        let wanted = Hash::new(&data);
        let authorized_key = SecretKey::generate();
        let outsider_key = SecretKey::generate();
        let server_key = SecretKey::generate();

        let store = FsStore::load(&root).await.expect("private provider store");
        let retained = store.add_slice(&data).await.expect("seed authorized file");
        assert_eq!(retained.hash, wanted);
        let forbidden_tag = store.add_slice(b"other forbidden blob").await.expect("seed denied hash");
        let (events, worker, refused) = deny_by_default(authorized_key.public(), wanted);
        let endpoint = local_endpoint(server_key).await;
        let router = Router::builder(endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, Some(events)))
            .spawn();
        let client = local_endpoint(authorized_key).await;
        let address = router.endpoint().addr();
        let connection = client.connect(address.clone(), iroh_blobs::ALPN)
            .await.expect("direct authenticated QUIC connects");
        let manifest = Manifest {
            id: ContentId(*wanted.as_bytes()),
            size: data.len() as u64,
        };

        let first = tokio::time::timeout(
            STEP_TIMEOUT, bounded_wire_get(&connection, wanted, FIRST.clone())
        ).await.expect("first GET deadline").expect("first wire response");
        verify_network_response(manifest, FIRST.clone(), &first, &data).expect("Staya independently verified on-wire proof");

        // Negative proof fixtures mutate the *captured wire response*, never
        // the FsStore, and may not mint a verified range.
        let mut tampered = first.clone();
        let flip = tampered.len() / 2;
        tampered[flip] ^= 0x80;
        assert!(matches!(
            verify_network_response(manifest, FIRST.clone(), &tampered, &data),
            Err(TransferError::CorruptData)
        ));
        let mut appended = first.clone();
        appended.push(0);
        assert!(matches!(
            verify_network_response(manifest, FIRST.clone(), &appended, &data),
            Err(TransferError::CorruptData)
        ));
        let mut wrong_size = first.clone();
        wrong_size[..8].copy_from_slice(&(manifest.size + 1).to_le_bytes());
        assert!(matches!(
            verify_network_response(manifest, FIRST.clone(), &wrong_size, &data),
            Err(TransferError::CorruptData)
        ));

        // Authorized transport identity does not confer access to other hash.
        let forbidden_attempt = tokio::time::timeout(
            STEP_TIMEOUT, bounded_wire_get(&connection, forbidden_tag.hash, FIRST.clone())
        ).await.expect("forbidden hash request settled");
        assert!(forbidden_attempt.is_err() || forbidden_attempt.unwrap().len() < 8,
            "unlisted hash GET unexpectedly returned content");

        // A disabled request kind must not bypass single-blob GET policy.
        let unsolicited = MemStore::new();
        let malicious = unsolicited.add_slice(b"unsolicited transfer").await.unwrap();
        let _ = tokio::time::timeout(
            STEP_TIMEOUT,
            unsolicited.remote().execute_push(
                connection.clone(),
                PushRequest::new(malicious.hash, ChunkRangesSeq::root()),
            ).complete(),
        ).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(matches!(
            store.blobs().status(malicious.hash).await.expect("no unsolicited blob"),
            BlobStatus::NotFound
        ), "forbidden PUSH mutated provider store");

        let get_many = tokio::time::timeout(
            STEP_TIMEOUT,
            unsolicited.remote().execute_get_many(
                connection.clone(),
                GetManyRequest::new(vec![wanted], ChunkRangesSeq::all()),
            ).complete(),
        ).await.expect("disabled get_many settles");
        assert!(get_many.is_err(), "GET_MANY bypassed authorization");

        let outsider = local_endpoint(outsider_key).await;
        if let Ok(untrusted) = outsider.connect(address.clone(), iroh_blobs::ALPN).await {
            let result = tokio::time::timeout(
                STEP_TIMEOUT, bounded_wire_get(&untrusted, wanted, FIRST.clone())
            ).await.expect("outsider GET settled");
            assert!(result.is_err() || result.unwrap().len() < 8, "unknown peer received bytes");
            untrusted.close(0u8.into(), b"reject outsider");
        }
        // Connecting to an inaccessible or broken endpoint is NOT evidence of
        // admission control. Require an explicit provider-side denial event.
        assert!(refused.load(Ordering::SeqCst) > 0,
            "unknown endpoint was not explicitly rejected by provider policy");

        // Two independent QUIC connections; verified ranges are not persisted.
        connection.close(0u8.into(), b"deliberate reconnect");
        drop(connection);
        let reconnected = client.connect(address, iroh_blobs::ALPN)
            .await.expect("new QUIC connection");
        let second = tokio::time::timeout(
            STEP_TIMEOUT, bounded_wire_get(&reconnected, wanted, SECOND.clone())
        ).await.expect("second GET deadline").expect("second wire response");
        verify_network_response(manifest, SECOND.clone(), &second, &data)
            .expect("new QUIC connection independently validated second range");

        if let Ok(dest) = std::env::var("STY_QUIC_OUTPUT_DIR") {
            fs::create_dir_all(&dest).unwrap();
            fs::write(std::path::Path::new(&dest).join("first.bin"), &first).unwrap();
            fs::write(std::path::Path::new(&dest).join("second.bin"), &second).unwrap();
            fs::write(std::path::Path::new(&dest).join("manifest.txt"), format!(
                "blake3={}\nsize={}\nfirst={}-{}\nsecond={}-{}\n",
                wanted.to_hex(), manifest.size, FIRST.start, FIRST.end,
                SECOND.start, SECOND.end,
            )).unwrap();
        }

        reconnected.close(0u8.into(), b"test finished");
        router.shutdown().await.expect("stop provider");
        client.close().await;
        outsider.close().await;
        worker.abort();
        drop(retained);
        drop(forbidden_tag);
        // Router::shutdown delegates to BlobsProtocol::shutdown and already
        // closes this FsStore. A second RPC shutdown can return OneshotClosed.
        drop(store);
        fs::remove_dir_all(&root).expect("remove only owned private fixture");
        println!(
            "STY_G1E_QUIC actual_get=true bao=true direct=true reconnect=true unauthorized_get_hold=true push_hold=true get_many_hold=true relay_tested=false durable_resume=false file_gate=false"
        );
    }).await.expect("bounded STY-G1e QUIC interop timeout");
}

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

#[tokio::test(flavor = "multi_thread")]
async fn real_second_quic_get_stages_only_unverified_bytes() {
    use partial_adapter::{
        audit_clean_closed_fixture, stage_verified_fixture, stage_with_inflight_budget,
    };
    use staya_custody_lab::{
        StoreLease,
        admission::{Limits, SharedAdmission},
    };
    use staya_transfer::{
        TransferBudget,
        planner::{MissingRanges, VerifiedCheckpoint},
        recovery::{BaoStorageProfile, StoreIdentity},
    };
    use std::sync::atomic::AtomicBool;

    tokio::time::timeout(TEST_TIMEOUT, async {
        const START: u64 = 32_768;
        const END: u64 = 196_608;
        let root = std::env::temp_dir().join(format!(
            "staya-g2-06b-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!root.exists(), "fresh private fixture only");
        let provider_dir = root.join("provider");
        let receiver_dir = root.join("receiver");
        fs::create_dir_all(&provider_dir).unwrap();
        fs::create_dir_all(&receiver_dir).unwrap();

        let data = deterministic_bytes();
        let trusted_hash = Hash::new(&data);
        let manifest = Manifest {
            id: ContentId(*trusted_hash.as_bytes()),
            size: data.len() as u64,
        };
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };

        // Real pinned release/fork provider and an explicit locally permitted
        // QUIC peer, not a peer-provided bitmap or untrusted object identity.
        let source = FsStore::load(&provider_dir).await.unwrap();
        let provider_tag = source.add_slice(&data).await.unwrap();
        assert_eq!(provider_tag.hash, trusted_hash);
        let client_key = SecretKey::generate();
        let (events, policy_worker, _refused) =
            deny_by_default(client_key.public(), trusted_hash);
        let server_endpoint = local_endpoint(SecretKey::generate()).await;
        let router = Router::builder(server_endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&source, Some(events)))
            .spawn();
        let client = local_endpoint(client_key).await;
        let server_addr = router.endpoint().addr();
        let first_conn = client.connect(server_addr.clone(), iroh_blobs::ALPN)
            .await
            .expect("authorized first direct QUIC connection");

        // Stage ONE interior aligned range to the real receiver FsStore.
        // The stage permit is bounded and cannot establish durable authority.
        let owner = StoreLease::acquire(&receiver_dir).unwrap();
        let partial = FsStore::load(&receiver_dir).await.unwrap();
        let initial = ByteRange::new(START, END, manifest.size).unwrap();
        let first_wire = tokio::time::timeout(
            STEP_TIMEOUT,
            bounded_wire_get(&first_conn, trusted_hash, START..END),
        )
        .await
        .expect("first GET deadline")
        .expect("real first QUIC wire bytes");
        let ledger = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: 2 * 1024 * 1024,
            max_open_handles: 4,
            max_retries_per_object: 0,
        })
        .unwrap();
        let cancelled = AtomicBool::new(false);
        let (_accepted, permit) = stage_with_inflight_budget(
            &owner, &ledger, &partial, identity, initial.clone(), &first_wire, &cancelled,
        )
        .await
        .expect("bounded import of first authenticated wire range");
        drop(permit);
        assert_eq!(ledger.usage().unwrap(), (0, 0, 0));
        first_conn.close(0u8.into(), b"first GET finished");
        drop(first_conn);
        partial.shutdown().await.expect("quiesce first receiver actor");
        drop(partial);

        // A clean restart is NOT an unexpected process termination. Physical
        // data/outboard Bao validation must match freshly verified first-wire
        // bytes before they are placed into the temporary range planner.
        let persisted = audit_clean_closed_fixture(&receiver_dir, identity, initial.clone())
            .expect("root-anchored physical sparse Bao readback");
        let checked = TransferRequest::new(manifest, initial).unwrap();
        let verified = verify_bao_range(&checked, &first_wire[8..]).unwrap();
        assert_eq!(verified.bytes(), persisted.as_slice());
        let mut checkpoint = VerifiedCheckpoint::empty(manifest);
        checkpoint.record_bao(verified).unwrap();
        let budget = TransferBudget {
            max_inflight_bytes: 1024 * 1024,
            max_sources: 1,
            max_retries: 0,
        };
        let planned: Vec<_> = MissingRanges::from_checkpoint(manifest, &checkpoint, budget)
            .unwrap()
            .map(|range| (range.start(), range.end()))
            .collect();
        assert_eq!(planned, vec![(0, START), (END, manifest.size)]);
        assert_eq!(
            planned.iter().map(|(start, end)| end - start).sum::<u64>(),
            manifest.size - (END - START)
        );

        // Reconnect over a second actual QUIC connection. Every GET and
        // receiver import is issued strictly from the independently checked
        // missing-range plan, never from FsStore's persisted bitfield alone.
        let second_conn = client.connect(server_addr, iroh_blobs::ALPN)
            .await
            .expect("authorized second QUIC connection");
        let resumed = FsStore::load(&receiver_dir).await.expect("fresh FsStore actor");
        let mut captured = Vec::new();
        for &(start, end) in &planned {
            assert!(end <= START || start >= END, "re-GET of authenticated bytes");
            let wire = tokio::time::timeout(
                STEP_TIMEOUT,
                bounded_wire_get(&second_conn, trusted_hash, start..end),
            )
            .await
            .expect("second-phase GET deadline")
            .expect("second-phase real QUIC response");
            let wanted = ByteRange::new(start, end, manifest.size).unwrap();
            let request = TransferRequest::new(manifest, wanted.clone()).unwrap();
            let checked_wire = verify_bao_range(&request, &wire[8..]).unwrap();
            assert_eq!(checked_wire.bytes(), &data[start as usize..end as usize]);
            stage_verified_fixture(&resumed, identity, wanted, &wire)
                .await
                .expect("import missing authenticated bytes into reopened FsStore");
            captured.push(wire);
        }
        assert_eq!(captured.len(), 2);
        let reassembled = resumed
            .blobs()
            .get_bytes(trusted_hash)
            .await
            .expect("FsStore must expose the fully reconstructed object");
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(Hash::new(reassembled.as_ref()), trusted_hash);
        assert_eq!(reassembled.as_ref(), data.as_slice());

        // Optional CI evidence consists of exact raw GET bytes and a stable,
        // human-readable list of requested ranges and final BLAKE3 root.
        if let Some(dest) = std::env::var_os("STY_G2_06B_OUTPUT_DIR") {
            fs::create_dir_all(&dest).unwrap();
            let dest = std::path::PathBuf::from(dest);
            fs::write(dest.join("first.wire"), &first_wire).unwrap();
            fs::write(dest.join("missing-0.wire"), &captured[0]).unwrap();
            fs::write(dest.join("missing-1.wire"), &captured[1]).unwrap();
            fs::write(
                dest.join("inventory.txt"),
                format!(
                    "trusted_blake3={}\nsize={}\nretained={START}-{END}\nmissing={}-{}\nmissing={}-{}\ncompleted_blake3={}\n",
                    trusted_hash.to_hex(),
                    manifest.size,
                    planned[0].0,
                    planned[0].1,
                    planned[1].0,
                    planned[1].1,
                    Hash::new(reassembled.as_ref()).to_hex(),
                ),
            )
            .unwrap();
        }

        second_conn.close(0u8.into(), b"second GET complete");
        resumed.shutdown().await.expect("quiesce completed receiver actor");
        drop(resumed);

        // The same completed object must also survive a second CLEAN reload.
        let reopened = FsStore::load(&receiver_dir).await.unwrap();
        let bytes = reopened.blobs().get_bytes(trusted_hash).await.unwrap();
        assert_eq!(Hash::new(bytes.as_ref()), trusted_hash);
        assert_eq!(bytes.as_ref(), data.as_slice());
        reopened.shutdown().await.unwrap();
        drop(reopened);
        drop(owner);

        router.shutdown().await.expect("stop real provider");
        client.close().await;
        policy_worker.abort();
        drop(provider_tag);
        drop(source);
        fs::remove_dir_all(&root).expect("remove private test data only");
        println!(
            "STY_G2_06B real_quic_gets=3 second_connection=true first_retained={START}-{END} second_missing_ranges=2 full_blake3=true clean_reopen=true process_kill=false relay=false file_gate=false"
        );
    })
    .await
    .expect("bounded G2-06b network partial-resume fixture");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn linux_killed_receiver_redownloads_uncommitted_or_resumes_verified() {
    use partial_adapter::{
        audit_clean_closed_fixture, stage_verified_fixture, stage_with_inflight_budget,
    };
    use staya_custody_lab::{
        StoreLease,
        admission::{Limits, SharedAdmission},
        checkpoint::{CheckpointClaim, IROH_PREORDER_16K, read_candidates},
        partial_barrier::publish_after_quiescent_audit,
    };
    use staya_transfer::{
        TransferBudget,
        planner::{MissingRanges, VerifiedCheckpoint},
        recovery::{BaoStorageProfile, StoreIdentity},
    };
    use std::{
        io,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::atomic::AtomicBool,
        thread,
        time::Instant,
    };

    const FIRST_START: u64 = 32_768;
    const FIRST_END: u64 = 196_608;
    const TEST_MODE: &str = "STY_G2_06C_RECEIVER_CHILD";
    const TEST_ROOT: &str = "STY_G2_06C_RECEIVER_ROOT";
    const READY: &str = ".g2-06c-ready";
    const FIRST_WIRE: &str = ".g2-06c-first.wire";

    struct TerminateOnDrop(Child);
    impl Drop for TerminateOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // This is a real independent Linux receiver process; the OS terminates
    // its FsStore actor with SIGKILL, NOT a graceful Rust drop/shutdown.
    if let Ok(mode) = std::env::var(TEST_MODE) {
        assert!(mode == "uncommitted" || mode == "checkpointed");
        let dir = PathBuf::from(std::env::var_os(TEST_ROOT).expect("child private root"));
        let owner = StoreLease::acquire(&dir).expect("child owns Linux file lock");
        let data = deterministic_bytes();
        let root = Hash::new(&data);
        let manifest = Manifest {
            id: ContentId(*root.as_bytes()),
            size: data.len() as u64,
        };
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        let wire = fs::read(dir.join(FIRST_WIRE)).expect("parent supplied actual QUIC wire");
        let interval = ByteRange::new(FIRST_START, FIRST_END, manifest.size).unwrap();
        let quota = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: 2 * 1024 * 1024,
            max_open_handles: 4,
            max_retries_per_object: 0,
        })
        .unwrap();
        let cancelled = AtomicBool::new(false);
        let actor = FsStore::load(&dir).await.expect("pinned FsStore in child");
        let (_uncommitted, permit) = stage_with_inflight_budget(
            &owner,
            &quota,
            &actor,
            identity,
            interval.clone(),
            &wire,
            &cancelled,
        )
        .await
        .expect("verified first actual QUIC proof imported");
        drop(permit);

        if mode == "checkpointed" {
            actor.shutdown().await.expect("actor quiesced before claim");
            drop(actor);
            let claim = CheckpointClaim {
                sequence: 1,
                content_root: manifest.id.0,
                object_len: manifest.size,
                bao_profile: IROH_PREORDER_16K,
                start: FIRST_START,
                end: FIRST_END,
            };
            publish_after_quiescent_audit(&owner, claim, |_| {
                let bytes = audit_clean_closed_fixture(&dir, identity, interval)
                    .map_err(io::Error::other)?;
                if bytes != data[FIRST_START as usize..FIRST_END as usize] {
                    return Err(io::Error::other("physical Bao readback mismatch"));
                }
                Ok(())
            })
            .expect("Linux quiescent Bao and directory barrier before candidate");
        } else {
            // The actor remains live, and all its unsynced bytes are UNTRUSTED.
            let _ = &actor;
        }

        fs::write(dir.join(READY), mode.as_bytes()).unwrap();
        fs::File::open(dir.join(READY)).unwrap().sync_all().unwrap();
        tokio::time::sleep(Duration::from_secs(90)).await;
        panic!("child must be forcibly killed by parent");
    }

    tokio::time::timeout(Duration::from_secs(170), async {
        let base = std::env::temp_dir().join(format!(
            "staya-g2-06c-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!base.exists(), "never reuse a test-owned directory");
        fs::create_dir(&base).unwrap();
        let provider_dir = base.join("provider");
        fs::create_dir(&provider_dir).unwrap();
        let data = deterministic_bytes();
        let trusted_root = Hash::new(&data);
        let manifest = Manifest {
            id: ContentId(*trusted_root.as_bytes()),
            size: data.len() as u64,
        };
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        let provider = FsStore::load(&provider_dir).await.unwrap();
        let provider_tag = provider.add_slice(&data).await.unwrap();
        assert_eq!(provider_tag.hash, trusted_root);
        let key = SecretKey::generate();
        let (events, policy_worker, _refused) =
            deny_by_default(key.public(), trusted_root);
        let endpoint = local_endpoint(SecretKey::generate()).await;
        let router = Router::builder(endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&provider, Some(events)))
            .spawn();
        let client = local_endpoint(key).await;
        let address = router.endpoint().addr();

        for mode in ["uncommitted", "checkpointed"] {
            let receiver_dir = base.join(mode);
            fs::create_dir(&receiver_dir).unwrap();

            // First real QUIC GET precedes the receiver's separate process
            // import. The first network response itself remains in the
            // parent test harness; production recovery cannot depend on it.
            let first = client.connect(address.clone(), iroh_blobs::ALPN)
                .await
                .expect("authorized first connection");
            let first_wire = tokio::time::timeout(
                STEP_TIMEOUT,
                bounded_wire_get(&first, trusted_root, FIRST_START..FIRST_END),
            )
            .await
            .expect("bounded first QUIC GET")
            .expect("real network data");
            verify_network_response(
                manifest,
                FIRST_START..FIRST_END,
                &first_wire,
                &data,
            )
            .unwrap();
            first.close(0u8.into(), b"pre-kill phase complete");
            drop(first);
            fs::write(receiver_dir.join(FIRST_WIRE), &first_wire).unwrap();

            let child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("linux_killed_receiver_redownloads_uncommitted_or_resumes_verified")
                .arg("--nocapture")
                .env(TEST_MODE, mode)
                .env(TEST_ROOT, &receiver_dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start independent receiver process");
            let mut process = TerminateOnDrop(child);
            let ready = receiver_dir.join(READY);
            let started = Instant::now();
            while !ready.is_file() {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "child receiver exited before crash cut-point"
                );
                assert!(
                    started.elapsed() < Duration::from_secs(45),
                    "receiver could not import actual network bytes and reach kill point"
                );
                thread::sleep(Duration::from_millis(25));
            }
            assert_eq!(fs::read_to_string(&ready).unwrap(), mode);
            assert!(
                matches!(
                    StoreLease::acquire(&receiver_dir),
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
                ),
                "live receiver must exclude a second writer specifically with WouldBlock"
            );
            process.0.kill().expect("deliver real OS SIGKILL");
            let exit = process.0.wait().expect("reap killed receiver");
            assert!(!exit.success(), "child did not terminate abnormally");
            drop(process);

            // Parent is a NEW, independent receiver process relative to
            // the killed writer. Only locally provisioned immutable root,
            // size, profile and freshly verified physical bytes can permit
            // any resumed skip. No journal/bitfield is proof by itself.
            let owner = StoreLease::acquire(&receiver_dir)
                .expect("reclaim exclusive storage after receiver SIGKILL");
            let candidates = read_candidates(
                &owner,
                manifest.id.0,
                manifest.size,
                IROH_PREORDER_16K,
            )
            .unwrap();
            let mut checkpoint = VerifiedCheckpoint::empty(manifest);
            let permitted_skip = mode == "checkpointed";
            if permitted_skip {
                assert_eq!(candidates.len(), 1, "quiescent Linux checkpoint required");
                assert_eq!(candidates[0].start, FIRST_START);
                assert_eq!(candidates[0].end, FIRST_END);
                let bytes = audit_clean_closed_fixture(
                    &receiver_dir,
                    identity,
                    ByteRange::new(FIRST_START, FIRST_END, manifest.size).unwrap(),
                )
                .expect("post-kill physical Bao proof must authenticate");
                let request = TransferRequest::new(
                    manifest,
                    ByteRange::new(FIRST_START, FIRST_END, manifest.size).unwrap(),
                )
                .unwrap();
                let proof = verify_bao_range(&request, &first_wire[8..]).unwrap();
                assert_eq!(proof.bytes(), bytes.as_slice());
                checkpoint.record_bao(proof).unwrap();
            } else {
                assert!(candidates.is_empty(), "killed active actor minted a checkpoint");
                // Uncommitted FsStore data can appear intact by chance:
                // we deliberately do not inspect/reuse any of it.
            }

            let budget = TransferBudget {
                max_inflight_bytes: 1024 * 1024,
                max_sources: 1,
                max_retries: 0,
            };
            let ranges: Vec<_> = MissingRanges::from_checkpoint(manifest, &checkpoint, budget)
                .unwrap()
                .map(|r| (r.start(), r.end()))
                .collect();
            let wanted_bytes: u64 = ranges.iter().map(|(s, e)| e - s).sum();
            if permitted_skip {
                assert_eq!(ranges, vec![(0, FIRST_START), (FIRST_END, manifest.size)]);
                assert_eq!(wanted_bytes, manifest.size - (FIRST_END - FIRST_START));
            } else {
                assert_eq!(wanted_bytes, manifest.size, "unsafe partial bytes were reused");
            }
            // Uncommitted partial contents are quarantined by choosing an
            // entirely new private FsStore root, never the crashed root.
            let (destination, fresh_owner) = if permitted_skip {
                (receiver_dir.clone(), None)
            } else {
                let path = base.join("fresh-uncommitted");
                fs::create_dir(&path).unwrap();
                // The full-retry destination is a *different* physical root.
                // Owning the killed root does not authorize this new writer.
                let fresh_lease = StoreLease::acquire(&path)
                    .expect("full-retry destination must have independent OS custody");
                assert!(
                    matches!(
                        StoreLease::acquire(&path),
                        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
                    ),
                    "a second writer must be excluded from the fresh retry root"
                );
                (path, Some(fresh_lease))
            };
            let receiver = FsStore::load(&destination)
                .await
                .expect("real fresh/resumed receiver FsStore");
            let next = client.connect(address.clone(), iroh_blobs::ALPN)
                .await
                .expect("second real QUIC connection");
            let mut captures = Vec::new();
            for (start, end) in &ranges {
                if permitted_skip {
                    assert!(*end <= FIRST_START || *start >= FIRST_END);
                }
                let wire = tokio::time::timeout(
                    STEP_TIMEOUT,
                    bounded_wire_get(&next, trusted_root, *start..*end),
                )
                .await
                .expect("post-kill QUIC deadline")
                .expect("actual post-kill QUIC GET");
                let interval = ByteRange::new(*start, *end, manifest.size).unwrap();
                stage_verified_fixture(&receiver, identity, interval, &wire)
                    .await
                    .expect("import real authenticated network bytes");
                captures.push(wire);
            }
            assert_eq!(captures.len(), ranges.len());
            let assembled = receiver.blobs().get_bytes(trusted_root)
                .await
                .expect("FsStore must expose a complete verified blob");
            assert_eq!(Hash::new(assembled.as_ref()), trusted_root);
            assert_eq!(assembled.as_ref(), data.as_slice());
            next.close(0u8.into(), b"verified post-kill transfer");
            receiver.shutdown().await.unwrap();
            drop(receiver);
            drop(fresh_owner);

            if let Some(dest) = std::env::var_os("STY_G2_06C_OUTPUT_DIR") {
                let dir = PathBuf::from(dest);
                fs::create_dir_all(&dir).unwrap();
                let mut inventory = format!(
                    "mode={mode}\nexpected_blake3={}\nobject_size={}\n",
                    trusted_root.to_hex(),
                    manifest.size
                );
                for (start, end) in &ranges {
                    inventory.push_str(&format!("get={start}-{end}\n"));
                }
                inventory.push_str(&format!("full_blake3={}\n", trusted_root.to_hex()));
                fs::write(dir.join(format!("{mode}.ranges")), inventory).unwrap();
                fs::write(dir.join(format!("{mode}.first.wire")), &first_wire).unwrap();
                for (idx, wire) in captures.iter().enumerate() {
                    fs::write(dir.join(format!("{mode}.{idx}.wire")), wire).unwrap();
                }
            }
            drop(owner);
        }

        router.shutdown().await.unwrap();
        client.close().await;
        policy_worker.abort();
        drop(provider_tag);
        drop(provider);
        fs::remove_dir_all(&base).expect("delete disposable root only");
        println!(
            "STY_G2_06C linux_sigkill=true independent_receiver_process=true actual_network_get=true recovered_checkpoint_bao=true uncommitted_full_retry=true full_blake3=true power_loss=false relay=false file_gate=false"
        );
    })
    .await
    .expect("bounded Linux real-process crash QUIC integration");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_terminated_receiver_requires_new_full_quic_transfer() {
    use partial_adapter::stage_with_inflight_budget;
    use staya_custody_lab::{
        StoreLease,
        admission::{Limits, SharedAdmission},
        checkpoint::{IROH_PREORDER_16K, read_candidates},
    };
    use staya_transfer::recovery::{BaoStorageProfile, StoreIdentity};
    use std::{
        io,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::atomic::AtomicBool,
        thread,
        time::Instant,
    };

    const START: u64 = 32_768;
    const END: u64 = 196_608;
    const CHILD_FLAG: &str = "STY_G2_06D_CHILD";
    const CHILD_ROOT: &str = "STY_G2_06D_ROOT";
    const READY: &str = ".g2-06d-ready";
    const FIRST_WIRE: &str = ".g2-06d-first.wire";

    struct StopChild(Child);
    impl Drop for StopChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    if std::env::var_os(CHILD_FLAG).is_some() {
        let dir = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root supplied"));
        let lease = StoreLease::acquire(&dir).expect("child exclusive Windows custody");
        let data = deterministic_bytes();
        let trusted = Hash::new(&data);
        let manifest = Manifest {
            id: ContentId(*trusted.as_bytes()),
            size: data.len() as u64,
        };
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        let first = fs::read(dir.join(FIRST_WIRE)).expect("real first GET saved for child");
        verify_network_response(manifest, START..END, &first, &data)
            .expect("received Bao must match trusted immutable root");
        let actor = FsStore::load(&dir)
            .await
            .expect("real pinned receiver FsStore");
        let budget = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: 2 * 1024 * 1024,
            max_open_handles: 4,
            max_retries_per_object: 0,
        })
        .unwrap();
        let stop = AtomicBool::new(false);
        let range = ByteRange::new(START, END, manifest.size).unwrap();
        let (_imported, _permit) =
            stage_with_inflight_budget(&lease, &budget, &actor, identity, range, &first, &stop)
                .await
                .expect("bounded verified import before TerminateProcess");
        lease.validate_fence().unwrap();
        fs::write(dir.join(READY), b"uncommitted").unwrap();
        tokio::time::sleep(Duration::from_secs(100)).await;
        panic!("child should have been forcibly terminated by Windows parent");
    }

    tokio::time::timeout(Duration::from_secs(180), async {
        let base = std::env::temp_dir().join(format!(
            "staya-g2-06d-win-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!base.exists(), "private test root must be new");
        fs::create_dir(&base).unwrap();
        let provider_dir = base.join("provider");
        let failed_dir = base.join("killed");
        let fresh_dir = base.join("retry");
        fs::create_dir(&provider_dir).unwrap();
        fs::create_dir(&failed_dir).unwrap();
        fs::create_dir(&fresh_dir).unwrap();

        let data = deterministic_bytes();
        let trusted = Hash::new(&data);
        let manifest = Manifest {
            id: ContentId(*trusted.as_bytes()),
            size: data.len() as u64,
        };
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        let provider = FsStore::load(&provider_dir).await.unwrap();
        let retained = provider.add_slice(&data).await.unwrap();
        assert_eq!(retained.hash, trusted);
        let peer_key = SecretKey::generate();
        let (events, policy_worker, _refused) =
            deny_by_default(peer_key.public(), trusted);
        let server_endpoint = local_endpoint(SecretKey::generate()).await;
        let router = Router::builder(server_endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&provider, Some(events)))
            .spawn();
        let client = local_endpoint(peer_key).await;
        let address = router.endpoint().addr();

        let first_connection = client.connect(address.clone(), iroh_blobs::ALPN)
            .await
            .expect("first authenticated direct QUIC connection");
        let first = tokio::time::timeout(
            STEP_TIMEOUT,
            bounded_wire_get(&first_connection, trusted, START..END),
        )
        .await
        .expect("bounded first GET")
        .expect("real first GET bytes");
        verify_network_response(manifest, START..END, &first, &data).unwrap();
        first_connection.close(0u8.into(), b"before Windows process crash");
        drop(first_connection);
        fs::write(failed_dir.join(FIRST_WIRE), &first).unwrap();

        let worker = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("windows_terminated_receiver_requires_new_full_quic_transfer")
            .arg("--nocapture")
            .env(CHILD_FLAG, "1")
            .env(CHILD_ROOT, &failed_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("real independent Windows receiver process");
        let mut child = StopChild(worker);
        let marker = failed_dir.join(READY);
        let started = Instant::now();
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "receiver stopped before crash cut-point"
            );
            assert!(
                started.elapsed() < Duration::from_secs(45),
                "receiver did not stage the real QUIC data in time"
            );
            thread::sleep(Duration::from_millis(40));
        }
        assert_eq!(fs::read(&marker).unwrap(), b"uncommitted");
        let busy = StoreLease::acquire(&failed_dir).expect_err("live child must own FsStore");
        assert!(
            matches!(busy.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied),
            "second writer was blocked for an unrelated reason: {busy}"
        );
        child.0.kill().expect("Windows TerminateProcess");
        let result = child.0.wait().expect("reap receiver after process termination");
        assert!(!result.success(), "worker exited normally");
        drop(child);

        // Even if all partial bytes happen to survive process termination,
        // there was no durable checkpoint. NEVER authorize an optimistic skip.
        let former = StoreLease::acquire(&failed_dir)
            .expect("recover Windows OS custody from terminated child");
        let candidates = read_candidates(
            &former,
            manifest.id.0,
            manifest.size,
            IROH_PREORDER_16K,
        )
        .expect("untrusted checkpoint metadata must parse fail-closed");
        assert!(candidates.is_empty(), "terminated actor minted a checkpoint");
        let retry = StoreLease::acquire(&fresh_dir)
            .expect("separate retry store requires separate exclusive ownership");
        let receiver = FsStore::load(&fresh_dir)
            .await
            .expect("fresh real pinned FsStore after TerminateProcess");

        let second_connection = client.connect(address, iroh_blobs::ALPN)
            .await
            .expect("second authenticated direct QUIC connection");
        // TransferRequest::new checks geometry, not bandwidth. The actual
        // one-MiB gates are the planner's budget and Bao verifier. A full
        // object must be fetched in individually bounded Bao-aligned groups.
        let cap = staya_transfer::planner::MAX_PLANNED_RANGE_BYTES;
        assert_eq!(cap % (16 * 1024), 0);
        assert!(manifest.size > cap, "exercise the full-download budget boundary");
        let oversized = TransferRequest::new(
            manifest,
            ByteRange::new(0, manifest.size, manifest.size).unwrap(),
        )
        .expect("geometry is valid; the Bao budget gate must reject it");
        assert!(
            matches!(
                verify_bao_range(&oversized, &[]),
                Err(TransferError::InvalidBudget)
            ),
            "oversized Bao range must be rejected before decoding"
        );
        let empty = staya_transfer::planner::VerifiedCheckpoint::empty(manifest);
        assert!(matches!(
            staya_transfer::planner::MissingRanges::from_checkpoint(
                manifest,
                &empty,
                staya_transfer::TransferBudget {
                    max_inflight_bytes: cap + 1,
                    max_sources: 1,
                    max_retries: 0,
                }
            ),
            Err(TransferError::InvalidBudget)
        ));
        let requested = [(0, cap), (cap, manifest.size)];
        let quota = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: 4 * 1024 * 1024,
            max_open_handles: 4,
            max_retries_per_object: 0,
        })
        .unwrap();
        let stop = AtomicBool::new(false);
        let mut recovered_wires = Vec::new();
        for &(start, end) in &requested {
            assert!(end > start && end - start <= cap);
            let wire = tokio::time::timeout(
                STEP_TIMEOUT,
                bounded_wire_get(&second_connection, trusted, start..end),
            )
            .await
            .expect("bounded post-kill QUIC GET deadline")
            .expect("actual post-kill QUIC range");
            verify_network_response(manifest, start..end, &wire, &data)
                .expect("each bounded GET carries valid root-anchored Bao proof");
            let range = ByteRange::new(start, end, manifest.size).unwrap();
            let (_accepted, permit) = stage_with_inflight_budget(
                &retry, &quota, &receiver, identity, range, &wire, &stop,
            )
            .await
            .expect("fresh store imports verified bounded QUIC range");
            drop(permit);
            assert_eq!(quota.usage().unwrap(), (0, 0, 0));
            recovered_wires.push(wire);
        }
        assert_eq!(recovered_wires.len(), requested.len());
        assert_eq!(
            requested.iter().map(|(start, end)| end - start).sum::<u64>(),
            manifest.size,
            "fallback must re-download every byte without trusting killed store"
        );
        let complete = receiver
            .blobs()
            .get_bytes(trusted)
            .await
            .expect("FsStore exposes newly downloaded complete blob");
        assert_eq!(Hash::new(complete.as_ref()), trusted);
        assert_eq!(complete.as_ref(), data.as_slice());

        if let Some(directory) = std::env::var_os("STY_G2_06D_OUTPUT_DIR") {
            let evidence = PathBuf::from(directory);
            fs::create_dir_all(&evidence).unwrap();
            fs::write(evidence.join("first.wire"), &first).unwrap();
            fs::write(evidence.join("redownload-0.wire"), &recovered_wires[0]).unwrap();
            fs::write(evidence.join("redownload-1.wire"), &recovered_wires[1]).unwrap();
            fs::write(
                evidence.join("inventory.txt"),
                format!(
                    "mode=windows_uncommitted_terminate\nfirst_get={START}-{END}\ncheckpoint_candidates=0\nrecovery_get=0-{}\nrecovery_get={}-{}\nfull_blake3={}\nwindows_durable_skip=false\n",
                    requested[0].1,
                    requested[1].0,
                    requested[1].1,
                    trusted.to_hex(),
                ),
            )
            .unwrap();
        }

        second_connection.close(0u8.into(), b"safe full retry passed");
        receiver.shutdown().await.unwrap();
        drop(receiver);
        drop(retry);
        drop(former);
        router.shutdown().await.unwrap();
        client.close().await;
        policy_worker.abort();
        drop(retained);
        drop(provider);
        fs::remove_dir_all(base).expect("delete only private test fixture");
        println!(
            "STY_G2_06D actual_windows_terminate=true new_quic_connection=true old_untrusted_bytes_skipped=false full_redownload=true full_blake3=true durable_window_checkpoint=false file_gate=false relay=false"
        );
    })
    .await
    .expect("bounded Windows TerminateProcess and QUIC full-redownload integration");
}
