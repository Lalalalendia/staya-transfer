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
