//! STY-G1e: genuine local QUIC GET through pinned iroh-blobs provider.
//!
//! Experimental proof-bearing transport test: both endpoints use Iroh QUIC;
//! the server reads a real FsStore; the client reconstitutes the Bao proof
//! items received from the remote GET and Staya re-verifies them. This is
//! NOT a Roha/noq fork transport acceptance test, an Akula ACL, or crash resume.

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bao_tree::{
    BlockSize, ByteRanges,
    io::{
        BaoContentItem,
        outboard::PreOrderMemOutboard,
        round_up_to_chunks,
        sync::encode_ranges_validated,
    },
};
use iroh::{
    Endpoint, EndpointId, RelayMode,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_blobs::{
    BlobsProtocol,
    get::fsm::{self, BlobContentNext, ConnectedNext, EndBlobNext},
    protocol::{ChunkRanges, ChunkRangesExt, GetRequest},
    store::fs::FsStore,
};
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferBudget, TransferError, TransferRequest,
    bao::verify_bao_range,
    planner::{MissingRanges, VerifiedCheckpoint},
};

const FIRST: u64 = 33_333;
const LAST: u64 = 200_111;
const DATA_SIZE: usize = 256 * 1024 + 17;
const TIMEOUT: Duration = Duration::from_secs(75);

/// This is a *test harness* gate, not production Akula device authorization.
/// In particular, access to an endpoint never grants write access to a Vault.
#[derive(Clone, Debug)]
struct PeerAllowlist {
    allowed: EndpointId,
    blob_handler: BlobsProtocol,
    refused: Arc<AtomicUsize>,
}

impl ProtocolHandler for PeerAllowlist {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if connection.remote_id() != self.allowed {
            self.refused.fetch_add(1, Ordering::SeqCst);
            connection.close(1u32.into(), b"untrusted endpoint");
            return Ok(());
        }
        self.blob_handler.accept(connection).await
    }
}

fn data() -> Vec<u8> {
    (0..DATA_SIZE).map(|i| ((i * 41 + 3) % 251) as u8).collect()
}

async fn offline_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("local QUIC endpoint must bind")
}

/// A client uses the published Iroh GET FSM. Items are first decoded by Iroh,
/// then serialized in their original protocol order into the Bao response bytes
/// for *independent* Staya root verification. The transport's length header is
/// kept separate; Staya never trusts the peer to select its root or length.
async fn fetch_proof_over_quic(connection: Connection, hash: iroh_blobs::Hash) -> (u64, Vec<u8>) {
    let get = GetRequest::builder()
        .root(ChunkRanges::bytes(FIRST..LAST))
        .build(hash);
    let init = fsm::start(connection, get, Default::default());
    let stage = init.next().await.expect("initiate QUIC GET");
    let ConnectedNext::StartRoot(start) = stage.next().await.expect("send authenticated GET") else {
        panic!("unexpected response stage")
    };
    let header = start.next();
    let (mut current, claimed_size) = header.next().await.expect("read remote size");
    let mut proof = Vec::new();
    let mut item_count = 0usize;
    loop {
        match current.next().await {
            BlobContentNext::More((next, item)) => {
                match item.expect("Iroh verifies each received Bao item") {
                    BaoContentItem::Parent(parent) => {
                        proof.extend_from_slice(parent.pair.0.as_bytes());
                        proof.extend_from_slice(parent.pair.1.as_bytes());
                    }
                    BaoContentItem::Leaf(leaf) => proof.extend_from_slice(&leaf.data),
                }
                item_count += 1;
                assert!(proof.len() <= 2 * 1024 * 1024, "never allow unbounded proof buffers");
                current = next;
            }
            BlobContentNext::Done(end) => {
                let EndBlobNext::Closing(closing) = end.next() else {
                    panic!("only one requested object is allowed")
                };
                closing.next().await.expect("end of GET stream");
                break;
            }
        }
    }
    assert!(item_count > 0);
    (claimed_size, proof)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_quic_get_proof_verifies_and_unknown_peer_cannot_read() {
    tokio::time::timeout(TIMEOUT, async {
        let variant = std::env::var("STY_INTEROP_VARIANT")
            .unwrap_or_else(|_| "local".to_owned());
        let root = std::env::temp_dir().join(format!(
            "staya-g1e-quic-{}-{variant}",
            std::process::id(),
        ));
        assert!(!root.exists(), "isolation: never reuse a prior store");
        fs::create_dir_all(&root).expect("create isolated test directory");

        let payload = data();
        let store = FsStore::load(&root).await.expect("create real FsStore");
        let tag = store.add_slice(&payload).await.expect("publish a test object");
        let hash = tag.hash;

        let allowed = offline_endpoint().await;
        let unknown = offline_endpoint().await;
        assert_ne!(allowed.id(), unknown.id());

        let refused = Arc::new(AtomicUsize::new(0));
        let server = offline_endpoint().await;
        let gated = PeerAllowlist {
            allowed: allowed.id(),
            blob_handler: BlobsProtocol::new(&store, None),
            refused: refused.clone(),
        };
        let router = Router::builder(server)
            .accept(iroh_blobs::ALPN, gated)
            .spawn();
        let address = router.endpoint().addr();

        // Real QUIC streams: requested range, proof parents, proof leaves.
        let conn = allowed
            .connect(address.clone(), iroh_blobs::ALPN)
            .await
            .expect("allowed endpoint must connect by direct address");
        assert_eq!(conn.remote_id(), router.endpoint().id());
        let (peer_size, remote_proof) = fetch_proof_over_quic(conn, hash).await;
        assert_eq!(peer_size, DATA_SIZE as u64);

        let manifest = Manifest {
            id: ContentId(*hash.as_bytes()),
            size: DATA_SIZE as u64,
        };
        let request = TransferRequest::new(
            manifest,
            ByteRange::new(FIRST, LAST, manifest.size).unwrap(),
        ).unwrap();

        // Independent Staya verifier does NOT accept an untrusted peer's root.
        let verified = verify_bao_range(&request, &remote_proof)
            .expect("Staya must independently verify the proof received over QUIC");
        assert_eq!(verified.bytes(), &payload[FIRST as usize..LAST as usize]);

        // Cross-check actual network response against a second, local Bao
        // construction. The previous G1d test separately checked FsStore.
        let outboard = PreOrderMemOutboard::create(&payload, BlockSize::from_chunk_log(4));
        let ranges = round_up_to_chunks(&ByteRanges::from(FIRST..LAST));
        let mut reference_proof = Vec::new();
        encode_ranges_validated(payload.as_slice(), &outboard, &ranges, &mut reference_proof)
            .expect("independent Bao producer");
        assert_eq!(remote_proof, reference_proof, "QUIC Bao items must match reference proof");

        let mut checkpoint = VerifiedCheckpoint::empty(manifest);
        checkpoint.record_bao(verified).expect("proof-bound checkpoint");
        let pending = MissingRanges::from_checkpoint(
            manifest,
            &checkpoint,
            TransferBudget {
                max_inflight_bytes: 64 * 1024,
                max_sources: 1,
                max_retries: 0,
            },
        ).unwrap();
        assert!(pending.into_iter().all(|r| r.end() <= FIRST || r.start() >= LAST));

        // A forged root or mutated proof MUST never become verified bytes.
        let mut corrupt = remote_proof.clone();
        corrupt[corrupt.len() / 2] ^= 0x08;
        assert!(matches!(
            verify_bao_range(&request, &corrupt),
            Err(TransferError::CorruptData)
        ));
        let wrong = TransferRequest::new(
            Manifest {
                id: ContentId([0x6f; 32]),
                size: manifest.size,
            },
            request.range.clone(),
        ).unwrap();
        assert!(matches!(
            verify_bao_range(&wrong, &remote_proof),
            Err(TransferError::CorruptData)
        ));

        // The QUIC handshake by itself MUST NOT admit a different peer.
        // This guard is only a test-only EndpointId allowlist, not Vault ACL.
        if let Ok(untrusted_connection) = unknown.connect(address, iroh_blobs::ALPN).await {
            let untrusted = tokio::time::timeout(
                Duration::from_secs(10),
                iroh_blobs::get::request::get_blob(untrusted_connection, hash).bytes(),
            ).await;
            assert!(!matches!(untrusted, Ok(Ok(_))), "unknown peer must receive no content");
        }
        assert_eq!(refused.load(Ordering::SeqCst), 1, "unauthorized peer was rejected");

        router.shutdown().await.expect("stop provider");
        allowed.close().await;
        unknown.close().await;
        drop(tag);
        drop(store);
        fs::remove_dir_all(&root).expect("remove isolated data");

        println!(
            "STY_G1E_QUIC_GET=true real_fsm=true source=FsStore bytes={} range={}..{} \
             bao_staya_verified=true root_tamper_hold=true unknown_peer_hold=true \
             relay_disabled=true crash_resume=false akula_filegate=false",
            DATA_SIZE, FIRST, LAST
        );
    }).await.expect("QUIC test must terminate without hanging");
}
