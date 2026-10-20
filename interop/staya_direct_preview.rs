//! STY-G1f: manual, DIRECT-ONLY, two-process first-transfer preview.
//! It only writes a random private staging directory. It is NOT Akula Sync,
//! a File Gate publisher, an authenticated Device/Vault grant or durable resume.
//! No secret key is persisted or sent through command-line arguments.
#![forbid(unsafe_code)]

use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, endpoint::presets, protocol::Router};
use iroh_blobs::{
    BlobsProtocol, Hash,
    protocol::{ChunkRanges, GetRequest, Request},
    provider::events::{
        AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage,
        RequestMode, ThrottleMode,
    },
    store::fs::FsStore,
};
use staya_custody_lab::{
    StoreLease,
    admission::{Limits, SharedAdmission},
};
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferRequest,
    bao::{MAX_BAO_PROOF_BYTES, verify_bao_range},
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::AtomicBool,
    time::Duration,
};

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

const MAX_OBJECT: u64 = 8 * 1024 * 1024;
const RANGE: u64 = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write into string");
    }
    encoded
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > 8192 || !text.len().is_multiple_of(2) {
        return Err("invalid bounded hex ticket".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|e| format!("hex utf8: {e}"))?;
            u8::from_str_radix(pair, 16).map_err(|e| format!("hex decode: {e}"))
        })
        .collect()
}

fn private_root(label: &str) -> Result<PathBuf, String> {
    let nonce = SecretKey::generate().public().to_string();
    let root = std::env::temp_dir().join(format!("staya-direct-preview-{label}-{nonce}"));
    fs::create_dir(&root).map_err(|e| format!("private staging directory: {e}"))?;
    Ok(root)
}

async fn endpoint(key: SecretKey) -> Result<Endpoint, String> {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|e| format!("direct QUIC endpoint: {e}"))
}

fn deny_unlisted(allowed: EndpointId, hash: Hash) -> (EventSender, tokio::task::JoinHandle<()>) {
    let mask = EventMask {
        connected: ConnectMode::Intercept,
        get: RequestMode::Intercept,
        get_many: RequestMode::Disabled,
        push: RequestMode::Disabled,
        observe: ObserveMode::Intercept,
        throttle: ThrottleMode::None,
    };
    let (sender, mut events) = EventSender::channel(32, mask);
    let loop_task = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                ProviderMessage::ClientConnected(e) => {
                    let allowed_peer = e.endpoint_id == Some(allowed);
                    let _ = e.tx.send(if allowed_peer { Ok(()) } else {
                        Err(AbortReason::Permission)
                    }).await;
                }
                ProviderMessage::GetRequestReceived(e) => {
                    let allowed_object = e.request.hash == hash && e.request.ranges.is_blob();
                    let _ = e.tx.send(if allowed_object { Ok(()) } else {
                        Err(AbortReason::Permission)
                    }).await;
                }
                ProviderMessage::ObserveRequestReceived(e) => {
                    let _ = e.tx.send(Err(AbortReason::Permission)).await;
                }
                _ => {}
            }
        }
    });
    (sender, loop_task)
}

async fn bounded_get(conn: &iroh::endpoint::Connection, hash: Hash, range: std::ops::Range<u64>) -> Result<Vec<u8>, String> {
    if range.start >= range.end || range.end - range.start > RANGE {
        return Err("GET exceeds preview 64 KiB per-range limit".into());
    }
    let get = GetRequest::blob_ranges(hash, ChunkRanges::bytes(range));
    let frame = postcard::to_stdvec(&Request::Get(get))
        .map_err(|e| format!("GET serialization: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("QUIC stream: {e}"))?;
    send.write_all(&frame).await.map_err(|e| format!("send GET: {e}"))?;
    send.finish().map_err(|e| format!("finish GET: {e}"))?;
    recv.read_to_end(MAX_BAO_PROOF_BYTES.min(4 * 1024 * 1024) + 8)
        .await
        .map_err(|e| format!("bounded Bao response: {e}"))
}

async fn serve(source: &Path, allowed_text: &str) -> Result<(), String> {
    // A sender explicitly selects ONE local regular file and ONE allowed peer.
    // No directory enumeration, unsolicited PUSH, GET_MANY or Akula vault.
    let info = fs::symlink_metadata(source).map_err(|e| format!("inspect source: {e}"))?;
    if !info.is_file() || info.file_type().is_symlink() || info.len() == 0 || info.len() > MAX_OBJECT {
        return Err("source must be a nonempty regular file at most 8 MiB, not a symlink".into());
    }
    let bytes = fs::read(source).map_err(|e| format!("read explicit source: {e}"))?;
    if bytes.len() as u64 != info.len() || bytes.is_empty() || bytes.len() as u64 > MAX_OBJECT {
        return Err("source changed during read or exceeded bounded scope".into());
    }
    let allowed = EndpointId::from_str(allowed_text)
        .map_err(|e| format!("invalid explicitly allowed receiver ID: {e}"))?;
    let wanted = Hash::new(&bytes);
    let root = private_root("sender")?;
    let store = FsStore::load(&root).await.map_err(|e| format!("provider FsStore: {e}"))?;
    let tag = store.add_slice(&bytes).await.map_err(|e| format!("seed one authorized object: {e}"))?;
    if tag.hash != wanted {
        return Err("provider hash does not equal selected file".into());
    }
    let (policy, worker) = deny_unlisted(allowed, wanted);
    let ep = endpoint(SecretKey::generate()).await?;
    let router = Router::builder(ep)
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, Some(policy)))
        .spawn();
    let ticket = postcard::to_stdvec(&router.endpoint().addr())
        .map_err(|e| format!("serialize direct endpoint: {e}"))?;
    println!("CONNECT {} {} {}", hex(&ticket), wanted.to_hex(), bytes.len());
    io::stdout().flush().map_err(|e| format!("announce connect: {e}"))?;

    // A blocking stdin reader is isolated from Tokio. The sender lives only
    // while its operator keeps the session open; entering any line closes it.
    tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().read_line(&mut input)
    })
    .await
    .map_err(|e| format!("operator session: {e}"))?
    .map_err(|e| format!("operator input: {e}"))?;
    router.shutdown().await.map_err(|e| format!("provider shutdown: {e}"))?;
    worker.abort();
    drop(tag);
    drop(store);
    fs::remove_dir_all(root).map_err(|e| format!("clean private provider data: {e}"))?;
    Ok(())
}

async fn receive() -> Result<(), String> {
    // The receiver key never leaves this process and is never persisted.
    let private_key = SecretKey::generate();
    println!("PEER_ID {}", private_key.public());
    io::stdout().flush().map_err(|e| format!("announce receiver identity: {e}"))?;
    // Manually transfer the sender's CONNECT line over a trusted out-of-band
    // channel. The sender and root are NOT granted by a network peer inventory.
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("read manual CONNECT: {e}"))?;
    if input.len() > 8192 {
        return Err("manual CONNECT line exceeded bounded size".into());
    }
    let fields: Vec<_> = input.split_whitespace().collect();
    if fields.len() != 4 || fields[0] != "CONNECT" {
        return Err("expected: CONNECT <endpoint-ticket-hex> <trusted-root> <size>".into());
    }
    let address: EndpointAddr = postcard::from_bytes(&from_hex(fields[1])?)
        .map_err(|e| format!("decode endpoint ticket: {e}"))?;
    if address.is_empty() {
        return Err("sender supplied no direct address; relay is disabled".into());
    }
    let trusted_hash = Hash::from_str(fields[2]).map_err(|e| format!("trusted root: {e}"))?;
    let size = fields[3].parse::<u64>().map_err(|e| format!("object size: {e}"))?;
    if size == 0 || size > MAX_OBJECT {
        return Err("object must be nonempty and at most 8 MiB".into());
    }
    let manifest = Manifest { id: ContentId(*trusted_hash.as_bytes()), size };
    let identity = StoreIdentity {
        manifest,
        profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
    };
    let ep = endpoint(private_key).await?;
    let conn = tokio::time::timeout(STEP_TIMEOUT, ep.connect(address, iroh_blobs::ALPN))
        .await
        .map_err(|_| "direct QUIC connection timed out")?
        .map_err(|e| format!("direct QUIC connection: {e}"))?;

    let root = private_root("receiver")?;
    let owner = StoreLease::acquire(&root).map_err(|e| format!("receiver OS custody: {e}"))?;
    let actor = FsStore::load(&root).await.map_err(|e| format!("receiver FsStore: {e}"))?;
    let ledger = SharedAdmission::new(Limits {
        max_partial_objects: 1,
        max_reserved_bytes: 4 * 1024 * 1024,
        max_open_handles: 4,
        max_retries_per_object: 0,
    }).map_err(|e| format!("bounded admission: {e}"))?;
    let cancelled = AtomicBool::new(false);

    let mut start = 0u64;
    while start < size {
        let end = start.saturating_add(RANGE).min(size);
        let range = ByteRange::new(start, end, size).map_err(|e| format!("{e:?}"))?;
        let response = tokio::time::timeout(
            STEP_TIMEOUT, bounded_get(&conn, trusted_hash, start..end)
        ).await.map_err(|_| "bounded QUIC GET timed out")??;
        if response.len() < 8 || u64::from_le_bytes(response[..8].try_into().map_err(|_| "bad prefix")?) != size {
            return Err("untrusted response size mismatch".into());
        }
        let request = TransferRequest::new(manifest, range.clone()).map_err(|e| format!("{e:?}"))?;
        verify_bao_range(&request, &response[8..])
            .map_err(|e| format!("independent Bao root verification: {e:?}"))?;
        let (_, permit) = partial_adapter::stage_with_inflight_budget(
            &owner, &ledger, &actor, identity, range, &response, &cancelled
        ).await?;
        drop(permit);
        start = end;
    }
    ledger.stop_admissions().map_err(|e| format!("stop admissions: {e}"))?;
    if !ledger.admissions_drained().map_err(|e| format!("drain permits: {e}"))? {
        return Err("inflight permit remains after full transfer".into());
    }
    actor.shutdown().await.map_err(|e| format!("quiesce real FsStore: {e}"))?;
    drop(actor);
    // Filesystem readback is independently Bao-authenticated for every group;
    // receiving GET bytes or an FsStore bitmap is not a durable receipt.
    let mut audited = Vec::with_capacity(size as usize);
    let mut offset = 0u64;
    while offset < size {
        let end = offset.saturating_add(RANGE).min(size);
        let range = ByteRange::new(offset, end, size).map_err(|e| format!("{e:?}"))?;
        audited.extend(partial_adapter::audit_clean_closed_fixture(&root, identity, range)?);
        offset = end;
    }
    if audited.len() as u64 != size || *blake3::hash(&audited).as_bytes() != manifest.id.0 {
        return Err("cold physical readback did not match the trusted root".into());
    }
    owner.validate_fence().map_err(|e| format!("final local custody: {e}"))?;

    // Output is an untrusted private staging *copy*, not an Akula user file
    // and not a File Gate publication. Never accept a peer-supplied filename.
    let staged = root.join("verified-staged.bin");
    let mut output = OpenOptions::new().write(true).create_new(true)
        .open(&staged).map_err(|e| format!("new private stage: {e}"))?;
    output.write_all(&audited).map_err(|e| format!("write private stage: {e}"))?;
    output.sync_all().map_err(|e| format!("sync private stage: {e}"))?;
    drop(output);
    conn.close(0u8.into(), b"direct preview complete");
    ep.close().await;
    drop(owner);
    println!("STAGED {} ROOT={} SIZE={} NOT_APPLIED=true", staged.display(), trusted_hash.to_hex(), size);
    io::stdout().flush().map_err(|e| format!("report verified private staging: {e}"))?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    match cmd.as_str() {
        "serve" => {
            let source = args.next().ok_or("serve requires source path")?;
            let peer = args.next().ok_or("serve requires receiver EndpointId")?;
            if args.next().is_some() { return Err("unexpected serve argument".into()); }
            serve(Path::new(&source), &peer).await
        }
        "receive" => {
            if args.next().is_some() { return Err("receive takes no arguments".into()); }
            receive().await
        }
        _ => Err("usage: staya-direct-preview receive | serve <file> <receiver-id>; manual direct-only private staging".into())
    }
}
