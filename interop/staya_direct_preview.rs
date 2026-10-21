//! STY-G1f: manual, DIRECT-ONLY, two-process first-transfer preview.
//! It only writes a random private staging directory. It is NOT Akula Sync,
//! a File Gate publisher, an authenticated Device/Vault grant or durable resume.
//! No secret key is persisted or sent through command-line arguments.
// The only native Win32 FFI is in the audited platform-private module.
#![deny(unsafe_code)]

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, endpoint::presets, protocol::Router,
};
use iroh_blobs::{
    BlobsProtocol, Hash,
    protocol::{ChunkRanges, ChunkRangesExt, GetRequest, Request},
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
    queue::{ItemOutcome, QueuePhase, QueueSelection, SelectedFile},
    recovery::{BaoStorageProfile, StoreIdentity},
    source_stream::{STREAM_BUFFER_BYTES, stream_to_uncommitted_quarantine},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::AtomicBool,
    time::Duration,
};

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "windows_private_stage.rs"]
mod windows_private_stage;

const MAX_OBJECT: u64 = 8 * 1024 * 1024;
// Opt-in real single-file QUIC laboratory path, never a batch/user-vault limit.
const MAX_LARGE_OBJECT: u64 = 16 * 1024 * 1024;
const RANGE: u64 = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
// Global session budget: a broken peer cannot cause unbounded network retries.
const MAX_SESSION_RECONNECTS: u8 = 2;

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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|e| format!("hex utf8: {e}"))?;
            u8::from_str_radix(pair, 16).map_err(|e| format!("hex decode: {e}"))
        })
        .collect()
}

fn private_root(label: &str) -> Result<PathBuf, String> {
    let nonce = SecretKey::generate().public().to_string();
    let root = std::env::temp_dir().join(format!("staya-direct-preview-{label}-{nonce}"));
    // A random name does not imply confidentiality: create_dir with a
    // permissive umask can expose actual staged bytes to other local users.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&root)
            .map_err(|e| format!("private staging directory: {e}"))?;
        let mode = fs::symlink_metadata(&root)
            .map_err(|e| format!("check new staging directory: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o700 {
            return Err("staging directory must be owner-only mode 0700".into());
        }
    }
    #[cfg(windows)]
    {
        windows_private_stage::create_owner_only_directory(&root)
            .map_err(|e| format!("explicit Windows private staging DACL: {e}"))?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err("no safe private staging policy for this operating system".into());
    }
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

fn deny_unlisted(
    allowed: EndpointId,
    hashes: Vec<Hash>,
) -> (EventSender, tokio::task::JoinHandle<()>) {
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
                    let _ =
                        e.tx.send(if allowed_peer {
                            Ok(())
                        } else {
                            Err(AbortReason::Permission)
                        })
                        .await;
                }
                ProviderMessage::GetRequestReceived(e) => {
                    let allowed_object =
                        hashes.contains(&e.request.hash) && e.request.ranges.is_blob();
                    let _ =
                        e.tx.send(if allowed_object {
                            Ok(())
                        } else {
                            Err(AbortReason::Permission)
                        })
                        .await;
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

async fn bounded_get(
    conn: &iroh::endpoint::Connection,
    hash: Hash,
    range: std::ops::Range<u64>,
) -> Result<Vec<u8>, String> {
    if range.start >= range.end || range.end - range.start > RANGE {
        return Err("GET exceeds preview 64 KiB per-range limit".into());
    }
    let get = GetRequest::blob_ranges(hash, ChunkRanges::bytes(range));
    let frame =
        postcard::to_stdvec(&Request::Get(get)).map_err(|e| format!("GET serialization: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("QUIC stream: {e}"))?;
    send.write_all(&frame)
        .await
        .map_err(|e| format!("send GET: {e}"))?;
    send.finish().map_err(|e| format!("finish GET: {e}"))?;
    recv.read_to_end(MAX_BAO_PROOF_BYTES.min(4 * 1024 * 1024) + 8)
        .await
        .map_err(|e| format!("bounded Bao response: {e}"))
}

/// Retry exactly the same still-unverified range after a failed QUIC GET.
/// Reconnect uses the ORIGINAL pinned endpoint ticket and local ephemeral key.
/// A successful GET is not trusted until the caller independently verifies Bao.
async fn bounded_get_with_reconnect(
    endpoint: &Endpoint,
    address: &EndpointAddr,
    connection: &mut iroh::endpoint::Connection,
    hash: Hash,
    range: std::ops::Range<u64>,
    reconnects: &mut u8,
) -> Result<Vec<u8>, String> {
    loop {
        let failure =
            match tokio::time::timeout(STEP_TIMEOUT, bounded_get(connection, hash, range.clone()))
                .await
            {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(err)) => err,
                Err(_) => "bounded QUIC GET timed out".to_owned(),
            };
        if *reconnects >= MAX_SESSION_RECONNECTS {
            return Err(format!(
                "QUIC retry budget exhausted on unverified range: {failure}"
            ));
        }
        connection.close(0u8.into(), b"retry exact unverified range");
        // No fallback to relay, no replacement object/root/peer from the network.
        *connection = tokio::time::timeout(
            STEP_TIMEOUT,
            endpoint.connect(address.clone(), iroh_blobs::ALPN),
        )
        .await
        .map_err(|_| "bounded direct QUIC reconnect timed out")?
        .map_err(|err| format!("bounded direct QUIC reconnect rejected: {err}"))?;
        *reconnects += 1;
        eprintln!("STY_G1I_QUIC_RECONNECTED count={reconnects}");
    }
}

/// Bounded lab-only path selection, with all bytes read from ONE opened file
/// descriptor (not fs::read(path) after an unrelated metadata lookup).
/// Initial Windows path/reparse races are not solved by this helper.
fn read_explicit_synthetic_source(source: &Path) -> Result<Vec<u8>, String> {
    let prior =
        fs::symlink_metadata(source).map_err(|e| format!("inspect explicit source: {e}"))?;
    if !prior.is_file()
        || prior.file_type().is_symlink()
        || prior.len() == 0
        || prior.len() > MAX_OBJECT
    {
        return Err("selected source must be a nonempty regular non-symlink file <=8 MiB".into());
    }
    let mut opened = OpenOptions::new()
        .read(true)
        .open(source)
        .map_err(|e| format!("open selected file: {e}"))?;
    let pinned = opened
        .metadata()
        .map_err(|e| format!("inspect selected file handle: {e}"))?;
    if !pinned.is_file() || pinned.len() != prior.len() {
        return Err("selected file handle no longer matches approved size/type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pinned.dev() != prior.dev() || pinned.ino() != prior.ino() {
            return Err("selected source inode changed between inspection and open".into());
        }
    }
    let mut bytes = Vec::with_capacity(prior.len() as usize);
    {
        let mut bounded = Read::take(&mut opened, MAX_OBJECT + 1);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|e| format!("bounded read from selected handle: {e}"))?;
    }
    let after = opened
        .metadata()
        .map_err(|e| format!("reinspect selected file handle: {e}"))?;
    if !after.is_file() || after.len() != prior.len() || bytes.len() as u64 != prior.len() {
        return Err("selected source changed size or exceeded bounded read".into());
    }
    Ok(bytes)
}

async fn serve(source: &Path, allowed_text: &str) -> Result<(), String> {
    // A sender explicitly selects ONE local regular file and ONE allowed peer.
    // No directory enumeration, unsolicited PUSH, GET_MANY or Akula vault.
    let bytes = read_explicit_synthetic_source(source)?;
    let allowed = EndpointId::from_str(allowed_text)
        .map_err(|e| format!("invalid explicitly allowed receiver ID: {e}"))?;
    let wanted = Hash::new(&bytes);
    let root = private_root("sender")?;
    let store = FsStore::load(&root)
        .await
        .map_err(|e| format!("provider FsStore: {e}"))?;
    let tag = store
        .add_slice(&bytes)
        .await
        .map_err(|e| format!("seed one authorized object: {e}"))?;
    if tag.hash != wanted {
        return Err("provider hash does not equal selected file".into());
    }
    let (policy, worker) = deny_unlisted(allowed, vec![wanted]);
    let ep = endpoint(SecretKey::generate()).await?;
    let router = Router::builder(ep)
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, Some(policy)))
        .spawn();
    let ticket = postcard::to_stdvec(&router.endpoint().addr())
        .map_err(|e| format!("serialize direct endpoint: {e}"))?;
    println!(
        "CONNECT {} {} {}",
        hex(&ticket),
        wanted.to_hex(),
        bytes.len()
    );
    io::stdout()
        .flush()
        .map_err(|e| format!("announce connect: {e}"))?;

    // A blocking stdin reader is isolated from Tokio. The sender lives only
    // while its operator keeps the session open; entering any line closes it.
    tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().read_line(&mut input)
    })
    .await
    .map_err(|e| format!("operator session: {e}"))?
    .map_err(|e| format!("operator input: {e}"))?;
    router
        .shutdown()
        .await
        .map_err(|e| format!("provider shutdown: {e}"))?;
    worker.abort();
    drop(tag);
    drop(store);
    fs::remove_dir_all(root).map_err(|e| format!("clean private provider data: {e}"))?;
    Ok(())
}


/// G1m-b1: bounded >8 MiB real direct QUIC sender. A *single* locally
/// selected pre-opened regular source handle supplies all bytes; the bytes
/// are copied into a generated private spool using 64 KiB fixed buffering.
/// Only after full BLAKE3, on-disk spool re-read and protected FsStore
/// add_path(Copy) may the sender announce an object to ONE selected peer.
///
/// The original pathname open is NOT native reparse/symlink-race proof. This
/// is synthetic/manual lab only, with no Device/Vault grant or File Gate.
async fn serve_large(source: &Path, allowed_text: &str) -> Result<(), String> {
    let prior = fs::symlink_metadata(source)
        .map_err(|e| format!("inspect large selected source: {e}"))?;
    if !prior.is_file()
        || prior.file_type().is_symlink()
        || prior.len() <= MAX_OBJECT
        || prior.len() > MAX_LARGE_OBJECT
    {
        return Err("large preview requires regular non-symlink file >8 MiB and <=16 MiB".into());
    }
    let allowed = EndpointId::from_str(allowed_text)
        .map_err(|e| format!("invalid explicitly selected large-file receiver: {e}"))?;
    let mut opened = OpenOptions::new()
        .read(true)
        .open(source)
        .map_err(|e| format!("open selected large-file handle: {e}"))?;
    let pinned = opened.metadata()
        .map_err(|e| format!("stat selected large-file handle: {e}"))?;
    if !pinned.is_file() || pinned.len() != prior.len() {
        return Err("selected large-file handle changed type or length".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if prior.dev() != pinned.dev() || prior.ino() != pinned.ino() {
            return Err("selected large-file pathname replaced before opening".into());
        }
    }

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let count = match opened.read(&mut buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("hash selected handle: {e}")),
        };
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or("large source byte counter overflow")?;
        if total > MAX_LARGE_OBJECT {
            return Err("large selected source exceeded strict 16 MiB limit".into());
        }
        hasher.update(&buffer[..count]);
    }
    if total != prior.len() || opened.metadata().map_err(|e| e.to_string())?.len() != total {
        return Err("large selected source changed size during initial root binding".into());
    }
    let manifest = Manifest {
        id: ContentId(*hasher.finalize().as_bytes()),
        size: total,
    };
    opened.seek(SeekFrom::Start(0))
        .map_err(|e| format!("rewind selected descriptor: {e}"))?;

    let root = private_root("large-sender")?;
    let spool_path = root.join("pinned-source-spool.bin");
    let mut spool = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&spool_path)
        .map_err(|e| format!("create private uncommitted source spool: {e}"))?;
    let cancelled = AtomicBool::new(false);
    let copied = stream_to_uncommitted_quarantine(
        &mut opened, &mut spool, manifest, &cancelled,
    ).map_err(|e| format!("bounded selected source stream refused: {e:?}"))?;
    if copied.bytes != manifest.size || copied.max_requested_read_bytes > STREAM_BUFFER_BYTES {
        return Err("bounded input stream did not verify the selected object".into());
    }
    spool.sync_all().map_err(|e| format!("sync private source spool: {e}"))?;
    drop(spool);
    // An independent second File descriptor re-reads the physical spool.
    let mut spool_cold = fs::File::open(&spool_path)
        .map_err(|e| format!("cold source spool open: {e}"))?;
    stream_to_uncommitted_quarantine(
        &mut spool_cold, &mut io::sink(), manifest, &cancelled,
    ).map_err(|e| format!("cold source spool BLAKE3 mismatch: {e:?}"))?;
    drop(spool_cold);

    let store = FsStore::load(&root)
        .await
        .map_err(|e| format!("large sender protected FsStore: {e}"))?;
    // The pinned 0.103.1 release and pinned fork support add_path in Copy
    // mode: unlike add_slice, it does not allocate an entire >8MiB Bytes blob.
    let stored = store.add_path(&spool_path).await
        .map_err(|e| format!("streamed large source FsStore import: {e}"))?;
    let wanted = Hash::from_bytes(manifest.id.0);
    if stored.hash != wanted {
        return Err("FsStore add_path returned a different large-object BLAKE3 root".into());
    }
    let (policy, worker) = deny_unlisted(allowed, vec![wanted]);
    let ep = endpoint(SecretKey::generate()).await?;
    let router = Router::builder(ep)
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, Some(policy)))
        .spawn();
    let ticket = postcard::to_stdvec(&router.endpoint().addr())
        .map_err(|e| format!("serialize large-file direct endpoint: {e}"))?;
    println!("CONNECT {} {} {}", hex(&ticket), wanted.to_hex(), manifest.size);
    io::stdout().flush().map_err(|e| format!("announce manually approved large file: {e}"))?;
    tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().read_line(&mut input)
    })
    .await
    .map_err(|e| format!("large sender operator session: {e}"))?
    .map_err(|e| format!("large sender operator input: {e}"))?;
    router.shutdown().await.map_err(|e| format!("large sender shutdown: {e}"))?;
    worker.abort();
    drop(stored);
    drop(store);
    fs::remove_dir_all(root).map_err(|e| format!("clean large sender private data: {e}"))?;
    Ok(())
}

/// G1k-c: one explicitly approved receiver, one provider, one endpoint ticket,
/// a strictly bounded set of local regular-file contents. No folder scan,
/// peer-provided source paths, or implicit permission for an unlisted root.
async fn serve_batch(allowed_text: &str, sources: &[PathBuf]) -> Result<(), String> {
    if sources.is_empty() || sources.len() > staya_transfer::queue::MAX_QUEUE_FILES {
        return Err("batch requires 1..=8 explicitly selected files".into());
    }
    let allowed = EndpointId::from_str(allowed_text)
        .map_err(|e| format!("invalid explicitly selected receiver ID: {e}"))?;
    let mut chosen = Vec::with_capacity(sources.len());
    let mut payloads = Vec::with_capacity(sources.len());
    for source in sources {
        let label = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("selected file has no safe UTF-8 local basename")?
            .to_owned();
        let bytes = read_explicit_synthetic_source(source)?;
        chosen.push(SelectedFile {
            label,
            manifest: Manifest {
                id: ContentId(*blake3::hash(&bytes).as_bytes()),
                size: bytes.len() as u64,
            },
        });
        payloads.push(bytes);
    }
    let selection =
        QueueSelection::new(chosen).map_err(|e| format!("selected queue refused: {e:?}"))?;
    let root = private_root("batch-sender")?;
    let store = FsStore::load(&root)
        .await
        .map_err(|e| format!("batch provider FsStore: {e}"))?;
    let mut tags = Vec::with_capacity(payloads.len());
    let mut permitted_hashes = Vec::with_capacity(payloads.len());
    for (i, bytes) in payloads.iter().enumerate() {
        let expected = Hash::from_bytes(selection.entries()[i].manifest.id.0);
        let tag = store
            .add_slice(bytes)
            .await
            .map_err(|e| format!("seed selected object {i}: {e}"))?;
        if tag.hash != expected {
            return Err("provider stored root differs from pinned selected hash".into());
        }
        permitted_hashes.push(expected);
        tags.push(tag);
    }
    let (policy, worker) = deny_unlisted(allowed, permitted_hashes);
    let ep = endpoint(SecretKey::generate()).await?;
    let router = Router::builder(ep)
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, Some(policy)))
        .spawn();
    let ticket = postcard::to_stdvec(&router.endpoint().addr())
        .map_err(|e| format!("serialize batch direct-only endpoint: {e}"))?;
    let mut invitation = format!(
        "CONNECT_BATCH {} {} {}",
        hex(&ticket),
        hex(&selection.commitment()),
        selection.entries().len()
    );
    for entry in selection.entries() {
        let root = Hash::from_bytes(entry.manifest.id.0);
        invitation.push_str(&format!(
            " {} {} {}",
            entry.label,
            root.to_hex(),
            entry.manifest.size
        ));
    }
    if invitation.len() > 8192 {
        return Err("batch invitation exceeded protocol limit".into());
    }
    println!("{invitation}");
    io::stdout()
        .flush()
        .map_err(|e| format!("announce manually trusted batch: {e}"))?;

    // The provider remains live only for this one operator-approved session.
    tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().read_line(&mut input)
    })
    .await
    .map_err(|e| format!("batch operator session: {e}"))?
    .map_err(|e| format!("batch operator input: {e}"))?;
    router
        .shutdown()
        .await
        .map_err(|e| format!("batch provider shutdown: {e}"))?;
    worker.abort();
    drop(tags);
    drop(store);
    fs::remove_dir_all(root).map_err(|e| format!("clean batch provider private data: {e}"))?;
    Ok(())
}

async fn receive(lab_drop_after_first_range: bool, large: bool) -> Result<(), String> {
    // The receiver key never leaves this process and is never persisted.
    let private_key = SecretKey::generate();
    println!("PEER_ID {}", private_key.public());
    io::stdout()
        .flush()
        .map_err(|e| format!("announce receiver identity: {e}"))?;
    // Manually transfer the sender's CONNECT line over a trusted out-of-band
    // channel. The sender and root are NOT granted by a network peer inventory.
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("read manual CONNECT: {e}"))?;
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
    let size = fields[3]
        .parse::<u64>()
        .map_err(|e| format!("object size: {e}"))?;
    if large {
        if size <= MAX_OBJECT || size > MAX_LARGE_OBJECT {
            return Err("large preview requires object >8 MiB and <=16 MiB".into());
        }
    } else if size == 0 || size > MAX_OBJECT {
        return Err("object must be nonempty and at most 8 MiB".into());
    }
    if lab_drop_after_first_range && size <= RANGE {
        return Err("lab reconnect requires at least two Bao ranges".into());
    }
    let manifest = Manifest {
        id: ContentId(*trusted_hash.as_bytes()),
        size,
    };
    let identity = StoreIdentity {
        manifest,
        profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
    };
    let ep = endpoint(private_key).await?;
    let mut conn =
        tokio::time::timeout(STEP_TIMEOUT, ep.connect(address.clone(), iroh_blobs::ALPN))
            .await
            .map_err(|_| "direct QUIC connection timed out")?
            .map_err(|e| format!("direct QUIC connection: {e}"))?;

    let root = private_root("receiver")?;
    let owner = StoreLease::acquire(&root).map_err(|e| format!("receiver OS custody: {e}"))?;
    let actor = FsStore::load(&root)
        .await
        .map_err(|e| format!("receiver FsStore: {e}"))?;
    let ledger = SharedAdmission::new(Limits {
        max_partial_objects: 1,
        max_reserved_bytes: 4 * 1024 * 1024,
        max_open_handles: 4,
        max_retries_per_object: 0,
    })
    .map_err(|e| format!("bounded admission: {e}"))?;
    let cancelled = AtomicBool::new(false);

    let mut start = 0u64;
    let mut reconnects = 0u8;
    while start < size {
        let end = start.saturating_add(RANGE).min(size);
        let range = ByteRange::new(start, end, size).map_err(|e| format!("{e:?}"))?;
        let response = bounded_get_with_reconnect(
            &ep,
            &address,
            &mut conn,
            trusted_hash,
            start..end,
            &mut reconnects,
        )
        .await?;
        if response.len() < 8
            || u64::from_le_bytes(response[..8].try_into().map_err(|_| "bad prefix")?) != size
        {
            return Err("untrusted response size mismatch".into());
        }
        let request =
            TransferRequest::new(manifest, range.clone()).map_err(|e| format!("{e:?}"))?;
        verify_bao_range(&request, &response[8..])
            .map_err(|e| format!("independent Bao root verification: {e:?}"))?;
        let (_, permit) = partial_adapter::stage_with_inflight_budget(
            &owner, &ledger, &actor, identity, range, &response, &cancelled,
        )
        .await?;
        drop(permit);
        if lab_drop_after_first_range && start == 0 {
            // Real QUIC close, not a mocked transport failure. The next GET
            // must reconnect with the same authenticated ephemeral identity.
            conn.close(0u8.into(), b"lab abrupt QUIC interruption");
        }
        start = end;
    }
    ledger
        .stop_admissions()
        .map_err(|e| format!("stop admissions: {e}"))?;
    if !ledger
        .admissions_drained()
        .map_err(|e| format!("drain permits: {e}"))?
    {
        return Err("inflight permit remains after full transfer".into());
    }
    actor
        .shutdown()
        .await
        .map_err(|e| format!("quiesce real FsStore: {e}"))?;
    drop(actor);
    // Cold physical source readback: every output range is first independently
    // Bao-audited from the cleanly closed FsStore, never trusted from its bitfield.
    // Large objects are written in 64KiB chunks, never one entire-size Vec.
    let staged = root.join(if large {
        "large-verified-staged.bin"
    } else {
        "verified-staged.bin"
    });
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|e| format!("new private stage: {e}"))?;
    if large {
        owner.validate_fence()
            .map_err(|e| format!("large stage OS custody: {e}"))?;
        let mut offset = 0u64;
        let mut hasher = blake3::Hasher::new();
        while offset < size {
            let end = offset.saturating_add(RANGE).min(size);
            let range = ByteRange::new(offset, end, size)
                .map_err(|e| format!("large physical audit range: {e:?}"))?;
            let authenticated = partial_adapter::audit_clean_closed_fixture(
                &root, identity, range,
            )?;
            if authenticated.len() as u64 != end - offset || authenticated.len() > RANGE as usize {
                return Err("large Bao cold audit returned incorrect bounded span".into());
            }
            output.write_all(&authenticated)
                .map_err(|e| format!("write Bao-audited large private stage: {e}"))?;
            hasher.update(&authenticated);
            offset = end;
        }
        if offset != size || hasher.finalize().as_bytes() != &manifest.id.0 {
            return Err("large physical Bao audit failed complete pinned BLAKE3 root".into());
        }
    } else {
        let audited = if size < 16 * 1024 {
            partial_adapter::audit_cold_small_complete_object(&root, identity).await?
        } else {
            let mut audited = Vec::with_capacity(size as usize);
            let mut offset = 0u64;
            while offset < size {
                let end = offset.saturating_add(RANGE).min(size);
                let range = ByteRange::new(offset, end, size).map_err(|e| format!("{e:?}"))?;
                audited.extend(partial_adapter::audit_clean_closed_fixture(
                    &root, identity, range,
                )?);
                offset = end;
            }
            audited
        };
        if audited.len() as u64 != size || *blake3::hash(&audited).as_bytes() != manifest.id.0 {
            return Err("cold physical readback did not match the trusted root".into());
        }
        owner.validate_fence()
            .map_err(|e| format!("final local custody: {e}"))?;
        output.write_all(&audited)
            .map_err(|e| format!("write private stage: {e}"))?;
    }
    output.sync_all()
        .map_err(|e| format!("sync private stage: {e}"))?;
    drop(output);

    if large {
        // Fresh descriptor after the actual staged write: this checks the
        // physical staged bytes, not the in-memory range reconstruction.
        let mut readback = fs::File::open(&staged)
            .map_err(|e| format!("cold final large stage open: {e}"))?;
        stream_to_uncommitted_quarantine(
            &mut readback, &mut io::sink(), manifest, &cancelled,
        )
        .map_err(|e| format!("post-write cold stage BLAKE3/size audit: {e:?}"))?;
        owner.validate_fence()
            .map_err(|e| format!("large final staging OS custody: {e}"))?;
    }
    #[cfg(windows)]
    {
        windows_private_stage::verify_owner_only_staging_root(&root)
            .map_err(|e| format!("receiver protected Windows staging root: {e}"))?;
        windows_private_stage::verify_owner_only_staged_file(&staged)
            .map_err(|e| format!("receiver inherited private file ACL: {e}"))?;
    }
    conn.close(0u8.into(), b"direct preview complete");
    ep.close().await;
    drop(owner);
    println!(
        "STAGED {} ROOT={} SIZE={} RECONNECTS={} NOT_APPLIED=true",
        staged.display(),
        trusted_hash.to_hex(),
        size,
        reconnects
    );
    io::stdout()
        .flush()
        .map_err(|e| format!("report verified private staging: {e}"))?;
    Ok(())
}

/// One physical receiver OS process and one QUIC endpoint for all selected
/// objects. CONNECT_BATCH is manually accepted over an authenticated offline
/// operator channel; it MUST NOT be treated as an unsolicited network grant.
async fn receive_batch(lab_probe_unlisted: bool) -> Result<(), String> {
    let key = SecretKey::generate();
    println!("PEER_ID {}", key.public());
    io::stdout()
        .flush()
        .map_err(|e| format!("receiver identity: {e}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("read manually approved batch invitation: {e}"))?;
    if input.len() > 8192 {
        return Err("batch invitation exceeds input budget".into());
    }
    let fields: Vec<_> = input.split_whitespace().collect();
    if fields.len() < 7 || fields[0] != "CONNECT_BATCH" {
        return Err("expected CONNECT_BATCH ticket commitment count triples".into());
    }
    let count = fields[3]
        .parse::<usize>()
        .map_err(|e| format!("batch item count: {e}"))?;
    if count == 0 || count > staya_transfer::queue::MAX_QUEUE_FILES || fields.len() != 4 + 3 * count
    {
        return Err("batch list length/count is invalid".into());
    }
    let address: EndpointAddr = postcard::from_bytes(&from_hex(fields[1])?)
        .map_err(|e| format!("invalid batch endpoint ticket: {e}"))?;
    if address.is_empty() {
        return Err("direct sender address is missing; relay disabled".into());
    }
    let mut declared = Vec::with_capacity(count);
    for i in 0..count {
        let base = 4 + 3 * i;
        let trusted_hash =
            Hash::from_str(fields[base + 1]).map_err(|e| format!("trusted batch root {i}: {e}"))?;
        let size = fields[base + 2]
            .parse::<u64>()
            .map_err(|e| format!("trusted batch size {i}: {e}"))?;
        declared.push(SelectedFile {
            label: fields[base].to_owned(),
            manifest: Manifest {
                id: ContentId(*trusted_hash.as_bytes()),
                size,
            },
        });
    }
    let selection = QueueSelection::new(declared)
        .map_err(|e| format!("unsafe or over-budget batch invitation: {e:?}"))?;
    let commitment = selection.commitment();
    if !hex(&commitment).eq_ignore_ascii_case(fields[2]) {
        return Err("operator trusted ordered batch commitment does not match the manifest".into());
    }
    let mut queue = selection.into_cursor();
    let ep = endpoint(key).await?;
    let mut conn =
        tokio::time::timeout(STEP_TIMEOUT, ep.connect(address.clone(), iroh_blobs::ALPN))
            .await
            .map_err(|_| "batch direct QUIC timed out")?
            .map_err(|e| format!("batch direct QUIC connection rejected: {e}"))?;
    let mut reconnects = 0u8;

    for i in 0..count {
        let manifest = queue
            .current()
            .ok_or("no selected batch item available")?
            .manifest;
        let trusted_hash = Hash::from_bytes(manifest.id.0);
        let size = manifest.size;
        let identity = StoreIdentity {
            manifest,
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        // Each object receives its own process-generated private storage root.
        // No peer label is ever a filesystem path component.
        let root = private_root("batch-receiver")?;
        let owner =
            StoreLease::acquire(&root).map_err(|e| format!("batch item {i} OS custody: {e}"))?;
        let actor = FsStore::load(&root)
            .await
            .map_err(|e| format!("batch item {i} FsStore: {e}"))?;
        let ledger = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: 4 * 1024 * 1024,
            max_open_handles: 4,
            max_retries_per_object: 0,
        })
        .map_err(|e| format!("batch item {i} bounded admission: {e}"))?;
        let cancelled = AtomicBool::new(false);
        let mut start = 0u64;
        while start < size {
            let end = start.saturating_add(RANGE).min(size);
            let range = ByteRange::new(start, end, size)
                .map_err(|e| format!("batch item {i} invalid range: {e:?}"))?;
            let response = bounded_get_with_reconnect(
                &ep,
                &address,
                &mut conn,
                trusted_hash,
                start..end,
                &mut reconnects,
            )
            .await?;
            if response.len() < 8
                || u64::from_le_bytes(response[..8].try_into().map_err(|_| "bad Bao length")?)
                    != size
            {
                return Err("batch GET returned a mismatched object size".into());
            }
            let request = TransferRequest::new(manifest, range.clone())
                .map_err(|e| format!("batch item {i} request: {e:?}"))?;
            verify_bao_range(&request, &response[8..])
                .map_err(|e| format!("batch item {i} independent Bao: {e:?}"))?;
            let (_, permit) = partial_adapter::stage_with_inflight_budget(
                &owner, &ledger, &actor, identity, range, &response, &cancelled,
            )
            .await?;
            drop(permit);
            start = end;
        }
        ledger
            .stop_admissions()
            .map_err(|e| format!("batch stop admission: {e}"))?;
        if !ledger
            .admissions_drained()
            .map_err(|e| format!("batch drain: {e}"))?
        {
            return Err("batch item still has an inflight write".into());
        }
        actor
            .shutdown()
            .await
            .map_err(|e| format!("batch quiesce: {e}"))?;
        drop(actor);
        let audited = if size < 16 * 1024 {
            partial_adapter::audit_cold_small_complete_object(&root, identity).await?
        } else {
            let mut audited = Vec::with_capacity(size as usize);
            let mut offset = 0u64;
            while offset < size {
                let end = offset.saturating_add(RANGE).min(size);
                let range = ByteRange::new(offset, end, size)
                    .map_err(|e| format!("batch audit range: {e:?}"))?;
                audited.extend(partial_adapter::audit_clean_closed_fixture(
                    &root, identity, range,
                )?);
                offset = end;
            }
            audited
        };
        if audited.len() as u64 != size || *blake3::hash(&audited).as_bytes() != manifest.id.0 {
            return Err("cold batch physical Bao audit did not match local selection".into());
        }
        owner
            .validate_fence()
            .map_err(|e| format!("batch custody: {e}"))?;
        let staged = root.join(format!("staged-{i:03}.bin"));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .map_err(|e| format!("create private staged batch item: {e}"))?;
        output
            .write_all(&audited)
            .map_err(|e| format!("write batch item: {e}"))?;
        output
            .sync_all()
            .map_err(|e| format!("sync batch item: {e}"))?;
        drop(output);
        #[cfg(windows)]
        {
            windows_private_stage::verify_owner_only_staging_root(&root)
                .map_err(|e| format!("Windows protected batch directory: {e}"))?;
            windows_private_stage::verify_owner_only_staged_file(&staged)
                .map_err(|e| format!("Windows protected batch file: {e}"))?;
        }
        // The queue receipt is based on the *written staging file*,
        // not a byte slice that was authenticated before the output write.
        let staged_bytes = fs::read(&staged)
            .map_err(|e| format!("physical readback of written batch stage: {e}"))?;
        queue
            .record_verified_staging(manifest, &staged_bytes)
            .map_err(|e| format!("batch staged-file root/size verification: {e:?}"))?;
        if queue.outcomes()[i] != ItemOutcome::VerifiedStaged {
            return Err("batch cursor did not record a verified stage".into());
        }
        drop(owner);
        let progress = queue.verified_staging_progress();
        println!(
            "STAGED_QUEUE {i} {} ROOT={} SIZE={} RECONNECTS={} VERIFIED_ITEMS={}/{} VERIFIED_BYTES={}/{} PHASE={:?} NOT_APPLIED=true",
            staged.display(),
            trusted_hash.to_hex(),
            size,
            reconnects,
            progress.verified_staged_items,
            progress.selected_items,
            progress.verified_staged_bytes,
            progress.selected_bytes,
            progress.phase
        );
        io::stdout()
            .flush()
            .map_err(|e| format!("batch report stage: {e}"))?;
    }

    if lab_probe_unlisted {
        // Positive authorized requests were already proven on this same
        // connection; a hash never selected by the sender must be rejected.
        let absent = Hash::new(b"staya-g1k-lab-unlisted-object-not-in-selected-set");
        match tokio::time::timeout(STEP_TIMEOUT, bounded_get(&conn, absent, 0..1)).await {
            Ok(Err(_)) => println!("STY_G1K_UNLISTED_GET_DENIED=true"),
            Ok(Ok(_)) => return Err("unlisted object GET was not refused".into()),
            Err(_) => return Err("unlisted object denial timed out (not proof)".into()),
        }
    }
    if queue.phase() != QueuePhase::Complete {
        return Err("batch cursor did not finish after verified objects".into());
    }
    conn.close(0u8.into(), b"selected batch complete");
    ep.close().await;
    let progress = queue.verified_staging_progress();
    if progress.verified_staged_items != progress.selected_items
        || progress.verified_staged_bytes != progress.selected_bytes
    {
        return Err("complete batch has unverified staged bytes".into());
    }
    println!(
        "QUEUE_COMPLETE COUNT={count} COMMITMENT={} RECONNECTS={} VERIFIED_ITEMS={}/{} VERIFIED_BYTES={}/{} PHASE={:?} NOT_APPLIED=true",
        hex(&commitment),
        reconnects,
        progress.verified_staged_items,
        progress.selected_items,
        progress.verified_staged_bytes,
        progress.selected_bytes,
        progress.phase
    );
    io::stdout()
        .flush()
        .map_err(|e| format!("batch completion report: {e}"))?;
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
        "serve-large" => {
            let path = args.next().ok_or("serve-large requires synthetic source path")?;
            let peer = args.next().ok_or("serve-large requires receiver EndpointId")?;
            if args.next().is_some() {
                return Err("unexpected serve-large argument".into());
            }
            serve_large(Path::new(&path), &peer).await
        }
        "receive-large" => {
            if args.next().is_some() {
                return Err("receive-large takes no arguments".into());
            }
            receive(false, true).await
        }
        "serve-batch" => {
            let allowed = args.next().ok_or("serve-batch requires receiver EndpointId")?;
            let sources = args.map(PathBuf::from).collect::<Vec<_>>();
            serve_batch(&allowed, &sources).await
        }
        "receive-batch" => {
            let lab_probe = match args.next().as_deref() {
                None => false,
                Some("--lab-request-unlisted") => true,
                Some(_) => return Err("unknown receive-batch option".into()),
            };
            if args.next().is_some() {
                return Err("unexpected receive-batch argument".into());
            }
            receive_batch(lab_probe).await
        }
        "receive" => {
            // Explicit non-production fault injection; normal use needs no flag.
            let lab_drop = match args.next().as_deref() {
                None => false,
                Some("--lab-drop-after-first-range") => true,
                Some(_) => return Err("unknown receive option".into()),
            };
            if args.next().is_some() {
                return Err("unexpected receive argument".into());
            }
            receive(lab_drop, false).await
        }
        _ => Err("usage: staya-direct-preview receive | serve <file> <receiver-id>; manual direct-only private staging".into())
    }
}
