//! G2-05h3g6: cancel a *real polled* pinned FsStore load/shutdown future.
//! A fake OpeningFsStore drop is not evidence of upstream actor cancellation.
//! The child proves Poll::Pending on the real future before dropping it;
//! the parent requires kernel custody to survive until the process is killed.
//! There is no durable receipt, verified resume, or Akula File Gate.

// Reuse the real production-shaped fixture modules, while this focused
// cancellation executable intentionally exercises only their lifecycle path.
#[allow(dead_code)]
#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;
#[allow(dead_code)]
#[path = "fsstore_shutdown_supervisor.rs"]
mod shutdown_supervisor;

use bao_tree::{
    BaoTree, BlockSize, ByteRanges,
    io::{outboard::PreOrderOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::store::fs::FsStore;
use shutdown_supervisor::ActiveFsStore;
use staya_custody_lab::{
    StoreLease,
    admission::Limits,
    checkpoint::{IROH_PREORDER_16K, read_candidates},
};
use staya_transfer::{ByteRange, ContentId, Manifest, TransferRequest, bao::verify_bao_range};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    task::Poll,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STAGE_ENV: &str = "STY_G2_05H3G6_REAL_STAGE";
const ROOT_ENV: &str = "STY_G2_05H3G6_REAL_ROOT";
const MARKER_ENV: &str = "STY_G2_05H3G6_REAL_MARKER";
const TEST: &str = "real_polled_fsstore_load_and_shutdown_cancellation_retains_os_custody";
const LEN: usize = 16 * 1024 * 1024 + 17;
const START: u64 = 32_768;
const END: u64 = 196_608;
const DEADLINE: Duration = Duration::from_secs(40);

fn limits() -> Limits {
    Limits {
        max_partial_objects: 1,
        max_reserved_bytes: LEN as u64 + 100_000,
        max_open_handles: 4,
        max_retries_per_object: 1,
    }
}

fn payload() -> Vec<u8> {
    (0..LEN).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

fn digest() -> blake3::Hash {
    blake3::hash(&payload())
}

fn publish_marker(marker: &Path, stage: &str) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)?;
    f.write_all(stage.as_bytes())?;
    f.sync_all()
}

fn assert_not_exited(child: &mut Child, stage: &str) {
    if let Some(status) = child.try_wait().expect("native subprocess poll") {
        panic!("real {stage} child exited before proving a pending future: {status}");
    }
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

/// Seed a full, clean pinned FsStore blob with disk-backed .data/.obao4.
/// It is explicitly complete BEFORE entering the cancellation shutdown test.
async fn seed(root: &Path) {
    let owner = StoreLease::acquire(root).expect("seed owns exclusive physical store");
    let store = FsStore::load(root)
        .await
        .expect("pinned real actor for seed");
    let bytes = payload();
    let tag = store
        .add_slice(&bytes)
        .await
        .expect("seed real FsStore bytes");
    assert_eq!(tag.hash.as_bytes(), digest().as_bytes());
    store
        .shutdown()
        .await
        .expect("complete physical baseline shutdown");
    drop(tag);
    drop(store);
    drop(owner);
    let hex = digest().to_hex().to_string();
    assert!(root.join("data").join(format!("{hex}.data")).is_file());
    assert!(root.join("data").join(format!("{hex}.obao4")).is_file());
}

/// Trust only immutable test fixture root and a freshly opened disk-backed
/// Bao outboard after the killed OS process is independently reaped.
fn audit_physical_bao(root: &Path) {
    let expected = digest();
    let hex = expected.to_hex().to_string();
    let data_path = root.join("data").join(format!("{hex}.data"));
    let bao_path = root.join("data").join(format!("{hex}.obao4"));
    let bytes = payload();
    assert_eq!(
        fs::read(&data_path).expect("post-crash physical data"),
        bytes
    );
    let tree = BaoTree::new(LEN as u64, BlockSize::from_chunk_log(4));
    assert_eq!(
        fs::metadata(&bao_path)
            .expect("physical disk outboard")
            .len(),
        tree.outboard_size()
    );
    let data = File::open(data_path).expect("cold disk data");
    let proof = File::open(bao_path).expect("cold disk outboard");
    let outboard = PreOrderOutboard {
        root: expected,
        tree,
        data: &proof,
    };
    let chunks = round_up_to_chunks(&ByteRanges::from(START..END));
    let mut wire = Vec::new();
    encode_ranges_validated(&data, outboard, &chunks, &mut wire)
        .expect("independent disk-backed Bao encoding");
    let request = TransferRequest::new(
        Manifest {
            id: ContentId(*expected.as_bytes()),
            size: LEN as u64,
        },
        ByteRange::new(START, END, LEN as u64).expect("valid tested range"),
    )
    .expect("transfer request for immutable root");
    let verified = verify_bao_range(&request, &wire).expect("root-authenticated Bao from disk");
    assert_eq!(verified.bytes(), &bytes[START as usize..END as usize]);
}

async fn child(stage: &str, root: &Path, marker: &Path) {
    match stage {
        "load" => {
            // The future actually enters FsStore::load: not a simulated
            // OpeningFsStore guard. A Ready result is NOT evidence and fails.
            let mut load = Box::pin(ActiveFsStore::open(root, limits()));
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(load.as_mut().poll(cx).is_pending())).await;
            assert!(
                pending,
                "actual pinned FsStore::load returned Ready on first poll; cannot claim in-flight cancellation"
            );
            drop(load); // OpeningFsStore::Drop deliberately leaks OS custody
        }
        "shutdown" => {
            let active = ActiveFsStore::open(root, limits())
                .await
                .expect("real pinned store opens under custody");
            let closing = active
                .begin_closing()
                .unwrap_or_else(|(_, err)| panic!("cannot enter real Closing state: {err}"));
            assert!(
                closing.admissions().admissions_drained().unwrap(),
                "no outstanding test permits may exist"
            );
            let mut shutdown = Box::pin(closing.finish());
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx).is_pending()))
                    .await;
            assert!(
                pending,
                "real FsStore::shutdown returned Ready on first poll; cannot claim in-flight cancellation"
            );
            drop(shutdown); // ActiveFsStore::Drop holds lock until process exit
        }
        _ => panic!("unknown real cancellation stage"),
    }
    assert!(
        matches!(
            StoreLease::acquire(root),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
        ),
        "cancelled polled actor future must not allow second writer in same process"
    );
    publish_marker(marker, stage).expect("publish pending-future cancellation marker");
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn real_polled_fsstore_load_and_shutdown_cancellation_retains_os_custody() {
    if let Ok(stage) = std::env::var(STAGE_ENV) {
        let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("child root env"));
        let marker = PathBuf::from(std::env::var_os(MARKER_ENV).expect("child marker env"));
        child(&stage, &root, &marker).await;
        return;
    }

    for stage in ["load", "shutdown"] {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("valid test clock")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("staya-g2-05h3g6-{}-{stage}-{stamp}", process::id()));
        assert!(
            !base.exists(),
            "only use disposable private test directories"
        );
        let root = base.join("store");
        let marker = base.join("future-cancelled");
        fs::create_dir_all(&root).expect("prepare new root");
        if stage == "shutdown" {
            seed(&root).await;
        }
        let process = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg(TEST)
            .arg("--nocapture")
            .env(STAGE_ENV, stage)
            .env(ROOT_ENV, &root)
            .env(MARKER_ENV, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn independent actor cancellation process");
        let mut child = ChildGuard(Some(process));
        let started = Instant::now();
        while !marker.is_file() {
            assert_not_exited(child.0.as_mut().unwrap(), stage);
            assert!(
                started.elapsed() < DEADLINE,
                "no proof that real {stage} future was pending and cancelled"
            );
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(fs::read(&marker).expect("read witness"), stage.as_bytes());
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "post-cancellation child holds OS custody until real process death"
        );
        child
            .0
            .as_mut()
            .unwrap()
            .kill()
            .expect("real OS hard termination");
        let status = child
            .0
            .take()
            .unwrap()
            .wait()
            .expect("reap actual OS child");
        assert!(!status.success(), "child must not issue clean actor ACK");
        let new_owner = StoreLease::acquire(&root)
            .expect("independent OS custody reacquired only after killed child");
        assert!(
            read_candidates(
                &new_owner,
                *digest().as_bytes(),
                LEN as u64,
                IROH_PREORDER_16K
            )
            .expect("read post-crash candidates")
            .is_empty(),
            "cancelled actor futures can never create verified checkpoint claims"
        );
        if stage == "shutdown" {
            audit_physical_bao(&root);
        }
        drop(new_owner);
        drop(child);
        fs::remove_dir_all(base).expect("only delete this private fixture");
    }
    println!(
        "STY_G2_05H3G6 real_polled_load=true real_polled_shutdown=true \
         os_lock_retained_until_death=true cold_bao=true checkpoint=false file_gate=false"
    );
}
