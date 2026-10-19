//! STY-G2-05a: kill a real pinned FsStore worker, then independently reopen.
//!
//! This is a process-crash observation, not a power-loss test. A candidate
//! checkpoint is never itself a verified range, and an interrupted import
//! has no committed checkpoint even when some physical bytes survive.
//! Run for both pinned upstream release and fork in the interop CI matrix.

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::{Hash, store::fs::FsStore};
use partial_adapter::{audit_clean_closed_fixture, stage_verified_fixture};
use staya_custody_lab::{
    StoreLease,
    checkpoint::{CheckpointClaim, IROH_PREORDER_16K, read_candidates},
    partial_barrier::publish_after_quiescent_audit,
};
use staya_transfer::{
    ByteRange, ContentId, Manifest,
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LEN: usize = 8 * 1024 * 1024 + 17;
const START: u64 = 32_768;
const END: u64 = 196_608;
const BLOCK: BlockSize = BlockSize::from_chunk_log(4);
const TEST_LIMIT: Duration = Duration::from_secs(180);
const READY_LIMIT: Duration = Duration::from_secs(90);
const READY_FILE: &str = ".staya-g2-05a-ready";
const ENV_MODE: &str = "STY_G2_05A_CHILD_MODE";
const ENV_ROOT: &str = "STY_G2_05A_ROOT";

fn make_data() -> Vec<u8> {
    (0..LEN).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

fn identity(data: &[u8]) -> StoreIdentity {
    StoreIdentity {
        manifest: Manifest {
            id: ContentId(*blake3::hash(data).as_bytes()),
            size: data.len() as u64,
        },
        profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
    }
}

fn range() -> ByteRange {
    ByteRange::new(START, END, LEN as u64).expect("bounded test interval")
}

fn proof_wire(data: &[u8]) -> Vec<u8> {
    let outboard = PreOrderMemOutboard::create(data, BLOCK);
    assert_eq!(outboard.root.as_bytes(), blake3::hash(data).as_bytes());
    let mut bao = Vec::new();
    let requested = round_up_to_chunks(&ByteRanges::from(START..END));
    encode_ranges_validated(data, &outboard, &requested, &mut bao)
        .expect("deterministic pinned Bao fixture");
    let mut wire = (data.len() as u64).to_le_bytes().to_vec();
    wire.extend_from_slice(&bao);
    wire
}

fn claim(expected: StoreIdentity) -> CheckpointClaim {
    CheckpointClaim {
        sequence: 1,
        content_root: expected.manifest.id.0,
        object_len: expected.manifest.size,
        bao_profile: IROH_PREORDER_16K,
        start: START,
        end: END,
    }
}

async fn child_writer(root: &Path, mode: &str) {
    let owner = StoreLease::acquire(root).expect("child is the sole OS writer");
    let data = make_data();
    let expected = identity(&data);
    let store = FsStore::load(root)
        .await
        .expect("real pinned FsStore in child");
    let wire = proof_wire(&data);
    stage_verified_fixture(&store, expected, range(), &wire)
        .await
        .expect("real partial Bao import before crash");

    if mode == "checkpointed" {
        // The separate checkpoint is only permitted after closing the actor,
        // syncing the physical backings and auditing real stored Bao.
        store.shutdown().await.expect("quiescent FsStore shutdown");
        drop(store);
        let result = publish_after_quiescent_audit(&owner, claim(expected), |_| {
            let verified =
                audit_clean_closed_fixture(root, expected, range()).map_err(io::Error::other)?;
            if verified != data[START as usize..END as usize] {
                return Err(io::Error::other("quiescent Bao physical readback mismatch"));
            }
            Ok(())
        });
        #[cfg(unix)]
        assert!(
            result.is_ok(),
            "Unix sync and Bao audit must pass: {result:?}"
        );
        #[cfg(windows)]
        assert_eq!(
            result
                .expect_err("Windows must not publish a durable claim")
                .kind(),
            io::ErrorKind::Unsupported
        );
    } else {
        assert_eq!(mode, "uncommitted");
        // Keep the live actor and its buffers alive until the parent issues
        // SIGKILL / TerminateProcess. In particular, DO NOT call shutdown().
        let _ = &store;
    }

    // Only a test-control signal: writing this marker is NOT an FsStore
    // durability barrier. Parent kills this process after seeing it.
    let mut ready = fs::File::create(root.join(READY_FILE)).expect("create ready marker");
    ready
        .write_all(mode.as_bytes())
        .expect("write ready marker");
    ready.sync_all().expect("publish ready marker to parent");
    println!("STY_G2_05A_CHILD_READY={mode}");
    tokio::time::sleep(Duration::from_secs(120)).await;
    panic!("worker was not forcibly terminated by parent");
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_root(mode: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "staya-g2-05a-{}-{mode}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("new private store root");
    root
}

async fn run_and_reopen(mode: &str) {
    let root = private_root(mode);
    let mut child = KillOnDrop(
        Command::new(env::current_exe().expect("current test binary"))
            .arg("--exact")
            .arg("real_fsstore_kill_reopen_candidate_gate")
            .arg("--nocapture")
            .env(ENV_MODE, mode)
            .env(ENV_ROOT, &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("independent real FsStore child process"),
    );
    let ready_path = root.join(READY_FILE);
    let started = Instant::now();
    while !ready_path.is_file() {
        let status = child.0.try_wait().expect("child status");
        assert!(status.is_none(), "worker exited before ready: {status:?}");
        assert!(
            started.elapsed() < READY_LIMIT,
            "real FsStore child did not reach kill point within {READY_LIMIT:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(fs::read_to_string(&ready_path).unwrap(), mode);
    assert!(
        StoreLease::acquire(&root).is_err(),
        "concurrent child writer must hold the OS lease"
    );

    child.0.kill().expect("forcefully terminate process");
    let exit = child.0.wait().expect("reap killed worker");
    assert!(
        !exit.success(),
        "test worker exited gracefully, not by kill"
    );
    // On Windows Child::kill() invokes TerminateProcess; unlike Linux
    // SIGKILL, Windows reports a process exit code rather than a Unix signal.
    // This is crash-process evidence, NOT power-loss persistence evidence.
    #[cfg(windows)]
    println!(
        "STY_G2_05E_WINDOWS_TERMINATE_PROCESS mode={mode} exit_code={:?}",
        exit.code()
    );
    drop(child);

    let owner = StoreLease::acquire(&root).expect("independent process reclaims OS lock");
    let payload = make_data();
    let expected = identity(&payload);
    let candidates = read_candidates(
        &owner,
        expected.manifest.id.0,
        expected.manifest.size,
        IROH_PREORDER_16K,
    )
    .expect("fail-closed checkpoint metadata parsing");

    let audited = audit_clean_closed_fixture(&root, expected, range());
    let physically_verified = match audited {
        Ok(bytes) => {
            assert_eq!(bytes, payload[START as usize..END as usize]);
            true
        }
        Err(error) => {
            println!("STY_G2_05A_PHYSICAL_AUDIT_HOLD mode={mode} reason={error}");
            false
        }
    };

    if mode == "uncommitted" {
        assert!(
            candidates.is_empty(),
            "interrupted live actor must not mint a published checkpoint"
        );
        // FsStore may have retained bytes or may have lost them. With no
        // checkpoint there is no authorization to skip, in either case.
    } else {
        assert_eq!(mode, "checkpointed");
        #[cfg(unix)]
        {
            assert_eq!(candidates, vec![claim(expected)]);
            assert!(
                physically_verified,
                "committed metadata needs physically authenticated bytes after process kill"
            );
        }
        #[cfg(windows)]
        {
            assert!(
                candidates.is_empty(),
                "Windows directory durability is unsupported and must fail closed"
            );
            // This mode cleanly shut down the actor before TerminateProcess.
            // A physical Bao readback MUST succeed before our final PASS marker
            // may claim one. This is still not a power-loss durability test.
            assert!(
                physically_verified,
                "Windows clean-shutdown attempt must pass post-kill physical Bao audit"
            );
        }
    }

    // Reopen the real pinned store in the second process, but never promote
    // its bitmap/status into a VerifiedCheckpoint without Bao readback.
    let reopened = FsStore::load(&root)
        .await
        .expect("FsStore reopens after process death");
    let backend_status = reopened
        .blobs()
        .status(Hash::from_bytes(expected.manifest.id.0))
        .await
        .expect("post-kill FsStore metadata status");
    println!(
        "STY_G2_05A_REOPEN mode={mode} backend_status={backend_status:?} checkpoint_candidates={} physically_verified={} trusted_skip=false",
        candidates.len(),
        physically_verified
    );
    reopened.shutdown().await.expect("clean up reopened actor");
    drop(reopened);
    drop(owner);
    fs::remove_dir_all(&root).expect("delete only private test root");
}

#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_kill_reopen_candidate_gate() {
    tokio::time::timeout(TEST_LIMIT, async {
        if let Ok(mode) = env::var(ENV_MODE) {
            let root = PathBuf::from(env::var_os(ENV_ROOT).expect("child test root"));
            child_writer(&root, &mode).await;
            return;
        }
        run_and_reopen("uncommitted").await;
        run_and_reopen("checkpointed").await;
        // Both child-process kill paths must finish before this marker.
        // Windows must never claim a durably published partial checkpoint.
        #[cfg(windows)]
        println!(
            "STY_G2_05E_WINDOWS_REAL_FSSTORE_KILL=PASS uncommitted=true              checkpoint_attempt_denied=true backend_release_or_fork=true              physical_bao_readback=true trusted_skip=false power_loss_tested=false"
        );
    })
    .await
    .expect("G2-05a subprocess and reopen must be bounded");
}
