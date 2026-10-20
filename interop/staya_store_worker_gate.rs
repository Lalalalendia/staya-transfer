//! G2-05h3g: real pinned FsStore under Linux PDEATHSIG / Windows JobObject.
//! Independent observer kills its launcher and verifies native worker death,
//! cooperative OS lock reacquisition and physical Bao against trusted BLAKE3.
//! Linux verifies kernel-bound IPC before store open; still no executable
//! attestation, clean shutdown, durable grant or File Gate authorization.

use bao_tree::{
    BaoTree, BlockSize, ByteRanges,
    io::{outboard::PreOrderOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use staya_custody_lab::{
    StoreLease,
    checkpoint::{IROH_PREORDER_16K, read_candidates},
};
use staya_transfer::{ByteRange, ContentId, Manifest, TransferRequest, bao::verify_bao_range};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use staya_native_parent_lab::{ipc::spawn_unarmed, linux::PidFd};
#[cfg(windows)]
use staya_windows_job_lab::windows::{ProcessWatcher, SuspendedJobWorker};

const LAUNCHER_ENV: &str = "STY_G2_05H3G_LAUNCHER_ROOT";
const TEST_NAME: &str = "real_fsstore_native_containment_survives_parent_kill";
const WORKER_READY: &str = ".g2-05h3g-fsstore-ready";
const WORKER_PID: &str = ".g2-05h3g-worker-pid";
const LAUNCHER_READY: &str = ".g2-05h3g-launcher-ready";
// Exactly equal to the real worker's size; large enough to require a
// physical outboard under both pinned FsStore variants.
const OBJECT_SIZE: usize = 16 * 1024 * 1024 + 17;
const START: u64 = 33_333;
const END: u64 = 100_111;
const DEADLINE: Duration = Duration::from_secs(65);

fn payload() -> Vec<u8> {
    (0..OBJECT_SIZE)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect()
}

fn publish(root: &Path, name: &str, content: &[u8]) -> io::Result<()> {
    let pending = root.join(format!(".{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, root.join(name))
}

fn launcher(root: &Path) -> io::Result<()> {
    let executable = Path::new(env!("CARGO_BIN_EXE_staya-store-worker"));

    #[cfg(target_os = "linux")]
    let linux_running = {
        let mut command = Command::new(executable);
        command
            .arg(root)
            .arg(process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let unarmed = spawn_unarmed(command)?;
        // The worker process exists but has not yet received private ARM.
        if root.join(".staya-writer.lock").exists() || root.join("data").exists() {
            return Err(io::Error::other("real FsStore opened before IPC ARM: HOLD"));
        }
        unarmed.arm()?
    };
    #[cfg(target_os = "linux")]
    let pid = linux_running.process_id();

    #[cfg(windows)]
    let running = {
        let args = vec![
            root.as_os_str().to_os_string(),
            process::id().to_string().into(),
        ];
        let suspended = SuspendedJobWorker::create(executable, &args)?;
        if root.join(WORKER_READY).exists() {
            return Err(io::Error::other("worker started before Job assignment"));
        }
        let assigned = suspended.assign()?;
        if root.join(WORKER_READY).exists() {
            return Err(io::Error::other("worker executed before Job assignment"));
        }
        assigned.resume()?
    };
    #[cfg(windows)]
    let pid = running.process_id();

    #[cfg(target_os = "linux")]
    let worker_witness = PidFd::open(pid)?;
    publish(root, WORKER_PID, pid.to_string().as_bytes())?;
    let started = Instant::now();
    while !root.join(WORKER_READY).is_file() {
        #[cfg(target_os = "linux")]
        if worker_witness.exited(0)? {
            return Err(io::Error::other(
                "IPC-authenticated real FsStore worker exited before readiness",
            ));
        }
        #[cfg(windows)]
        if ProcessWatcher::open(pid)?.exited(0)? {
            return Err(io::Error::other(
                "Windows FsStore worker exited before readiness",
            ));
        }
        if started.elapsed() >= DEADLINE {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native FsStore startup deadline exceeded: HOLD",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
    publish(root, LAUNCHER_READY, b"WORKER_OS_OWNED_REAL_FSSTORE")?;
    #[cfg(windows)]
    let _keep_job_owner = running;
    #[cfg(target_os = "linux")]
    let _keep_kernel_ipc_owner = linux_running;
    loop {
        #[cfg(target_os = "linux")]
        if worker_witness.exited(0)? {
            return Err(io::Error::other("IPC-authenticated FsStore worker died"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn audit_physical_bao(root: &Path, expected: blake3::Hash) {
    let bytes = payload();
    let hex = expected.to_hex().to_string();
    let data_path = root.join("data").join(format!("{hex}.data"));
    let bao_path = root.join("data").join(format!("{hex}.obao4"));
    assert_eq!(fs::read(&data_path).expect("physical data"), bytes);
    let tree = BaoTree::new(OBJECT_SIZE as u64, BlockSize::from_chunk_log(4));
    assert_eq!(
        fs::metadata(&bao_path)
            .expect("real FsStore outboard")
            .len(),
        tree.outboard_size()
    );
    let data = fs::File::open(data_path).expect("physical data handle");
    let proof = fs::File::open(bao_path).expect("physical outboard handle");
    let outboard = PreOrderOutboard {
        root: expected,
        tree,
        data: &proof,
    };
    let chunks = round_up_to_chunks(&ByteRanges::from(START..END));
    let mut wire = Vec::new();
    encode_ranges_validated(&data, outboard, &chunks, &mut wire)
        .expect("real on-disk Bao encoding");
    let request = TransferRequest::new(
        Manifest {
            id: ContentId(*expected.as_bytes()),
            size: OBJECT_SIZE as u64,
        },
        ByteRange::new(START, END, OBJECT_SIZE as u64).unwrap(),
    )
    .unwrap();
    let verified = verify_bao_range(&request, &wire).expect("independent root-authenticated Bao");
    assert_eq!(
        verified.bytes(),
        &bytes[START as usize..END as usize],
        "post-kill Bao bytes must match immutable trusted payload"
    );
}

#[test]
fn real_fsstore_native_containment_survives_parent_kill() {
    if let Some(root) = std::env::var_os(LAUNCHER_ENV) {
        launcher(Path::new(&root)).expect("native launcher must hold worker lifetime");
        return;
    }

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("valid clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-g2-05h3g-{}-{unique}-{}",
        process::id(),
        std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned())
    ));
    assert!(!root.exists(), "never reuse a private FsStore test root");
    fs::create_dir(&root).expect("create disposable native FsStore root");

    let mut parent = KillOnDrop(
        Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(LAUNCHER_ENV, &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn independent native worker launcher"),
    );
    let started = Instant::now();
    while !root.join(LAUNCHER_READY).is_file() {
        if let Some(status) = parent.0.try_wait().expect("launcher OS status") {
            panic!("native launcher exited before FsStore readiness: {status}");
        }
        assert!(
            started.elapsed() < DEADLINE,
            "native FsStore launcher failed to reach READY"
        );
        thread::sleep(Duration::from_millis(25));
    }
    let pid: u32 = fs::read_to_string(root.join(WORKER_PID))
        .expect("native worker PID marker")
        .parse()
        .expect("worker PID must be numeric");

    #[cfg(target_os = "linux")]
    let witness = PidFd::open(pid).expect("independent pidfd of real FsStore worker");
    #[cfg(windows)]
    let witness = ProcessWatcher::open(pid).expect("independent native process handle");

    assert!(
        !witness.exited(0).expect("live kernel worker witness"),
        "worker exited before launcher kill"
    );
    assert!(
        matches!(
            StoreLease::acquire(&root),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
        ),
        "another OS process cannot acquire the active worker's StoreLease"
    );
    let expected = blake3::hash(&payload());
    assert_eq!(
        fs::read(root.join(WORKER_READY)).expect("post-write readiness"),
        expected.as_bytes(),
        "fixture marker is diagnostic, not a checkpoint"
    );

    parent.0.kill().expect("terminate real owning launcher");
    assert!(
        !parent.0.wait().expect("reap launcher").success(),
        "launcher must not have exited cleanly"
    );
    assert!(
        witness
            .exited(15000)
            .expect("native worker death observation"),
        "OS-contained real FsStore worker survived launcher death: HOLD"
    );
    let next_owner =
        StoreLease::acquire(&root).expect("only after actual worker death may OS custody return");
    next_owner
        .validate_fence()
        .expect("new independently acquired physical fence");
    audit_physical_bao(&root, expected);
    assert!(
        read_candidates(
            &next_owner,
            *expected.as_bytes(),
            OBJECT_SIZE as u64,
            IROH_PREORDER_16K
        )
        .expect("candidate readback")
        .is_empty(),
        "worker readiness or parent death must not publish checkpoint claims"
    );
    drop(next_owner);
    drop(witness);
    drop(parent);
    fs::remove_dir_all(&root).expect("only owned disposable native test data");
    println!(
        "STY_G2_05H3G native_parent_death=true real_fsstore=true \
         os_worker_exit=true independent_bao=true candidate_checkpoint=false file_gate=false"
    );
}

#[cfg(target_os = "linux")]
fn disposable_ipc_root(case: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock for unique native IPC fixture")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-g2-05h3g2-ipc-{}-{case}-{unique}",
        process::id()
    ));
    assert!(!root.exists(), "no preexisting stores or user files");
    fs::create_dir(&root).expect("create disposable native IPC fixture");
    root
}

#[cfg(target_os = "linux")]
fn real_ipc_worker_command(root: &Path, claimed_parent: u32) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_staya-store-worker"));
    cmd.arg(root)
        .arg(claimed_parent.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

#[cfg(target_os = "linux")]
fn assert_ipc_has_not_created_custody(root: &Path) {
    assert!(
        !root.join(".staya-writer.lock").exists(),
        "StoreLease must not exist before kernel IPC ARM"
    );
    assert!(
        !root.join("data").exists(),
        "real pinned FsStore must not start before verified IPC"
    );
    assert!(
        !root.join(WORKER_READY).exists(),
        "unverified worker may not publish readiness"
    );
}

/// A genuine worker exists, but withholding private ARM leaves custody
/// unopened even after the child has had time to run.
#[cfg(target_os = "linux")]
#[test]
fn real_fsstore_ipc_denies_unarmed_without_custody() {
    let root = disposable_ipc_root("no-arm");
    let child = spawn_unarmed(real_ipc_worker_command(&root, process::id()))
        .expect("spawn actual unarmed FsStore binary");
    thread::sleep(Duration::from_millis(120));
    assert_ipc_has_not_created_custody(&root);
    drop(child); // kill and reap unarmed OS worker, not a clean receipt
    assert_ipc_has_not_created_custody(&root);
    fs::remove_dir_all(root).expect("only own disposable data");
}

#[cfg(target_os = "linux")]
#[test]
fn real_fsstore_ipc_denies_wrong_parent_before_custody() {
    let root = disposable_ipc_root("wrong-parent");
    let child = spawn_unarmed(real_ipc_worker_command(&root, u32::MAX))
        .expect("spawn first-party binary with wrong claimed creator");
    assert!(
        child.arm().is_err(),
        "wrong creator PID must fail before StoreLease"
    );
    assert_ipc_has_not_created_custody(&root);
    fs::remove_dir_all(root).expect("only own disposable data");
}

#[cfg(target_os = "linux")]
#[test]
fn real_fsstore_ipc_denies_missing_socket_before_custody() {
    let root = disposable_ipc_root("missing-fd");
    let status = real_ipc_worker_command(&root, process::id())
        .status()
        .expect("spawn a real worker without the inherited kernel socket");
    assert!(!status.success(), "no IPC socket must fail closed");
    assert_ipc_has_not_created_custody(&root);
    fs::remove_dir_all(root).expect("only own disposable data");
}
