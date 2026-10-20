//! Actual Windows OS parent/job/worker tests, not mocked peer identities.
use staya_windows_job_lab::{
    ipc::PendingPipe,
    windows::{ProcessWatcher, RunningJobWorker, SuspendedJobWorker},
};
use std::{
    env,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn fixture(case: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "staya-g2-windows-ipc-{}-{case}-{stamp}",
        std::process::id()
    ));
    assert!(!root.exists(), "never use an existing test root");
    fs::create_dir(&root).unwrap();
    root
}
fn child(root: &Path, pipe: &str, claimed_parent: u32) -> io::Result<RunningJobWorker> {
    let args = [
        OsString::from("--worker"),
        root.as_os_str().to_os_string(),
        OsString::from(pipe),
        OsString::from(claimed_parent.to_string()),
    ];
    SuspendedJobWorker::create(
        Path::new(env!("CARGO_BIN_EXE_staya-windows-pipe-fixture")),
        &args,
    )?
    .assign()?
    .resume()
}
fn wait_marker(root: &Path, name: &str, launcher: &mut Child) {
    let start = Instant::now();
    while !root.join(name).is_file() {
        assert!(
            launcher.try_wait().unwrap().is_none(),
            "launcher died before IPC ready"
        );
        assert!(
            start.elapsed() < Duration::from_secs(14),
            "IPC fixture marker timeout"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
struct KillLauncher(Child);
impl Drop for KillLauncher {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

#[test]
fn bound_windows_job_worker_arms_only_after_mutual_kernel_pid_and_nonce() -> io::Result<()> {
    let root = fixture("positive");
    let pending = PendingPipe::create()?;
    let running = child(&root, pending.name(), std::process::id())?;
    assert!(!root.join("ipc-worker-armed").exists());
    let witness = ProcessWatcher::open(running.process_id())?;
    let authenticated = pending.arm(running.process_id())?;
    let start = Instant::now();
    while !root.join("ipc-worker-armed").is_file() {
        assert!(!witness.exited(0)?, "worker died before ARM");
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "worker never ARM"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read(root.join("ipc-worker-armed"))?,
        b"WINDOWS_KERNEL_PIPE_PID_AND_NONCE"
    );
    drop(authenticated);
    drop(running);
    assert!(witness.exited(5000)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn wrong_claimed_launcher_pid_denied_by_worker_before_file_access() -> io::Result<()> {
    let root = fixture("wrong-server");
    let pending = PendingPipe::create()?;
    let running = child(&root, pending.name(), u32::MAX)?;
    assert!(
        pending.arm(running.process_id()).is_err(),
        "wrong parent may not ACK"
    );
    assert!(!root.join("ipc-worker-armed").exists());
    drop(running);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn wrong_actual_worker_pid_denied_by_server_before_arm() -> io::Result<()> {
    let root = fixture("wrong-client");
    let pending = PendingPipe::create()?;
    let running = child(&root, pending.name(), std::process::id())?;
    assert!(
        pending.arm(u32::MAX).is_err(),
        "kernel client PID != assigned worker"
    );
    assert!(!root.join("ipc-worker-armed").exists());
    drop(running);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_pipe_cannot_authorize_any_worker_file_write() -> io::Result<()> {
    let root = fixture("missing-pipe");
    let running = child(
        &root,
        r"\\.\pipe\staya-g2-05h3g3-99999-00000000000000000000000000000000",
        std::process::id(),
    )?;
    let witness = ProcessWatcher::open(running.process_id())?;
    assert!(witness.exited(5000)?, "nonexistent pipe worker must exit");
    assert!(!root.join("ipc-worker-armed").exists());
    drop(running);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_terminateprocess_launcher_kills_armed_job_worker() -> io::Result<()> {
    let root = fixture("parent-kill");
    let parent = Command::new(env!("CARGO_BIN_EXE_staya-windows-pipe-fixture"))
        .arg("--launcher")
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut launcher = KillLauncher(parent);
    wait_marker(&root, "ipc-launcher-ready", &mut launcher.0);
    let pid: u32 = fs::read_to_string(root.join("ipc-worker-pid"))?
        .parse()
        .unwrap();
    assert_ne!(pid, launcher.0.id());
    let independent = ProcessWatcher::open(pid)?;
    assert!(!independent.exited(0)?);
    assert_eq!(
        fs::read(root.join("ipc-worker-armed"))?,
        b"WINDOWS_KERNEL_PIPE_PID_AND_NONCE"
    );
    launcher.0.kill()?; // actual TerminateProcess, no Rust Drop in launcher
    assert!(!launcher.0.wait()?.success());
    assert!(
        independent.exited(10000)?,
        "last JobObject handle close must kill worker"
    );
    drop(launcher);
    fs::remove_dir_all(root)?;
    Ok(())
}
