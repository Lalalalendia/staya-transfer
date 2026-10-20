//! Three real Linux OS-process falsifiers, with an actual inherited socket.
use staya_native_parent_lab::{ipc::spawn_unarmed, linux::PidFd};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WAIT: Duration = Duration::from_secs(12);

fn fixture(case: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "staya-g2-linux-ipc-{}-{case}-{nonce}",
        std::process::id()
    ));
    assert!(!root.exists(), "fixture must never reuse user data");
    fs::create_dir(&root).unwrap();
    root
}

fn await_marker(root: &Path, name: &str) {
    let started = Instant::now();
    while !root.join(name).is_file() {
        assert!(started.elapsed() < WAIT, "missing fixture marker {name}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn command(root: &Path, claimed_parent: u32) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_staya-linux-ipc-fixture"));
    command
        .arg("--worker")
        .arg(root)
        .arg(claimed_parent.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
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
fn real_own_fd_and_kernel_credentials_gate_child_before_arm() -> io::Result<()> {
    let root = fixture("authenticated");
    let unarmed = spawn_unarmed(command(&root, std::process::id()))?;
    assert!(
        !root.join("ipc-worker-armed").exists(),
        "worker ran before ARM"
    );
    let pidfd = PidFd::open(unarmed.process_id())?;
    assert!(!pidfd.exited(0)?);
    let armed = unarmed.arm()?;
    await_marker(&root, "ipc-worker-armed");
    assert_eq!(
        fs::read(root.join("ipc-worker-armed"))?,
        b"SO_PEERCRED_PID_UID_GID_NONCE_ACK"
    );
    assert!(
        !pidfd.exited(0)?,
        "kernel-backed worker unexpectedly exited"
    );
    let status = armed.terminate_and_reap()?;
    assert!(!status.success());
    assert!(pidfd.exited(5000)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn wrong_claimed_parent_refused_before_any_file_access() -> io::Result<()> {
    let root = fixture("wrong-parent");
    let unarmed = spawn_unarmed(command(&root, u32::MAX))?;
    assert!(
        unarmed.arm().is_err(),
        "wrong claimed parent must not authenticate even with real socket"
    );
    assert!(!root.join("ipc-worker-armed").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_inherited_socket_refused_before_file_access() -> io::Result<()> {
    let root = fixture("missing-fd");
    let status = command(&root, std::process::id()).status()?;
    assert!(!status.success(), "no inherited socket must fail closed");
    assert!(!root.join("ipc-worker-armed").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn hard_kill_launcher_kills_authenticated_ipc_worker() -> io::Result<()> {
    let root = fixture("parent-kill");
    let mut launcher = KillLauncher(
        Command::new(env!("CARGO_BIN_EXE_staya-linux-ipc-fixture"))
            .arg("--launcher")
            .arg(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    await_marker(&root, "ipc-launcher-ready");
    let pid: u32 = fs::read_to_string(root.join("ipc-worker-pid"))?
        .parse()
        .expect("kernel worker PID");
    let witness = PidFd::open(pid)?;
    assert!(!witness.exited(0)?);
    assert_eq!(
        fs::read(root.join("ipc-worker-armed"))?,
        b"SO_PEERCRED_PID_UID_GID_NONCE_ACK"
    );
    launcher.0.kill()?;
    assert!(!launcher.0.wait()?.success());
    assert!(
        witness.exited(8000)?,
        "PDEATHSIG must kill the real authenticated socket worker"
    );
    drop(launcher);
    fs::remove_dir_all(root)?;
    Ok(())
}
