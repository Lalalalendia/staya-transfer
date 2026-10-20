//! Real Linux OS tests: live pidfd and independent launcher SIGKILL.
use staya_native_parent_lab::linux::PidFd;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WAIT: Duration = Duration::from_secs(12);

fn fresh_root(case: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test nonce")
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "staya-native-g2-05h3e-{}-{case}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("disposable unique test root");
    root
}

struct Launcher(Child);
impl Drop for Launcher {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn await_marker(root: &Path, name: &str, parent: &mut Child) {
    let started = Instant::now();
    while !root.join(name).is_file() {
        assert!(
            parent.try_wait().unwrap().is_none(),
            "launcher exited before child registered: {name}"
        );
        assert!(started.elapsed() < WAIT, "never observed {name}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_hard_kill(arm: bool) {
    let root = fresh_root(if arm { "armed" } else { "unarmed" });
    let exe = env!("CARGO_BIN_EXE_staya-native-parent-lab");
    let child = Command::new(exe)
        .arg("--launcher")
        .arg(&root)
        .arg(if arm { "armed" } else { "unarmed" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start independent launcher OS process");
    let mut launcher = Launcher(child);

    await_marker(&root, "launcher-ready", &mut launcher.0);
    let child_pid: u32 = fs::read_to_string(root.join("worker-pid"))
        .expect("published real child identity")
        .parse()
        .expect("real numeric OS child PID");
    assert_ne!(child_pid, launcher.0.id());
    let witness = PidFd::open(child_pid).expect("Linux pidfd for live child");
    assert!(
        !witness.exited(0).unwrap(),
        "worker exited before parent SIGKILL"
    );

    if arm {
        assert_eq!(
            fs::read(root.join("worker-armed")).expect("post-ARM synced marker"),
            b"ARM_AFTER_PARENT_BIND"
        );
    } else {
        assert!(!root.join("worker-armed").exists(), "worker ran before ARM");
    }

    // Actual hard kill: dropping Child or closing stdin alone is not proof.
    launcher.0.kill().expect("SIGKILL launcher");
    launcher.0.wait().expect("reap independent launcher");
    assert!(
        witness.exited(8000).expect("pidfd OS exit poll"),
        "child survived parent SIGKILL: HOLD"
    );
    if !arm {
        assert!(
            !root.join("worker-armed").exists(),
            "unarmed child must never publish writable marker"
        );
    }
    fs::remove_dir_all(root).expect("remove disposable native lab root");
}

#[test]
fn parent_sigkill_kills_armed_child_without_clean_ack() {
    run_hard_kill(true);
}

#[test]
fn parent_sigkill_kills_unarmed_child_before_write() {
    run_hard_kill(false);
}

#[test]
fn wrong_parent_identity_is_denied_before_arm() -> io::Result<()> {
    let root = fresh_root("wrong-parent");
    let status = Command::new(env!("CARGO_BIN_EXE_staya-native-parent-lab"))
        .arg("--worker")
        .arg(&root)
        .arg(u32::MAX.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(!status.success(), "wrong parent must fail closed");
    assert!(!root.join("worker-armed").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}
