//! Independent real Windows processes: no mocked Job or surrogate ACK.
use staya_windows_job_lab::windows::ProcessWatcher;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_WAIT: Duration = Duration::from_secs(15);

fn private_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "staya-g2-05h3f-{}-{label}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("unique disposable OS process root");
    path
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

fn await_file(root: &Path, name: &str, launcher: &mut Child) {
    let started = Instant::now();
    while !root.join(name).is_file() {
        assert!(
            launcher.try_wait().unwrap().is_none(),
            "launcher exited before {name} was published"
        );
        assert!(started.elapsed() < MAX_WAIT, "missing {name}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_case(fail_assignment: bool) {
    let root = private_root(if fail_assignment { "denied" } else { "killed" });
    let executable = env!("CARGO_BIN_EXE_staya-windows-job-lab");
    let mode = if fail_assignment {
        "--launcher-refuse"
    } else {
        "--launcher"
    };
    let child = Command::new(executable)
        .arg(mode)
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start independent OS launcher process");
    let mut launcher = Launcher(child);

    await_file(&root, "worker-pid", &mut launcher.0);
    let pid: u32 = fs::read_to_string(root.join("worker-pid"))
        .expect("get OS worker pid")
        .parse()
        .expect("parse OS process identity");
    assert_ne!(pid, launcher.0.id());
    let worker = ProcessWatcher::open(pid)
        .expect("grandparent pins PROCESS wait handle, not the Job handle");
    assert!(
        !worker.exited(0).unwrap(),
        "worker exited before parent signalled launch decision"
    );
    assert!(
        !root.join("worker-started").exists(),
        "worker wrote before suspended Job attachment"
    );
    fs::write(root.join("grandparent-has-process-handle"), b"OBSERVED").unwrap();

    if fail_assignment {
        await_file(&root, "assignment-refused", &mut launcher.0);
        launcher.0.wait().expect("reap refusing launcher");
        assert!(
            worker.exited(10_000).expect("kernel worker exit witness"),
            "suspended process survived failed admission"
        );
        assert!(
            !root.join("worker-started").exists(),
            "rejected worker executed in spite of never being resumed"
        );
    } else {
        await_file(&root, "launcher-ready", &mut launcher.0);
        assert_eq!(
            fs::read(root.join("worker-started")).expect("check real execution"),
            b"EXECUTED_ONLY_AFTER_JOB_ASSIGNMENT"
        );
        assert!(
            !worker.exited(0).unwrap(),
            "worker died before native launcher hard kill"
        );
        // This is a true Windows TerminateProcess of launcher, not Rust
        // Drop. The process owns the ONLY JobObject HANDLE; the separate
        // PROCESS wait handle intentionally does not keep the job alive.
        launcher
            .0
            .kill()
            .expect("native Windows TerminateProcess launcher");
        launcher.0.wait().expect("reap launcher OS process");
        assert!(
            worker.exited(10_000).expect("kernel child-process exit"),
            "KILL_ON_JOB_CLOSE failed to terminate worker: HOLD"
        );
    }

    fs::remove_dir_all(root).expect("remove disposable OS test files");
}

#[test]
fn real_terminateprocess_launcher_kills_resumed_job_worker() {
    run_case(false);
}

#[test]
fn denied_assignment_never_resumes_suspended_worker() {
    run_case(true);
}
