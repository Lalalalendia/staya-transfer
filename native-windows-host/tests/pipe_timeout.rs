//! STY-G2-05h3g5: real kernel timeouts and cancellation before any File Gate.
//! Never substitutes sleeps or mocked handles for pending Windows pipe I/O.

use staya_windows_job_lab::{
    ipc::PendingPipe,
    windows::{ProcessWatcher, SuspendedJobWorker},
};
use std::{
    env,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn private_root(case: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("monotonic private fixture label")
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "staya-bounded-windows-ipc-{}-{case}-{stamp}",
        std::process::id()
    ));
    assert!(!root.exists(), "must not reuse a user folder");
    fs::create_dir(&root).expect("create disposable IPC fixture");
    root
}

#[test]
fn absent_job_worker_does_not_block_pipe_connect_forever() -> io::Result<()> {
    let server = PendingPipe::create()?;
    let started = Instant::now();
    let error = match server.arm(u32::MAX) {
        Err(error) => error,
        Ok(_) => panic!("pipe admitted a worker that was never launched"),
    };
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "no-client pending kernel ConnectNamedPipe must time out"
    );
    assert!(
        started.elapsed() < Duration::from_secs(13),
        "CancelIoEx + completion drain must end the pending connect"
    );
    println!("STY_G2_05H3G5 no_client=true cancellation_drained=true");
    Ok(())
}

#[test]
fn worker_connected_but_no_arm_exits_before_any_file_access() -> io::Result<()> {
    let root = private_root("no-arm");
    let server = PendingPipe::create()?;
    let args = [
        OsString::from("--worker"),
        root.as_os_str().to_os_string(),
        OsString::from(server.name()),
        OsString::from(std::process::id().to_string()),
    ];
    let worker = SuspendedJobWorker::create(
        Path::new(env!("CARGO_BIN_EXE_staya-windows-pipe-fixture")),
        &args,
    )?
    .assign()?
    .resume()?;
    let witness = ProcessWatcher::open(worker.process_id())?;
    assert!(
        witness.exited(13_000)?,
        "real named-pipe reader must time out and fail closed without ARM"
    );
    assert!(
        !root.join("ipc-worker-armed").exists(),
        "timeout must not be promoted to an authenticated IPC session"
    );
    drop(worker);
    drop(server);
    fs::remove_dir_all(root)?;
    println!("STY_G2_05H3G5 missing_arm=true worker_exited=true file_gate=false");
    Ok(())
}
