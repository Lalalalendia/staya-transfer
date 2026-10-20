//! Real Windows launcher/worker with JobObject assignment before pipe ARM.
use staya_windows_job_lab::{
    ipc::{PendingPipe, receive_parent_arm},
    windows::SuspendedJobWorker,
};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

fn publish(root: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let pending = root.join(format!(".{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(value)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, root.join(name))
}
fn wait_marker(root: &Path, name: &str) -> io::Result<()> {
    let start = Instant::now();
    while !root.join(name).is_file() {
        if start.elapsed() > Duration::from_secs(12) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "IPC marker timeout: HOLD",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
fn worker(root: &Path, pipe: &str, claimed_parent: u32) -> io::Result<()> {
    // Absolutely no marker, lockfile or store until kernel peer + nonce pass.
    let _session = receive_parent_arm(pipe, claimed_parent)?;
    publish(
        root,
        "ipc-worker-armed",
        b"WINDOWS_KERNEL_PIPE_PID_AND_NONCE",
    )?;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
fn launcher(root: &Path) -> io::Result<()> {
    let server = PendingPipe::create()?;
    let args = vec![
        OsString::from("--worker"),
        root.as_os_str().to_os_string(),
        OsString::from(server.name()),
        OsString::from(process::id().to_string()),
    ];
    let suspended = SuspendedJobWorker::create(&env::current_exe()?, &args)?;
    let pid = suspended.process_id();
    publish(root, "ipc-worker-pid", pid.to_string().as_bytes())?;
    let assigned = suspended.assign()?;
    if root.join("ipc-worker-armed").exists() {
        return Err(io::Error::other("worker ran before Job assignment: HOLD"));
    }
    let running = assigned.resume()?;
    let authenticated = server.arm(pid)?;
    wait_marker(root, "ipc-worker-armed")?;
    publish(
        root,
        "ipc-launcher-ready",
        b"JOB_ASSIGNED_THEN_KERNEL_PIPE_ARMED",
    )?;
    let _keep_handles = (running, authenticated);
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| io::Error::other("missing mode"))?;
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("missing root"))?,
    );
    if mode == "--worker" {
        let pipe = args
            .next()
            .ok_or_else(|| io::Error::other("missing pipe"))?
            .to_string_lossy()
            .into_owned();
        let claimed_parent = args
            .next()
            .ok_or_else(|| io::Error::other("missing parent PID"))?
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| io::Error::other("invalid parent PID"))?;
        if args.next().is_some() {
            return Err(io::Error::other("additional arguments forbidden"));
        }
        return worker(&root, &pipe, claimed_parent);
    }
    if mode == "--launcher" && args.next().is_none() {
        return launcher(&root);
    }
    Err(io::Error::other("unrecognized private Windows IPC command"))
}
fn main() {
    if let Err(error) = run() {
        eprintln!("STY_G2_05H3G3_HOLD {error}");
        process::exit(73);
    }
}
