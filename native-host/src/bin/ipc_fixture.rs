//! Disposable process fixture for real Linux inherited-socket IPC.
use staya_native_parent_lab::ipc::{receive_parent_arm, spawn_unarmed};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

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

fn await_file(root: &Path, name: &str) -> io::Result<()> {
    let start = Instant::now();
    while !root.join(name).is_file() {
        if start.elapsed() >= Duration::from_secs(12) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "IPC fixture not armed",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn run_worker(root: &Path, parent: u32) -> io::Result<()> {
    // This must succeed BEFORE any filesystem operation, even a marker.
    let _verified = receive_parent_arm(parent)?;
    publish(
        root,
        "ipc-worker-armed",
        b"SO_PEERCRED_PID_UID_GID_NONCE_ACK",
    )?;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn run_launcher(root: &Path) -> io::Result<()> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--worker")
        .arg(root)
        .arg(process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = spawn_unarmed(command)?.arm()?;
    publish(
        root,
        "ipc-worker-pid",
        child.process_id().to_string().as_bytes(),
    )?;
    await_file(root, "ipc-worker-armed")?;
    publish(
        root,
        "ipc-launcher-ready",
        b"FIRST_PARTY_KERNEL_SOCKET_ARMED",
    )?;
    let _retain_owner = child;
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
            .ok_or_else(|| io::Error::other("missing fixture root"))?,
    );
    if mode == "--worker" {
        let expected: u32 = args
            .next()
            .ok_or_else(|| io::Error::other("missing creator PID"))?
            .to_string_lossy()
            .parse()
            .map_err(|_| io::Error::other("invalid parent PID"))?;
        if args.next().is_some() {
            return Err(io::Error::other("unexpected worker argument"));
        }
        return run_worker(&root, expected);
    }
    if mode == "--launcher" && args.next().is_none() {
        return run_launcher(&root);
    }
    Err(io::Error::other("unrecognized IPC fixture command"))
}

fn main() {
    if let Err(err) = run() {
        eprintln!("STY_G2_IPC_HOLD {err}");
        process::exit(73);
    }
}
