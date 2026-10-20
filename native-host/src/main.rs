//! G2-05h3e private process fixture: grandparent -> launcher -> worker.
//! No persistent store, user documents, network grants or Akula are touched.
use staya_native_parent_lab::linux::{bind_actual_parent, require_parent_death_before_exec};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn publish(root: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let pending = root.join(format!(".{name}.pending"));
    let target = root.join(name);
    let mut writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    writable.write_all(data)?;
    writable.sync_all()?; // original writable handle: Windows parity later
    drop(writable);
    fs::rename(pending, target)
}

fn await_file(root: &Path, name: &str, timeout: Duration) -> io::Result<()> {
    let started = Instant::now();
    while !root.join(name).is_file() {
        if started.elapsed() > timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native parent/worker fixture handshake timeout",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn worker(root: &Path, expected_parent: u32) -> io::Result<()> {
    // Prior to trusting a byte on stdin, bind to the kernel's parent process.
    let parent = bind_actual_parent(expected_parent)?;
    let mut arm = [0u8; 1];
    io::stdin().read_exact(&mut arm)?;
    if arm != *b"A" || parent.exited(0)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "missing/invalid ARM or dead parent: HOLD",
        ));
    }
    publish(root, "worker-armed", b"ARM_AFTER_PARENT_BIND")?;
    // PDEATHSIG kills this real OS process even when it is blocked here.
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn launcher(root: &Path, armed: bool) -> io::Result<()> {
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("--worker")
        .arg(root)
        .arg(process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    require_parent_death_before_exec(&mut command, process::id());
    // Real spawn returns only after the child has installed PDEATHSIG before exec.
    let mut child = command.spawn()?;
    publish(root, "worker-pid", child.id().to_string().as_bytes())?;
    if armed {
        let pipe = child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("registered stdin writer missing"))?;
        pipe.write_all(b"A")?;
        pipe.flush()?;
        await_file(root, "worker-armed", Duration::from_secs(10))?;
    }
    publish(root, "launcher-ready", b"CHILD_REGISTERED")?;
    // Launcher is deliberately hard-killed by a third independent process.
    // Dropping a Child handle alone would not kill it; kernel PDEATHSIG must.
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args_os();
    let _exe = args.next();
    let mode = args
        .next()
        .ok_or_else(|| io::Error::other("missing fixture mode"))?;
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("missing root"))?,
    );
    if mode == "--worker" {
        let expected = args
            .next()
            .ok_or_else(|| io::Error::other("missing parent PID"))?
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| io::Error::other("invalid parent PID"))?;
        if args.next().is_some() {
            return Err(io::Error::other("unexpected worker input"));
        }
        return worker(&root, expected);
    }
    if mode == "--launcher" {
        let mode = args
            .next()
            .ok_or_else(|| io::Error::other("missing ARM mode"))?;
        if args.next().is_some() {
            return Err(io::Error::other("unexpected launcher input"));
        }
        return launcher(&root, mode == "armed");
    }
    Err(io::Error::other("unknown private process fixture mode"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("STY_G2_05H3E_HOLD: {error}");
        process::exit(73);
    }
}
