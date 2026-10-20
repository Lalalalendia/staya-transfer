//! Real Windows OS grandparent -> launcher -> suspended Job worker fixture.
//! No installed Staya, FsStore, Akula, user documents or remote network use.
use staya_windows_job_lab::windows::SuspendedJobWorker;
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

fn publish(root: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let pending = root.join(format!(".{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?; // original writable Windows handle, never File::open
    drop(file);
    fs::rename(pending, root.join(name))
}

fn await_file(root: &Path, name: &str) -> io::Result<()> {
    let start = Instant::now();
    while !root.join(name).is_file() {
        if start.elapsed() > Duration::from_secs(12) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process fixture timeout: HOLD",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn worker(root: &Path) -> io::Result<()> {
    publish(
        root,
        "worker-started",
        b"EXECUTED_ONLY_AFTER_JOB_ASSIGNMENT",
    )?;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn launcher(root: &Path, inject_failure_before_assignment: bool) -> io::Result<()> {
    let executable = env::current_exe()?;
    let args: Vec<OsString> = vec![OsString::from("--worker"), root.as_os_str().to_os_string()];
    let suspended = SuspendedJobWorker::create(&executable, &args)?;
    publish(
        root,
        "worker-pid",
        suspended.process_id().to_string().as_bytes(),
    )?;
    // Grandparent independently opens a PROCESS-only wait handle while the
    // child is suspended; it NEVER receives a JobObject handle.
    await_file(root, "grandparent-has-process-handle")?;
    if root.join("worker-started").exists() {
        return Err(io::Error::other(
            "worker ran before suspended Job assignment",
        ));
    }

    if inject_failure_before_assignment {
        // A deliberate lab refusal: do not call AssignProcessToJobObject.
        // Dropping the guarded suspended child MUST kill/reap it; resume is
        // inaccessible on the SuspendedJobWorker type.
        drop(suspended);
        publish(root, "assignment-refused", b"FAIL_CLOSED_BEFORE_RESUME")?;
        return Ok(());
    }

    let assigned = suspended.assign()?;
    assert!(
        !root.join("worker-started").exists(),
        "worker executed before completing JobObject assignment"
    );
    let running = assigned.resume()?;
    await_file(root, "worker-started")?;
    publish(root, "launcher-ready", b"ASSIGNED_THEN_RESUMED")?;
    // Preserve the one noninheritable JobObject HANDLE until grandparent
    // performs REAL TerminateProcess on us. Rust Drop does not run then.
    let _keep_owned_job = running;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let mode = args
        .next()
        .ok_or_else(|| io::Error::other("missing test mode"))?;
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("missing root"))?,
    );
    if args.next().is_some() {
        return Err(io::Error::other("unexpected fixture command argument"));
    }
    if mode == "--worker" {
        return worker(&root);
    }
    if mode == "--launcher" {
        return launcher(&root, false);
    }
    if mode == "--launcher-refuse" {
        return launcher(&root, true);
    }
    Err(io::Error::other("unknown private Windows fixture mode"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("STY_G2_05H3F_HOLD: {error}");
        process::exit(73);
    }
}
