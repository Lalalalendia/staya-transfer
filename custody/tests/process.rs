use staya_custody_lab::StoreLease;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn private_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "staya-g2-03-{}-{}-{nonce}",
        std::process::id(),
        label
    ));
    fs::create_dir(&path).expect("private empty root");
    path
}

fn worker(mode: &str, path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
        .arg(mode)
        .arg(path)
        .output()
        .expect("independent custody worker")
}

fn stdout_text(output: &std::process::Output) -> String {
    assert!(
        output.status.success(),
        "worker error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .expect("worker utf8")
        .trim()
        .to_owned()
}

#[test]
fn two_processes_and_normal_release() {
    let root = private_root("normal");
    let lease = StoreLease::acquire(&root).expect("first owner");
    assert_eq!(stdout_text(&worker("probe", &root)), "BUSY");
    lease
        .validate_fence()
        .expect("owner still owns same identity");
    drop(lease);

    // A stale lockfile still exists but MUST NOT block a new real OS owner.
    assert!(root.join(".staya-writer.lock").is_file());
    assert_eq!(stdout_text(&worker("probe", &root)), "ACQUIRED");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn terminate_owner_then_reacquire_in_separate_process() {
    let root = private_root("terminate");
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
        .arg("hold")
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn real owner");
    let mut line = String::new();
    let mut reader = BufReader::new(child.stdout.take().expect("child output"));
    let read = reader.read_line(&mut line).expect("child lock acquisition");
    assert!(read > 0, "child terminated before admitting owner");
    assert_eq!(line.trim(), "ACQUIRED");
    assert_eq!(stdout_text(&worker("probe", &root)), "BUSY");

    // Real SIGKILL on Linux; Child::kill invokes TerminateProcess on Windows.
    // There is intentionally no graceful FsStore or journal shutdown here.
    child.kill().expect("terminate owner process");
    child.wait().expect("reap terminated child");
    assert_eq!(stdout_text(&worker("probe", &root)), "ACQUIRED");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replacing_custody_lockfile_invalidates_prior_lease() {
    let root = private_root("lock-swap");
    let lease = StoreLease::acquire(&root).unwrap();
    let lock = lease.lock_path().to_owned();
    let moved = root.join("old-locked-inode");

    // Windows may forbid renaming open locked handles; that denial itself
    // prevents replacement. Unix generally allows rename of a held inode.
    if fs::rename(&lock, &moved).is_ok() {
        fs::write(&lock, b"new inode").unwrap();
        assert!(lease.validate_fence().is_err(), "old owner must HOLD");
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    } else {
        lease.validate_fence().expect("OS blocked replacement");
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn directory_replacement_invalidates_prior_lease() {
    let root = private_root("directory-swap");
    let lease = StoreLease::acquire(&root).unwrap();
    let moved = root.with_extension("renamed");

    if fs::rename(&root, &moved).is_ok() {
        fs::create_dir(&root).unwrap();
        assert!(lease.validate_fence().is_err(), "root inode changed");
        drop(lease);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    } else {
        lease
            .validate_fence()
            .expect("OS prevents moved open directory");
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn alias_of_same_root_does_not_acquire_second_writer() {
    let root = private_root("alias");
    let guard = StoreLease::acquire(&root).unwrap();
    // Canonical spellings reach the same inode and must not bypass ownership.
    let alias = root.join(".").join(".");
    assert_eq!(stdout_text(&worker("probe", &alias)), "BUSY");
    guard.validate_fence().unwrap();
    drop(guard);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
fn debug_lock_ownership(root: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let lock = root.join(".staya-writer.lock");
    let inode = fs::metadata(&lock).ok().map(|m| m.ino());
    let mut own_fds = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc/self/fd") {
        for entry in entries.flatten() {
            if fs::read_link(entry.path()).ok().as_deref() == Some(lock.as_path()) {
                own_fds.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let current_locks = fs::read_to_string("/proc/locks").unwrap_or_default();
    let inode_token = inode.map(|id| format!(":{id} ")).unwrap_or_default();
    let active = current_locks
        .lines()
        .filter(|line| line.contains(&inode_token))
        .take(8)
        .collect::<Vec<_>>();
    format!(
        "lock={} inode={inode:?} this_process_lock_fds={own_fds:?} proc_locks={active:?}",
        lock.display()
    )
}

#[cfg(not(target_os = "linux"))]
fn debug_lock_ownership(_root: &Path) -> String {
    "Linux /proc lock diagnostics unavailable".to_owned()
}

#[test]
fn repeated_drop_and_reacquire_has_no_stale_lock_descriptor() {
    let root = private_root("reacquire-128");
    for cycle in 0..128 {
        let lease = StoreLease::acquire(&root).unwrap_or_else(|err| {
            panic!(
                "reacquire cycle {cycle} failed: {err:?}; {}",
                debug_lock_ownership(&root)
            )
        });
        lease.validate_fence().expect("owned physical identity");
        if cycle % 32 == 0 {
            assert_eq!(
                stdout_text(&worker("probe", &root)),
                "BUSY",
                "cycle {cycle}: another OS process cannot enter while held"
            );
        }
        drop(lease);
        if cycle % 32 == 0 {
            assert_eq!(
                stdout_text(&worker("probe", &root)),
                "ACQUIRED",
                "cycle {cycle}: another OS process must enter immediately after release"
            );
        }
    }
    println!("STY_G2_05D_CUSTODY_STRESS cycles=128 cross_process_checks=8 success=true");
    fs::remove_dir_all(root).unwrap();
}

/// Linux-only, diagnostic experiment: compare uncontended lease turnover
/// against the same operation while a distinct thread repeatedly spawns
/// unrelated OS processes. A forked child may transiently retain an inherited
/// open file description before exec closes CLOEXEC descriptors. This is an
/// inference to TEST, not a claimed explanation for the existing EWOULDBLOCK.
///
/// The subprocesses touch a DIFFERENT, private directory. No busy error is
/// swallowed by production code: the required 128-cycle regression remains
/// unchanged and independently failing CI still blocks this Draft PR.
#[cfg(target_os = "linux")]
#[test]
fn linux_unrelated_spawn_interference_diagnostic() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };

    fn count_busy(root: &Path, cycles: usize, explicit_release: bool) -> usize {
        let mut busy = 0;
        for _ in 0..cycles {
            match StoreLease::acquire(root) {
                Ok(lease) => {
                    lease.validate_fence().expect("stable private root");
                    if explicit_release {
                        lease.release().expect("quiescent explicit unlock");
                    } else {
                        drop(lease);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => busy += 1,
                Err(err) => panic!("unexpected acquisition error: {err:?}"),
            }
        }
        busy
    }

    let root = private_root("unrelated-spawn-target");
    let explicit_root = private_root("unrelated-spawn-explicit");
    let unrelated_root = private_root("unrelated-spawn-child");
    let baseline_busy = count_busy(&root, 1024, false);

    let started = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_started = Arc::clone(&started);
    let thread_stop = Arc::clone(&stop);
    let spawner = std::thread::spawn(move || {
        thread_started.wait();
        let mut subprocesses = 0;
        while !thread_stop.load(Ordering::Acquire) {
            let result = worker("probe", &unrelated_root);
            assert_eq!(stdout_text(&result), "ACQUIRED");
            subprocesses += 1;
        }
        fs::remove_dir_all(unrelated_root).expect("remove unrelated private root");
        subprocesses
    });

    started.wait();
    let spawn_busy = count_busy(&root, 8192, false);
    // A/B only: release() performs explicit LOCK_UN after quiescence. The
    // normal Drop-only behavior remains separately required and unchanged.
    let explicit_busy = count_busy(&explicit_root, 8192, true);
    stop.store(true, Ordering::Release);
    let subprocesses = spawner.join().expect("unrelated subprocess test thread");
    println!(
        "STY_G2_05D_LINUX_SPAWN_AB baseline_wouldblock={baseline_busy} spawn_wouldblock={spawn_busy} explicit_release_wouldblock={explicit_busy} unrelated_subprocesses={subprocesses} cycles_baseline=1024 cycles_spawn_each=8192"
    );
    assert!(subprocesses > 0, "spawn-stress condition must be exercised");
    // Zero observed contention is inconclusive; a nonzero number would
    // independently reproduce the issue under concurrent, unrelated spawn.
    fs::remove_dir_all(root).expect("remove target private root");
    fs::remove_dir_all(explicit_root).expect("remove explicit release private root");
}

/// An explicit LOCK_UN experiment; does not replace or silence the separate
/// Drop-only 128-cycle stress test. Both must be reported independently.
#[test]
fn explicit_unlock_reacquire_128_with_competing_process() {
    let root = private_root("explicit-unlock-128");
    for cycle in 0..128 {
        let lease = StoreLease::acquire(&root).unwrap_or_else(|err| {
            panic!(
                "explicit-release cycle {cycle} failed: {err:?}; {}",
                debug_lock_ownership(&root)
            )
        });
        lease.validate_fence().expect("lease still valid");
        if cycle % 32 == 0 {
            assert_eq!(stdout_text(&worker("probe", &root)), "BUSY");
        }
        lease.release().expect("explicit OS unlock with live owner");
        if cycle % 32 == 0 {
            assert_eq!(stdout_text(&worker("probe", &root)), "ACQUIRED");
        }
    }
    println!("STY_G2_05D_EXPLICIT_UNLOCK cycles=128 cross_process_checks=8 success=true");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn symbolic_link_alias_is_denied() {
    use std::os::unix::fs::symlink;
    let root = private_root("symlink");
    let alias = root.with_extension("link");
    symlink(&root, &alias).unwrap();
    assert!(StoreLease::acquire(&alias).is_err());
    fs::remove_file(alias).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_symlink_alias_is_denied_if_creation_permitted() {
    use std::os::windows::fs::symlink_dir;
    let root = private_root("symlink");
    let alias = root.with_extension("link");
    if symlink_dir(&root, &alias).is_ok() {
        assert!(StoreLease::acquire(&alias).is_err());
        fs::remove_dir(alias).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hard_link_to_locked_file_cannot_acquire_separate_lock() {
    use std::fs::{OpenOptions, TryLockError};
    let root = private_root("hardlink");
    let lease = StoreLease::acquire(&root).unwrap();
    let alias = root.join("hardlink-to-lease");
    fs::hard_link(lease.lock_path(), &alias).expect("same-volume hardlink");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(alias)
        .unwrap();
    assert!(matches!(file.try_lock(), Err(TryLockError::WouldBlock)));
    drop(file);
    drop(lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_root_is_never_created_by_untrusted_request() {
    let root = private_root("nonexistent");
    fs::remove_dir(&root).unwrap();
    assert!(StoreLease::acquire(&root).is_err());
    assert!(!root.exists());
}
