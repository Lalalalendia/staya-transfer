//! G2-05h3c real OS subprocess custody and register-vs-close regressions.
use staya_custody_lab::{
    StoreLease,
    child_registry::{ReapedChildren, WriterProcessRegistry},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-g2-05h3c-{}-{label}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn waiting_child(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"));
    command.arg("arm-hold").arg(root);
    command
}

fn expect_child_owns_store(root: &Path) {
    let started = Instant::now();
    loop {
        match StoreLease::acquire(root) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Ok(lease) => drop(lease),
            Err(e) => panic!("unexpected custody error: {e}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "ARM child failed to acquire real OS custody"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn registered_child_is_inert_until_arm_then_busy_then_reaped() {
    let root = root("real-owner");
    let registry = WriterProcessRegistry::new(1).unwrap();
    let id = registry.spawn_unarmed(waiting_child(&root)).unwrap();
    let lease = StoreLease::acquire(&root).expect("unarmed child has no lease");
    lease.validate_fence().unwrap();
    drop(lease);
    assert!(registry.spawn_unarmed(waiting_child(&root)).is_err());
    registry.arm(id).unwrap();
    expect_child_owns_store(&root);
    assert!(registry.arm(id).is_err(), "one-use ARM");
    registry.begin_closing().unwrap();
    registry.begin_closing().unwrap();
    assert!(registry.arm(id).is_err());
    assert!(registry.spawn_unarmed(waiting_child(&root)).is_err());
    assert_eq!(registry.active_children().unwrap(), 1);
    assert_eq!(
        registry.close_and_reap(Duration::from_secs(15)).unwrap(),
        ReapedChildren { count: 1 }
    );
    assert_eq!(registry.active_children().unwrap(), 0);
    let next = StoreLease::acquire(&root).expect("independent OS owner post-reap");
    next.validate_fence().unwrap();
    drop(next);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn racing_spawn_and_close_never_enable_post_close_arm() {
    for _ in 0..8 {
        let root = root("race");
        let registry = Arc::new(WriterProcessRegistry::new(2).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let other = Arc::clone(&registry);
        let gate = Arc::clone(&barrier);
        let child_root = root.clone();
        let attempting = thread::spawn(move || {
            gate.wait();
            other.spawn_unarmed(waiting_child(&child_root))
        });
        barrier.wait();
        registry.begin_closing().unwrap();
        if let Ok(id) = attempting.join().unwrap() {
            assert!(registry.arm(id).is_err());
        }
        let outstanding = registry.active_children().unwrap();
        assert_eq!(
            registry.close_and_reap(Duration::from_secs(15)).unwrap().count,
            outstanding
        );
        assert_eq!(registry.active_children().unwrap(), 0);
        let lease = StoreLease::acquire(&root).unwrap();
        lease.validate_fence().unwrap();
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn never_armed_child_is_killed_and_closed_registry_cannot_reopen() {
    let root = root("never-armed");
    assert!(WriterProcessRegistry::new(0).is_err());
    assert!(WriterProcessRegistry::new(65).is_err());
    let registry = WriterProcessRegistry::new(1).unwrap();
    let id = registry.spawn_unarmed(waiting_child(&root)).unwrap();
    assert_eq!(
        registry.close_and_reap(Duration::from_secs(15)).unwrap(),
        ReapedChildren { count: 1 }
    );
    assert!(registry.arm(id).is_err());
    assert!(registry.spawn_unarmed(waiting_child(&root)).is_err());
    assert_eq!(
        registry.close_and_reap(Duration::from_secs(1)).unwrap(),
        ReapedChildren { count: 0 }
    );
    let lease = StoreLease::acquire(&root).unwrap();
    drop(lease);
    fs::remove_dir_all(root).unwrap();
}
