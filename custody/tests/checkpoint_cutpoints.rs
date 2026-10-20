//! STY-G2-06g1: real Linux SIGKILL during checkpoint metadata publication.
//! No recovered journal, even a fully synced one, authorizes a verified range.
#![cfg(all(target_os = "linux", feature = "g2-cutpoint-lab"))]

use staya_custody_lab::{
    StoreLease,
    checkpoint::{CheckpointClaim, IROH_PREORDER_16K, read_candidates},
    partial_barrier::reaudit_untrusted_candidate_backings,
};
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ROOT: [u8; 32] = [0x42; 32];
const SIZE: u64 = 1_048_593;

fn claim() -> CheckpointClaim {
    CheckpointClaim {
        sequence: 1,
        content_root: ROOT,
        object_len: SIZE,
        bao_profile: IROH_PREORDER_16K,
        start: 0,
        end: 16_384,
    }
}

fn private_case(stage: &str) -> (PathBuf, PathBuf, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "staya-g2-06g1-{}-{stage}-{nonce}",
        std::process::id()
    ));
    let store = base.join("partial");
    let marker = base.join("reached-cutpoint");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&store).unwrap();
    (base, store, marker)
}

#[test]
fn actual_sigkill_at_checkpoint_publication_cuts_never_authorizes_skip() {
    let stages = [
        ("record-written", 0usize),
        ("record-synced", 0),
        ("renamed", 1),
        ("directory-synced", 1),
        ("pre-ack", 1),
    ];
    for (stage, expected_candidates) in stages {
        let (base, store, marker) = private_case(stage);
        let mut child = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
            .arg("checkpoint-publish")
            .arg(&store)
            .env("STY_G2_06G_LAB_CHILD", "1")
            .env("STY_G2_06G_CUT", stage)
            .env("STY_G2_06G_MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("independent real publisher process");
        let started = Instant::now();
        while !marker.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "publisher exited before {stage}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(25),
                "publisher never reached cut-point {stage}"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read(&marker).unwrap(), stage.as_bytes());
        child.kill().expect("real OS SIGKILL, not a cooperative shutdown");
        let killed = child.wait_with_output().unwrap();
        assert_eq!(
            killed.status.signal(),
            Some(9),
            "child must die by SIGKILL at {stage}; stderr={}",
            String::from_utf8_lossy(&killed.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&killed.stdout).contains("METADATA_ONLY"),
            "no publication ACK can be emitted before process death"
        );

        // The custody and metadata classification MUST be checked by a
        // different OS process, not by the killed actor or its original fd.
        let reopened = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
            .arg("checkpoint-read")
            .arg(&store)
            .output()
            .expect("independent OS checkpoint reader");
        assert!(
            reopened.status.success(),
            "reopen after {stage}: {}",
            String::from_utf8_lossy(&reopened.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&reopened.stdout).trim(),
            format!("ACQUIRED\nCANDIDATES={expected_candidates}")
        );

        let owner = StoreLease::acquire(&store).expect("SIGKILL must release custody");
        let candidates = read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap();
        assert_eq!(candidates.len(), expected_candidates);
        // This fixture has NO physical FsStore data/outboard. Even a valid
        // renamed and directory-synced metadata candidate is NOT Bao proof.
        assert!(
            reaudit_untrusted_candidate_backings(&owner, claim(), |_| Ok(())).is_err(),
            "unverified journal must never become a reusable byte range"
        );
        drop(owner);
        fs::remove_dir_all(base).unwrap();
        println!(
            "STY_G2_06G1 stage={stage} os_sigkill=9 candidates={expected_candidates} physically_verified=false unauthorized_skip=false"
        );
    }
}
