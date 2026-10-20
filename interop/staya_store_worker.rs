//! G2-05h3g: a disposable, real pinned FsStore writer under OS containment.
//!
//! This executable is a crash laboratory, NOT an installable Staya service.
//! It deliberately has no clean CLOSE, network commands, or File Gate access.
//! After custody begins, unexpected errors abort the whole process, not just
//! its actor. Linux IPC rejection before custody exits without opening a lock.

use iroh_blobs::store::fs::FsStore;
use staya_custody_lab::StoreLease;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process,
    time::Duration,
};

#[cfg(target_os = "linux")]
use staya_native_parent_lab::ipc::receive_parent_arm;

const READY: &str = ".g2-05h3g-fsstore-ready";
// Pin above the Iroh default 16 KiB inline-outboard threshold.
// A smaller object may have NO physical .obao4 by design.
const OBJECT_SIZE: usize = 16 * 1024 * 1024 + 17;

fn payload() -> Vec<u8> {
    (0..OBJECT_SIZE)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect()
}

fn abort_hold(stage: &str, error: impl std::fmt::Display) -> ! {
    eprintln!("STY_G2_05H3G_HOLD stage={stage} error={error}");
    process::abort();
}

fn publish_ready(root: &Path, hash: &[u8; 32]) -> io::Result<()> {
    let pending = root.join(".g2-05h3g-ready-pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(hash)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, root.join(READY))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // No panic unwinding may silently drop StoreLease while a Tokio actor
    // spawned by the pinned upstream FsStore could still be alive.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("STY_G2_05H3G_PANIC_HOLD {info}");
        process::abort();
    }));

    let mut args = env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .unwrap_or_else(|| abort_hold("arguments", "missing private test root")),
    );
    let parent: u32 = args
        .next()
        .unwrap_or_else(|| abort_hold("arguments", "missing parent PID"))
        .to_string_lossy()
        .parse()
        .unwrap_or_else(|e| abort_hold("arguments", e));
    if args.next().is_some() {
        abort_hold("arguments", "unexpected additional input");
    }

    // G2-05h3g2: Linux cannot open StoreLease until the anonymous inherited
    // socket has proven SO_PEERCRED, live parent pidfd, versioned ARM and ACK.
    // This is still not executable attestation or a signed file grant.
    #[cfg(target_os = "linux")]
    let _parent_witness = receive_parent_arm(parent).unwrap_or_else(|error| {
        // No StoreLease, FsStore actor or writable user data exists yet.
        eprintln!("STY_G2_05H3G2_HOLD stage=ipc-before-custody error={error}");
        process::exit(73);
    });
    #[cfg(windows)]
    let _ = parent; // Containment on Windows belongs to the suspended Job launcher.

    let owner = StoreLease::acquire(&root).unwrap_or_else(|e| abort_hold("custody", e));
    owner
        .validate_fence()
        .unwrap_or_else(|e| abort_hold("initial-fence", e));
    let store = FsStore::load(owner.canonical_root())
        .await
        .unwrap_or_else(|e| abort_hold("fsstore-load", e));

    let bytes = payload();
    let expected = blake3::hash(&bytes);
    let tag = store
        .add_slice(&bytes)
        .await
        .unwrap_or_else(|e| abort_hold("fsstore-write", e));
    if tag.hash.as_bytes() != expected.as_bytes() {
        abort_hold(
            "fsstore-hash",
            "upstream hash disagrees with expected bytes",
        );
    }
    owner
        .validate_fence()
        .unwrap_or_else(|e| abort_hold("post-write-fence", e));
    // The test is explicitly a physical .data/.obao4 crash audit. The
    // upstream defaults may inline smaller outboards into the metadata DB,
    // so require real files before publishing this fixture's readiness.
    let hex = expected.to_hex().to_string();
    let data_path = owner
        .canonical_root()
        .join("data")
        .join(format!("{hex}.data"));
    let bao_path = owner
        .canonical_root()
        .join("data")
        .join(format!("{hex}.obao4"));
    if !data_path.is_file() || !bao_path.is_file() {
        abort_hold(
            "physical-sidecars",
            "pinned FsStore did not materialize data+outboard",
        );
    }
    publish_ready(owner.canonical_root(), expected.as_bytes())
        .unwrap_or_else(|e| abort_hold("ready-marker", e));

    // Hold all three authorities until the OS kills this entire process.
    // Process termination is the ONLY release route in this crash experiment.
    let _keep_ownership = (&owner, &store, &tag);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
