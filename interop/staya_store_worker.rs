//! G2-05h3g: a disposable, real pinned FsStore writer under OS containment.
//!
//! This executable is a crash laboratory, NOT an installable Staya service.
//! It deliberately has no clean CLOSE, network commands, or File Gate access.
//! Every unexpected error aborts the whole process before unlocking custody.

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
use staya_native_parent_lab::linux::bind_actual_parent;

const READY: &str = ".g2-05h3g-fsstore-ready";
const OBJECT_SIZE: usize = 256 * 1024 + 17;

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

    // The Linux launcher installed PR_SET_PDEATHSIG before exec, and worker
    // checks a pidfd before opening FsStore. This still does NOT prove a
    // non-forgeable original-parent identity on all kernels.
    #[cfg(target_os = "linux")]
    let _parent_witness =
        bind_actual_parent(parent).unwrap_or_else(|e| abort_hold("parent-binding", e));
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
        abort_hold("fsstore-hash", "upstream hash disagrees with expected bytes");
    }
    owner
        .validate_fence()
        .unwrap_or_else(|e| abort_hold("post-write-fence", e));
    publish_ready(owner.canonical_root(), expected.as_bytes())
        .unwrap_or_else(|e| abort_hold("ready-marker", e));

    // Hold all three authorities until the OS kills this entire process.
    // Process termination is the ONLY release route in this crash experiment.
    let _keep_ownership = (&owner, &store, &tag);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
