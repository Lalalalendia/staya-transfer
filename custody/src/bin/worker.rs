//! A separate OS process used to verify real file-lock ownership semantics.
use staya_custody_lab::StoreLease;
use std::{
    env,
    io::{self, Read, Write},
    process,
};

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("mode: hold or probe");
    let root = args.next().expect("private local store path");
    assert!(args.next().is_none(), "unexpected input");

    // Linux-only diagnostic: parent deliberately passes its flock's open file
    // description as stdin. Do not open another StoreLease in this worker.
    // The inherited descriptor stays alive until this process is killed.
    #[cfg(target_os = "linux")]
    if mode == "hold-inherited-fd" {
        println!("INHERITED_FD_READY");
        io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }

    let guard = match StoreLease::acquire(&root) {
        Ok(guard) => guard,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            println!("BUSY");
            io::stdout().flush().unwrap();
            return;
        }
        Err(err) => {
            eprintln!("CUSTODY_ERROR={err:?}");
            process::exit(3);
        }
    };
    guard.validate_fence().expect("fresh lease identity");
    println!("ACQUIRED");
    io::stdout().flush().unwrap();

    match mode.as_str() {
        "hold" => {
            let mut buf = [0u8; 1];
            // Wait for parent to kill the process; an EOF also ends custody.
            let _ = io::stdin().read(&mut buf);
        }
        "probe" => {}
        "checkpoint-publish" => {
            use staya_custody_lab::checkpoint::{
                CheckpointClaim, IROH_PREORDER_16K, publish_candidate,
            };
            let claim = CheckpointClaim {
                sequence: 1,
                content_root: [0x42; 32],
                object_len: 1_048_593,
                bao_profile: IROH_PREORDER_16K,
                start: 0,
                end: 16_384,
            };
            // The lab parent kills this process *inside* publish_candidate,
            // not after a graceful Drop or after returning a metadata ACK.
            let barrier = publish_candidate(&guard, claim).expect("lab checkpoint publication");
            println!("METADATA_ONLY={barrier:?}");
        }
        "checkpoint-read" => {
            // Metadata readback from another real OS process is still only
            // a claim inventory, NEVER independently verified Bao bytes.
            let claims = staya_custody_lab::checkpoint::read_candidates(
                &guard,
                [0x42; 32],
                1_048_593,
                staya_custody_lab::checkpoint::IROH_PREORDER_16K,
            )
            .expect("independent checkpoint candidate read");
            println!("CANDIDATES={}", claims.len());
        }
        _ => process::exit(4),
    }
}
