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
        _ => process::exit(4),
    }
}
