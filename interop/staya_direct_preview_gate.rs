//! STY-G1f: actual two OS-process, direct-only Iroh transfer with one
//! authorized receiver and one denied outsider. No File Gate and no APPLIED.
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WAIT: Duration = Duration::from_secs(45);

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capture(child: &mut Child) -> Receiver<String> {
    let stdout = child.stdout.take().expect("child stdout pipe");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn next_line(lines: &Receiver<String>) -> String {
    lines
        .recv_timeout(WAIT)
        .expect("child did not announce bounded protocol line")
}

fn exited(child: &mut Child) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("query real child exit") {
            return status;
        }
        assert!(start.elapsed() < WAIT, "real preview child timed out");
        thread::sleep(Duration::from_millis(30));
    }
}

fn new_receiver() -> (OwnedProcess, Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
        .arg("receive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("real receiver OS process");
    let lines = capture(&mut child);
    (OwnedProcess(child), lines)
}

#[test]
fn one_manual_direct_file_two_os_processes_and_unlisted_peer_denied() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture_root =
        std::env::temp_dir().join(format!("staya-g1f-{}-{nonce}", std::process::id()));
    fs::create_dir(&fixture_root).unwrap();
    let file = fixture_root.join("explicit-source.bin");
    let payload: Vec<u8> = (0..(1024 * 1024 + 17))
        .map(|index| ((index * 43 + 17) % 251) as u8)
        .collect();
    fs::write(&file, &payload).unwrap();
    let expected_hash = blake3::hash(&payload).to_hex().to_string();

    let (mut permitted, permitted_lines) = new_receiver();
    let allowed_id = next_line(&permitted_lines)
        .strip_prefix("PEER_ID ")
        .expect("bounded manually authorized receiver identifier")
        .to_owned();
    assert!(!allowed_id.is_empty());

    let mut provider = OwnedProcess(
        Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
            .arg("serve")
            .arg(&file)
            .arg(&allowed_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("real provider OS process"),
    );
    let provider_lines = capture(&mut provider.0);
    let invitation = next_line(&provider_lines);
    let invitation_fields: Vec<_> = invitation.split_whitespace().collect();
    assert_eq!(invitation_fields.len(), 4);
    assert_eq!(invitation_fields[0], "CONNECT");
    assert_eq!(invitation_fields[2], expected_hash);
    assert_eq!(invitation_fields[3], payload.len().to_string());

    // Unknown peer really connects to the same running Iroh provider. Its
    // certificate identity must be rejected before any object can be staged.
    let (mut unknown, unknown_lines) = new_receiver();
    let unknown_id = next_line(&unknown_lines);
    assert_ne!(unknown_id, format!("PEER_ID {allowed_id}"));
    unknown
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(invitation.as_bytes())
        .unwrap();
    unknown.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(unknown.0.stdin.take());
    let outsider_status = exited(&mut unknown.0);
    assert!(
        !outsider_status.success(),
        "unlisted peer got private Bao content"
    );
    assert!(unknown_lines.try_iter().all(|l| !l.starts_with("STAGED ")));

    // The single explicitly allowed peer now receives the same object.
    permitted
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(invitation.as_bytes())
        .unwrap();
    permitted
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    drop(permitted.0.stdin.take());
    let report = next_line(&permitted_lines);
    assert!(
        report.starts_with("STAGED "),
        "receiver did not stage: {report}"
    );
    assert!(
        report.contains("NOT_APPLIED=true"),
        "private preview claimed File Gate authority"
    );
    assert!(report.contains(&format!("ROOT={expected_hash}")));
    let staged_path = report
        .strip_prefix("STAGED ")
        .unwrap()
        .split(" ROOT=")
        .next()
        .unwrap();
    let staged = PathBuf::from(staged_path);
    let staging_root = staged
        .parent()
        .expect("private staging parent")
        .to_path_buf();
    assert!(staging_root.starts_with(std::env::temp_dir()));
    assert!(
        staging_root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("staya-direct-preview-receiver-")
    );
    assert_eq!(fs::read(&staged).unwrap(), payload);
    assert!(
        exited(&mut permitted.0).success(),
        "receiver OS process did not finish"
    );

    // EOF on the operator's private control pipe closes the provider.
    drop(provider.0.stdin.take());
    assert!(
        exited(&mut provider.0).success(),
        "provider did not exit on session close"
    );
    fs::remove_dir_all(&staging_root).expect("delete only owned random private receiver staging");
    fs::remove_dir_all(&fixture_root).expect("delete only own disposable test source");

    if let Some(out) = std::env::var_os("STY_G1F_OUTPUT_DIR") {
        let dir = PathBuf::from(out);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("inventory.txt"), format!(
            "source_blake3={expected_hash}\nobject_size={}\nseparate_os_processes=true\nunknown_peer_denied=true\nroot_anchored_bao=true\nphysical_readback=true\nstaging_only=true\nakula_file_gate=false\napplied=false\n",
            payload.len()
        )).unwrap();
        fs::write(dir.join("received.bin"), &payload).unwrap();
    }
    println!(
        "STY_G1F separate_sender_receiver=true QUIC=true root_verified=true unauthorized_denied=true staging_only=true"
    );
}
