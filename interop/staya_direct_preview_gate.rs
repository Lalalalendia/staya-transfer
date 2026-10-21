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

#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "windows_private_stage.rs"]
mod windows_private_stage;

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

fn new_receiver(lab_drop: bool) -> (OwnedProcess, Receiver<String>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"));
    command.arg("receive");
    if lab_drop {
        command.arg("--lab-drop-after-first-range");
    }
    let mut child = command
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
    run_manual_preview(false);
}

#[test]
fn manual_preview_reconnects_real_quic_after_forced_close() {
    run_manual_preview(true);
}

fn run_manual_preview(lab_drop: bool) {
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

    let (mut permitted, permitted_lines) = new_receiver(lab_drop);
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
    let (mut unknown, unknown_lines) = new_receiver(false);
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
    assert!(
        report.contains(&format!("RECONNECTS={}", if lab_drop { 1 } else { 0 })),
        "real QUIC reconnect was not observed or was unexpectedly retried: {report}"
    );
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&staging_root).unwrap().permissions().mode() & 0o777,
            0o700,
            "real staged file must not be in a group/world-readable directory"
        );
    }
    assert_eq!(fs::read(&staged).unwrap(), payload);
    #[cfg(windows)]
    {
        windows_private_stage::verify_owner_only_staging_root(&staging_root)
            .expect("Windows private root has explicit protected owner/System DACL");
        windows_private_stage::verify_owner_only_staged_file(&staged)
            .expect("Windows stage file inherited no broad user/group access");
        windows_private_stage::prove_anonymous_file_read_denied(&staged)
            .expect("different Windows anonymous principal must get ACCESS_DENIED");
        println!("STY_G1J_ANONYMOUS_DATA_READ_DENIED=true");
        assert!(
            windows_private_stage::create_owner_only_directory(&staging_root).is_err(),
            "existing path must never be reused or have its DACL widened"
        );
    }
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

    if !lab_drop && let Some(out) = std::env::var_os("STY_G1F_OUTPUT_DIR") {
        let dir = PathBuf::from(out);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("inventory.txt"), format!(
            "source_blake3={expected_hash}\nobject_size={}\nseparate_os_processes=true\nunknown_peer_denied=true\nroot_anchored_bao=true\nphysical_readback=true\nstaging_only=true\nakula_file_gate=false\napplied=false\n",
            payload.len()
        )).unwrap();
        fs::write(dir.join("received.bin"), &payload).unwrap();
    }
    println!(
        "STY_G1F separate_sender_receiver=true QUIC=true root_verified=true unauthorized_denied=true staging_only=true forced_reconnect={lab_drop}"
    );
}

#[test]
fn three_explicit_files_real_quic_serial_queue_with_physical_readback() {
    use staya_transfer::{
        ContentId, Manifest,
        queue::{ItemOutcome, QueuePhase, QueueSelection, SelectedFile},
    };

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!("staya-g1k-{}-{nonce}", std::process::id()));
    fs::create_dir(&fixture).expect("owned synthetic queue fixture");
    let payloads = [
        vec![0x13],
        (0..64 * 1024)
            .map(|i| ((i * 19 + 11) % 251) as u8)
            .collect(),
        (0..1024 * 1024 + 17)
            .map(|i| ((i * 43 + 17) % 251) as u8)
            .collect(),
    ];
    let selected: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, bytes)| SelectedFile {
            label: format!("item-{:04}.bin", i + 1),
            manifest: Manifest {
                id: ContentId(*blake3::hash(bytes).as_bytes()),
                size: bytes.len() as u64,
            },
        })
        .collect();
    let plan = QueueSelection::new(selected.clone()).expect("bounded trusted local selection");
    assert_eq!(plan.entries().len(), 3);
    let commit = plan.commitment();
    let mut queue = plan.into_cursor();
    let mut inventory = format!("local_selection={}\n", hex_digest(&commit));

    for (i, bytes) in payloads.iter().enumerate() {
        assert_eq!(queue.current_index(), i);
        assert_eq!(queue.current().unwrap().manifest, selected[i].manifest);
        let source = fixture.join(format!("selected-{i:03}.bin"));
        fs::write(&source, bytes).expect("selected local-only synthetic source");

        // Every item uses a real, independent OS sender and receiver,
        // manually authenticated peer and immutable root, not a mock wire.
        let (mut permitted, permitted_lines) = new_receiver(false);
        let allowed = next_line(&permitted_lines)
            .strip_prefix("PEER_ID ")
            .expect("receiver announces ephemeral identity")
            .to_owned();

        let mut sender = OwnedProcess(
            Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
                .arg("serve")
                .arg(&source)
                .arg(&allowed)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("real selected object provider"),
        );
        let announced = capture(&mut sender.0);
        let invitation = next_line(&announced);
        let parts: Vec<_> = invitation.split_whitespace().collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "CONNECT");
        assert_eq!(parts[2], blake3::hash(bytes).to_hex().as_str());
        assert_eq!(parts[3], bytes.len().to_string());

        // A different peer with the same invitation must not obtain data.
        if i != 1 {
            let (mut outsider, outsider_lines) = new_receiver(false);
            let outsider_id = next_line(&outsider_lines);
            assert_ne!(outsider_id, format!("PEER_ID {allowed}"));
            outsider
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(invitation.as_bytes())
                .unwrap();
            outsider.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
            drop(outsider.0.stdin.take());
            assert!(
                !exited(&mut outsider.0).success(),
                "unlisted peer got queue item {i}"
            );
            assert!(outsider_lines.try_iter().all(|s| !s.starts_with("STAGED ")));
        }

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
            "queue item {i} failed: {report}"
        );
        assert!(report.contains("NOT_APPLIED=true"));
        assert!(report.contains(&format!("ROOT={}", parts[2])));
        let destination = PathBuf::from(
            report
                .strip_prefix("STAGED ")
                .unwrap()
                .split(" ROOT=")
                .next()
                .unwrap(),
        );
        let private = destination
            .parent()
            .expect("private staging root")
            .to_path_buf();
        assert!(private.starts_with(std::env::temp_dir()));
        assert!(
            private
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("staya-direct-preview-receiver-")
        );
        let readback = fs::read(&destination).expect("real staged bytes on disk");
        assert_eq!(
            readback, *bytes,
            "independent physical queue item {i} mismatch"
        );
        assert!(exited(&mut permitted.0).success());

        // Only an exact local root/length can advance the queue; not STAGED
        // stdout and never a network-provided filename or APPLIED flag.
        queue
            .record_verified_staging(selected[i].manifest, &readback)
            .expect("actual staged bytes match locally selected manifest");
        assert_eq!(queue.outcomes()[i], ItemOutcome::VerifiedStaged);
        inventory.push_str(&format!(
            "item={i} bytes={} blake3={} staged_and_reaudited=true\n",
            readback.len(),
            blake3::hash(&readback).to_hex()
        ));

        if let Some(out) = std::env::var_os("STY_G1K_OUTPUT_DIR") {
            let out = PathBuf::from(out);
            fs::create_dir_all(&out).unwrap();
            fs::write(out.join(format!("selected-{i:03}.bin")), &readback).unwrap();
        }
        drop(sender.0.stdin.take());
        assert!(
            exited(&mut sender.0).success(),
            "provider should close cleanly"
        );
        fs::remove_dir_all(private).expect("delete only own random private staging");
    }
    assert_eq!(queue.phase(), QueuePhase::Complete);
    assert!(
        queue
            .outcomes()
            .iter()
            .all(|s| *s == ItemOutcome::VerifiedStaged)
    );
    if let Some(out) = std::env::var_os("STY_G1K_OUTPUT_DIR") {
        fs::write(PathBuf::from(out).join("inventory.txt"), inventory).unwrap();
    }
    fs::remove_dir_all(fixture).expect("remove disposable local queue fixture");
    println!(
        "STY_G1K_REAL_QUIC sessions=3 authorized_only=true \
         ordered_roots=true cold_staged_bytes=true no_file_gate=true"
    );
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
fn new_batch_receiver(probe_unlisted: bool) -> (OwnedProcess, Receiver<String>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"));
    cmd.arg("receive-batch");
    if probe_unlisted {
        cmd.arg("--lab-request-unlisted");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("real one-session batch receiver OS process");
    let received = capture(&mut child);
    (OwnedProcess(child), received)
}

#[test]
fn one_provider_one_receiver_one_quic_connection_serves_exact_selected_set() {
    use staya_transfer::{
        ContentId, Manifest,
        queue::{ItemOutcome, QueuePhase, QueueSelection, SelectedFile},
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture =
        std::env::temp_dir().join(format!("staya-g1k-single-{}-{nonce}", std::process::id()));
    fs::create_dir(&fixture).expect("disposable local selected sources");
    let payloads = [
        vec![0x33],
        (0..64 * 1024)
            .map(|i| ((i * 31 + 29) % 251) as u8)
            .collect(),
        (0..1024 * 1024 + 17)
            .map(|i| ((i * 43 + 7) % 251) as u8)
            .collect(),
    ];
    let mut paths = Vec::new();
    let mut entries = Vec::new();
    for (i, bytes) in payloads.iter().enumerate() {
        let label = format!("batch-{i:03}.bin");
        let path = fixture.join(&label);
        fs::write(&path, bytes).expect("write locally selected synthetic file");
        entries.push(SelectedFile {
            label,
            manifest: Manifest {
                id: ContentId(*blake3::hash(bytes).as_bytes()),
                size: bytes.len() as u64,
            },
        });
        paths.push(path);
    }
    let selection = QueueSelection::new(entries.clone()).unwrap();
    let commit = selection.commitment();
    let mut queue = selection.into_cursor();

    let (mut receiver, receiver_lines) = new_batch_receiver(true);
    let receiver_id = next_line(&receiver_lines)
        .strip_prefix("PEER_ID ")
        .expect("batch receiver announces one ephemeral ID")
        .to_owned();
    let mut provider_cmd = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"));
    provider_cmd
        .arg("serve-batch")
        .arg(&receiver_id)
        .args(&paths)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut provider = OwnedProcess(provider_cmd.spawn().expect("real batch provider process"));
    let provider_lines = capture(&mut provider.0);
    let invitation = next_line(&provider_lines);
    let parts: Vec<_> = invitation.split_whitespace().collect();
    assert_eq!(parts[0], "CONNECT_BATCH");
    assert_eq!(parts.len(), 4 + 3 * 3);
    assert_eq!(parts[2], hex_digest(&commit));
    assert_eq!(parts[3], "3");
    for i in 0..3 {
        let pos = 4 + i * 3;
        assert_eq!(parts[pos], entries[i].label);
        assert_eq!(parts[pos + 1], blake3::hash(&payloads[i]).to_hex().as_str());
        assert_eq!(parts[pos + 2], payloads[i].len().to_string());
    }

    let (mut unlisted, outsider_lines) = new_batch_receiver(false);
    let other_id = next_line(&outsider_lines)
        .strip_prefix("PEER_ID ")
        .expect("outsider must announce own identity")
        .to_owned();
    assert_ne!(receiver_id, other_id);
    unlisted
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(invitation.as_bytes())
        .unwrap();
    unlisted.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(unlisted.0.stdin.take());
    assert!(
        !exited(&mut unlisted.0).success(),
        "non-listed peer accepted"
    );
    assert!(
        !outsider_lines
            .try_iter()
            .any(|s| s.starts_with("STAGED_QUEUE "))
    );

    receiver
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(invitation.as_bytes())
        .unwrap();
    receiver.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(receiver.0.stdin.take());
    let mut inventory = format!("selection={}\n", hex_digest(&commit));
    let mut stage_roots = Vec::new();
    for (i, bytes) in payloads.iter().enumerate() {
        let report = next_line(&receiver_lines);
        assert!(
            report.starts_with(&format!("STAGED_QUEUE {i} ")),
            "{report}"
        );
        assert!(report.contains(&format!("ROOT={}", blake3::hash(bytes).to_hex())));
        assert!(report.contains(&format!("SIZE={}", bytes.len())));
        assert!(report.contains("NOT_APPLIED=true"));
        let verified_bytes: usize = payloads[..=i].iter().map(Vec::len).sum();
        let selected_bytes: usize = payloads.iter().map(Vec::len).sum();
        assert!(
            report.contains(&format!("VERIFIED_ITEMS={}/{}", i + 1, payloads.len())),
            "unverified item count must never be reported as complete: {report}"
        );
        assert!(
            report.contains(&format!("VERIFIED_BYTES={verified_bytes}/{selected_bytes}")),
            "batch progress must reflect exact local root-verified bytes: {report}"
        );
        let expected_phase = if i + 1 == payloads.len() {
            "Complete"
        } else {
            "Running"
        };
        assert!(report.contains(&format!("PHASE={expected_phase}")));
        let stage = PathBuf::from(
            report
                .strip_prefix(&format!("STAGED_QUEUE {i} "))
                .unwrap()
                .split(" ROOT=")
                .next()
                .unwrap(),
        );
        let private_root = stage.parent().unwrap().to_path_buf();
        assert!(private_root.starts_with(std::env::temp_dir()));
        assert!(
            private_root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("staya-direct-preview-batch-receiver-")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&private_root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        #[cfg(windows)]
        {
            windows_private_stage::verify_owner_only_staging_root(&private_root).unwrap();
            windows_private_stage::verify_owner_only_staged_file(&stage).unwrap();
            windows_private_stage::prove_anonymous_file_read_denied(&stage).unwrap();
        }
        let actual = fs::read(&stage).expect("independently open real staged file");
        assert_eq!(actual, *bytes);
        queue
            .record_verified_staging(entries[i].manifest, &actual)
            .expect("batch stage matches locally pinned root");
        assert_eq!(queue.outcomes()[i], ItemOutcome::VerifiedStaged);
        inventory.push_str(&format!(
            "item={i} size={} blake3={} verified=true\n",
            bytes.len(),
            blake3::hash(&actual).to_hex()
        ));
        if let Some(out) = std::env::var_os("STY_G1K_SINGLE_OUTPUT_DIR") {
            let dir = PathBuf::from(out);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("verified-{i:03}.bin")), &actual).unwrap();
        }
        stage_roots.push(private_root);
    }
    assert_eq!(
        next_line(&receiver_lines),
        "STY_G1K_UNLISTED_GET_DENIED=true"
    );
    let final_line = next_line(&receiver_lines);
    assert!(
        final_line.starts_with("QUEUE_COMPLETE COUNT=3 COMMITMENT="),
        "{final_line}"
    );
    assert!(final_line.contains(&hex_digest(&commit)));
    assert!(final_line.contains("NOT_APPLIED=true"));
    let final_bytes: usize = payloads.iter().map(Vec::len).sum();
    assert!(final_line.contains("VERIFIED_ITEMS=3/3"));
    assert!(final_line.contains(&format!("VERIFIED_BYTES={final_bytes}/{final_bytes}")));
    assert!(final_line.contains("PHASE=Complete"));
    assert!(
        final_line.contains("RECONNECTS=0"),
        "one physical QUIC connection was not proven: {final_line}"
    );
    assert!(exited(&mut receiver.0).success());
    assert_eq!(queue.phase(), QueuePhase::Complete);
    if let Some(out) = std::env::var_os("STY_G1K_SINGLE_OUTPUT_DIR") {
        fs::write(PathBuf::from(out).join("inventory.txt"), inventory).unwrap();
    }
    drop(provider.0.stdin.take());
    assert!(exited(&mut provider.0).success());
    for dir in stage_roots {
        fs::remove_dir_all(dir).expect("cleanup generated private staged object");
    }
    fs::remove_dir_all(fixture).expect("cleanup locally generated source corpus");
    println!(
        "STY_G1K_SINGLE_SESSION provider=1 receiver=1 direct_quic=true objects=3 unlisted_peer_denied=true unlisted_hash_denied=true full_bao=true no_file_gate=true"
    );
}

#[test]
fn batch_source_over_size_fails_before_invitation_or_peer_parsing() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-oversize-selected-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let selected = root.join("too-large.bin");
    fs::write(&selected, vec![0x44; 8 * 1024 * 1024 + 1]).unwrap();

    let (mut receiver, lines) = new_receiver(false);
    let identity = next_line(&lines)
        .strip_prefix("PEER_ID ")
        .expect("real receiver must announce a valid identity")
        .to_owned();
    for operation in ["serve", "serve-batch"] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"));
        process.arg(operation);
        if operation == "serve" {
            process.arg(&selected).arg(&identity);
        } else {
            process.arg(&identity).arg(&selected);
        }
        let result = process
            .output()
            .expect("source rejected by real child OS process");
        assert!(
            !result.status.success(),
            "{operation} unexpectedly accepted oversized file"
        );
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("<=8 MiB"),
            "{operation} failed for unrelated reason: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty(), "no invitation may be announced");
    }
    drop(receiver.0.stdin.take());
    let _ = exited(&mut receiver.0);
    fs::remove_dir_all(root).unwrap();
}


/// G1m-b1: a real provider/receiver pair sends a blob larger than the
/// original 8MiB preview ceiling, without reading the whole source/stage
/// into a Vec. Only generated synthetic bytes; no user file/Sync privileges.
#[test]
fn real_large_direct_quic_uses_bounded_source_and_cold_staging() {
    use std::io::Read;
    const SIZE: u64 = 8 * 1024 * 1024 + 17;
    const BUF: usize = 64 * 1024;
    const LARGE_WAIT: Duration = Duration::from_secs(180);

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let base = std::env::temp_dir().join(format!(
        "staya-g1m-quic-source-{}-{nonce}", std::process::id()
    ));
    fs::create_dir(&base).expect("new disposable source fixture");
    let path = base.join("synthetic-large.bin");
    let mut created = fs::OpenOptions::new()
        .write(true).create_new(true).open(&path)
        .expect("create synthetic 8MiB+17 source");
    let mut expected = blake3::Hasher::new();
    let full_chunk: Vec<u8> = (0..BUF).map(|i| (i.wrapping_mul(37) % 251) as u8).collect();
    let mut left = SIZE;
    while left > 0 {
        let n = (left as usize).min(BUF);
        created.write_all(&full_chunk[..n]).expect("write bounded synthetic input");
        expected.update(&full_chunk[..n]);
        left -= n as u64;
    }
    created.sync_all().unwrap();
    drop(created);
    let expected_root = expected.finalize().to_hex().to_string();

    let mut receiver = OwnedProcess(
        Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
            .arg("receive-large")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("independent QUIC large receiver process"),
    );
    let receiver_lines = capture(&mut receiver.0);
    let allowed = receiver_lines.recv_timeout(LARGE_WAIT)
        .expect("large receiver must announce PEER_ID");
    let allowed = allowed.strip_prefix("PEER_ID ")
        .expect("large receiver ephemeral identity").to_owned();
    let mut sender = OwnedProcess(
        Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
            .arg("serve-large").arg(&path).arg(&allowed)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("independent QUIC large sender process"),
    );
    let sender_lines = capture(&mut sender.0);
    let invitation = sender_lines.recv_timeout(LARGE_WAIT)
        .expect("bounded spool/import must announce CONNECT");
    let parts: Vec<_> = invitation.split_whitespace().collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "CONNECT");
    assert_eq!(parts[2], expected_root);
    assert_eq!(parts[3], SIZE.to_string());

    // The same approved ticket never permits a different real QUIC identity.
    let mut stranger = OwnedProcess(
        Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
            .arg("receive-large")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn().unwrap(),
    );
    let stranger_lines = capture(&mut stranger.0);
    let stranger_id = stranger_lines.recv_timeout(LARGE_WAIT).unwrap();
    assert_ne!(stranger_id, format!("PEER_ID {allowed}"));
    stranger.0.stdin.as_mut().unwrap().write_all(invitation.as_bytes()).unwrap();
    stranger.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(stranger.0.stdin.take());
    let outsider_code = await_large_exit(&mut stranger.0, LARGE_WAIT);
    assert!(!outsider_code.success(), "unlisted large-file recipient read selected content");
    assert!(stranger_lines.try_iter().all(|s| !s.starts_with("STAGED ")));

    receiver.0.stdin.as_mut().unwrap().write_all(invitation.as_bytes()).unwrap();
    receiver.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(receiver.0.stdin.take());
    let report = receiver_lines.recv_timeout(LARGE_WAIT).expect("real 8MiB+17 receiver stage");
    assert!(report.starts_with("STAGED "), "{report}");
    assert!(report.contains(&format!("ROOT={expected_root}")));
    assert!(report.contains(&format!("SIZE={SIZE}")));
    assert!(report.contains("NOT_APPLIED=true"));
    let staged = PathBuf::from(
        report.strip_prefix("STAGED ").unwrap().split(" ROOT=").next().unwrap()
    );
    let private = staged.parent().unwrap().to_path_buf();
    assert!(private.file_name().unwrap().to_string_lossy().starts_with(
        "staya-direct-preview-receiver-"
    ));
    assert_eq!(staged.file_name().unwrap(), "large-verified-staged.bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&private).unwrap().permissions().mode() & 0o777, 0o700);
    }
    #[cfg(windows)]
    {
        windows_private_stage::verify_owner_only_staging_root(&private).unwrap();
        windows_private_stage::verify_owner_only_staged_file(&staged).unwrap();
        windows_private_stage::prove_anonymous_file_read_denied(&staged).unwrap();
    }
    let actual_len = fs::metadata(&staged).unwrap().len();
    assert_eq!(actual_len, SIZE);
    // Independent third File handle: 64KiB readback, never a full-file Vec.
    let mut actual = fs::File::open(&staged).unwrap();
    let mut readback_root = blake3::Hasher::new();
    let mut buf = [0u8; BUF];
    let mut count = 0u64;
    loop {
        let n = actual.read(&mut buf).unwrap();
        if n == 0 { break; }
        readback_root.update(&buf[..n]);
        count += n as u64;
    }
    assert_eq!(count, SIZE);
    assert_eq!(readback_root.finalize().to_hex().to_string(), expected_root);
    assert!(await_large_exit(&mut receiver.0, LARGE_WAIT).success());
    if let Some(folder) = std::env::var_os("STY_G1M_LARGE_OUTPUT_DIR") {
        let output = PathBuf::from(folder);
        fs::create_dir_all(&output).unwrap();
        fs::copy(&staged, output.join("large-verified.bin")).unwrap();
        fs::write(output.join("inventory.txt"), format!(
            "size={SIZE}\nroot={expected_root}\nverified=true\nnot_applied=true\n",
        )).unwrap();
    }
    drop(sender.0.stdin.take());
    assert!(await_large_exit(&mut sender.0, LARGE_WAIT).success());
    fs::remove_dir_all(private).unwrap();
    fs::remove_dir_all(base).unwrap();
    println!("STY_G1M_REAL_LARGE_QUIC bytes={SIZE} unauthorized_peer_denied=true physical_bao_audited=true bounded_receiver=true not_applied=true");
}

fn await_large_exit(process: &mut Child, limit: Duration) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(result) = process.try_wait().expect("query large preview child") {
            return result;
        }
        assert!(start.elapsed() < limit, "large QUIC sender/receiver process timed out");
        thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn large_sender_rejects_beyond_16_mib_before_announcing_ticket() {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-g1m-reject-{}-{nonce}", std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let too_large = root.join("over-limit.bin");
    let file = fs::OpenOptions::new().write(true).create_new(true).open(&too_large).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    drop(file);
    let result = Command::new(env!("CARGO_BIN_EXE_staya-direct-preview"))
        .arg("serve-large")
        .arg(&too_large)
        .arg("not-an-endpoint-id")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty(), "oversized file may not get a CONNECT ticket");
    assert!(String::from_utf8_lossy(&result.stderr).contains("<=16 MiB"));
    fs::remove_dir_all(root).unwrap();
}
