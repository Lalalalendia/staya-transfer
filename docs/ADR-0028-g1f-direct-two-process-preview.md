# ADR-0028 — STY-G1f manual direct-only two-process file preview

Implements a **runnable** (not just mock) console preview for the narrow P2P path using pinned release/fork iroh-blobs, the existing Staya Bao verifier, existing OS StoreLease and existing bounded staging adapter. See [STY G2 release hold #23](https://github.com/Lalalalendia/staya-transfer/issues/23) and [STY master plan](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd).

## Two-terminal usage (same host or a directly reachable private LAN; relay OFF)

Build the release variant:
\`cargo build --locked --manifest-path interop/release/Cargo.toml --bin staya-direct-preview\`.
First, on the intended receiver, run \`staya-direct-preview receive\`. It prints an ephemeral \`PEER_ID <id>\` and waits. On the sender run \`staya-direct-preview serve <local-file> <that-receiver-id>\`. It prints exactly one \`CONNECT <encoded-direct-endpoint-addr> <object-BLAKE3> <object-size>\` line. Independently confirm that this code and the root/size came from the **intended sender**, then paste it as one line in the waiting receiver terminal. The sender stays alive until the operator presses Enter or closes its stdin.

The source must be one explicit nonempty regular file at most 8 MiB; no directory enumeration, symlink, or peer-selected filenames. Server provider policy denies any QUIC peer ID other than the manually admitted ephemeral receiver, any GET hash except the chosen BLAKE3 root, GET_MANY, PUSH, and observe. Only direct Iroh QUIC works: relay disabled, therefore NAT/IPv4 routing may prevent connections. This is not a universal two-device connectivity claim.

On Unix the random staging directory is created with explicitly enforced mode `0700`; the independent subprocess test inspects its actual resulting mode. On Windows the temporary directory inherits the user's configured `TEMP` ACL, which is **not independently hardened or proven against local attackers** in this manual preview. The preview is not suitable for sensitive user files until Windows ACL isolation and hostile filesystem races have separate acceptance.

Receiver retains its ephemeral private key **only in memory**, uses the manually trusted one-shot CONNECT line as the endpoint address and immutable root/size, makes 64 KiB bounded QUIC GETs, checks independent Bao against the trusted root before every import, and stages to a random temporary \`FsStore\` held by an exclusive OS lease and bounded per-range admission. After actor shutdown it independently re-reads every physical data+outboard Bao group and rechecks the complete BLAKE3; only then it creates \`verified-staged.bin\` inside its private random temporary directory with \`create_new\` and syncs the file. It prints \`NOT_APPLIED=true\`.

## Acceptance and limitations

The interop integration test starts **real separate sender and receiver OS processes** on both pinned Iroh versions, plus a third outsider OS process which must fail to receive the explicitly authorized object. It compares final verified stage bytes and a normalized inventory between release/fork. No test-supplied grants, received file paths, peer bitmap or journal may grant Akula File Gate authority. Strict rustfmt/Clippy and exact-head Rust/Windows/Iroh CI required.

This is a manual PREVIEW, not installed Akula, a production File Gate writer, a hardened file-system sandbox, a signed DeviceId/VaultId policy, resumable durable receipt, offline revocation, Windows power-loss guarantee, relay, or an S3 substitute. The manual CONNECT line itself is a trusted out-of-band user action; if pasted from an attacker, it has no secure independent attestation. The staged copy is NOT a durable \`APPLIED\` file. **Do not connect it to the Akula vault, auto-publish, or declare STY-G2-06 complete.** The CLI is in interop crates only, and must not be included in product installers without separate security acceptance.
