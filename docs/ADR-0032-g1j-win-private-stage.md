# STY-G1j — Native Win32 protected staging DACL (preview)

## Threat model and change

The G1f preview previously created `%TEMP%\staya-direct-preview-*` using inherited Windows ACLs. Random names and parent ACL inheritance cannot establish confidentiality. G1j changes the **Windows-only** private-stage directory creation to native `CreateDirectoryW` with an explicit *protected* DACL, while retaining Unix mode `0700` behavior and the existing direct-only Bao/QUIC protocol.

The isolated `interop/windows_private_stage.rs` FFI boundary obtains the current user token SID and builds an SDDL DACL with only the current user and LocalSystem (both full control, inherited by child files). Creation fails if the path exists, token/descriptor creation fails, or a parent is a non-directory/reparse point. Before announcing `STAGED`, the receiver queries the actual directory/file DACL, requires exactly those two trustees, full-control access and a protected directory DACL. No `icacls` subprocess, post-creation ACL repair, relay or Akula vault/file mutation.

## Evidence required before merging

- Native Windows pinned release/fork two-process sender/receiver, actual Bao root and physical bytes, denied outsider, no other existing workflow failures.
- Windows test inspects the real staged file and protected staging root, including refusing reuse of an existing directory. Strict Windows Rustfmt and Clippy `-D warnings` on exact HEAD.
- Linux release/fork and three-namespace Docker G1g unchanged; no unsafe code enters the core crate or QUIC/Bao transfer path.

## Explicit remaining risks and HOLD

- The Windows test impersonates the distinct **anonymous security principal** on a dedicated OS thread and requires a real `CreateFileW(GENERIC_READ)` attempt to fail with `ERROR_ACCESS_DENIED` (not a missing-file or transport error). A separate ordinary local-user SID and hostile inherited-permission matrix are **still not proven**, so owner-only confidentiality is not cleared for sensitive production use.
- Validating parent names before/after `CreateDirectoryW` does not prevent an attacker with control of an ancestor directory from racing a pathname swap. Handle-relative pinned storage / hostile-race tests remain open.
- Local administrators and privileged processes can override ACLs. NTFS and support for persistent ACLs are assumed; native DACL inspection fails closed when ACL is unavailable.
- This is manual **synthetic-only** staging, not a production secrets/vault path, no signed Device/Vault rights, no durable partial resume or Akula File Gate. Both physical hosts and production clearance remain HOLD.
- Future production implementation should keep this native boundary isolated and add an independent OS account denial test and TOCTOU-free pinned directory/file handles.

Sources: Windows [CreateDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw), [ConvertStringSecurityDescriptorToSecurityDescriptorW](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw), [G1f](https://github.com/Lalalalendia/staya-transfer/pull/43), [G1g](https://github.com/Lalalalendia/staya-transfer/pull/48), [G1j issue](https://github.com/Lalalalendia/staya-transfer/issues/54).
