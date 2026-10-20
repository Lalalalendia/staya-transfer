#![deny(unsafe_op_in_unsafe_fn)]
//! Linux-only native parent-liveness experiment. NOT a production supervisor.
//!
//! OS syscalls are deliberately isolated from the safe custody crate,
//! which retains #![forbid(unsafe_code)]. This module proves real process
//! exit in tests but does not own a pinned FsStore, StoreLease, or File Gate.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod ipc;

#[cfg(not(target_os = "linux"))]
compile_error!("STY-G2-05h3e is a Linux-only native OS laboratory; no Windows claim");
