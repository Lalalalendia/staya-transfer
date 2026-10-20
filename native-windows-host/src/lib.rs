#![deny(unsafe_op_in_unsafe_fn)]
//! Isolated native Win32 process-boundary laboratory (NOT File Gate).
//! The safe Staya custody crate retains #![forbid(unsafe_code)].
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub mod ipc;
#[cfg(not(windows))]
compile_error!("G2-05h3f is Windows-only; no Linux production claim");
