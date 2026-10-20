//! STY-G2-05h3c: owned registry of trusted child writers (LAB ONLY).
//!
//! One local mutex linearizes spawn/register, one-byte ARM, and closing.
//! The child executable must voluntarily block before ARM. Command::spawn
//! is not OS-suspended or a sandbox. No real FsStore actor, authenticated
//! IPC, kernel parent-death, checkpoint, grant or Akula File Gate is present.

use std::{
    collections::HashMap,
    io::{self, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(10);
const MAX_CHILDREN: usize = 64;
// In-process owner identity: prevents accidental cross-session ARM/reap ID reuse.
// Not a cross-process, cryptographic, or remotely delegated capability.
static NEXT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

fn deny(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

/// Registry-local opaque identifier, not a network credential or grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WriterId {
    registry_id: u64,
    sequence: u64,
}

/// Actual Child handles reaped; NEVER an FsStore-quiescence witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReapedChildren {
    pub count: usize,
}

struct Entry {
    child: Child,
    control: ChildStdin,
    armed: bool,
}

struct State {
    accepting: bool,
    next_id: u64,
    children: HashMap<WriterId, Entry>,
}

/// Only this owner may start/ARM registered children. Use Arc for local races.
pub struct WriterProcessRegistry {
    registry_id: u64,
    max_children: usize,
    state: Mutex<State>,
}

impl WriterProcessRegistry {
    pub fn new(max_children: usize) -> io::Result<Self> {
        if !(1..=MAX_CHILDREN).contains(&max_children) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid writer registry capacity",
            ));
        }
        let registry_id = NEXT_REGISTRY_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("registry owner identity exhausted: HOLD"))?;
        Ok(Self {
            registry_id,
            max_children,
            state: Mutex::new(State {
                accepting: true,
                next_id: 1,
                children: HashMap::new(),
            }),
        })
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("writer registry poisoned: HOLD"))
    }

    /// Must launch a trusted child whose first step is waiting on stdin ARM.
    /// No externally launched PID or untracked Child may be inserted here.
    pub fn spawn_unarmed(&self, mut command: Command) -> io::Result<WriterId> {
        let mut state = self.lock()?;
        if !state.accepting {
            return Err(deny("writer registration already closed"));
        }
        if state.children.len() >= self.max_children {
            return Err(deny("writer process capacity exceeded"));
        }
        state.children.try_reserve(1).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "writer registry allocation")
        })?;
        let next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("writer identifier exhausted: HOLD"))?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        let Some(control) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("missing child ARM control pipe"));
        };
        let id = WriterId {
            registry_id: self.registry_id,
            sequence: state.next_id,
        };
        state.next_id = next_id;
        state.children.insert(
            id,
            Entry {
                child,
                control,
                armed: false,
            },
        );
        Ok(id)
    }

    /// Sends a one-use startup byte, not an authenticated child ACK.
    pub fn arm(&self, id: WriterId) -> io::Result<()> {
        let mut state = self.lock()?;
        if !state.accepting {
            return Err(deny("late ARM after close"));
        }
        let entry = state
            .children
            .get_mut(&id)
            .ok_or_else(|| deny("unknown child identifier"))?;
        if entry.armed {
            return Err(deny("duplicate ARM"));
        }
        if entry.child.try_wait()?.is_some() {
            return Err(deny("child exited before ARM"));
        }
        if let Err(err) = entry
            .control
            .write_all(b"A")
            .and_then(|_| entry.control.flush())
        {
            state.accepting = false;
            return Err(err);
        }
        entry.armed = true;
        Ok(())
    }

    /// One-way and linearizable with spawn_unarmed and arm.
    pub fn begin_closing(&self) -> io::Result<()> {
        self.lock()?.accepting = false;
        Ok(())
    }

    pub fn active_children(&self) -> io::Result<usize> {
        Ok(self.lock()?.children.len())
    }

    /// Hard-kill then positively observe OS exit for every registered child.
    /// A timeout/kill error leaves unobserved processes registered and closed.
    /// This method never unlocks StoreLease or claims a clean FsStore shutdown.
    pub fn close_and_reap(&self, timeout: Duration) -> io::Result<ReapedChildren> {
        let started = Instant::now();
        let mut state = self.lock()?;
        state.accepting = false;
        let count = state.children.len();
        for entry in state.children.values_mut() {
            if entry.child.try_wait()?.is_none()
                && let Err(err) = entry.child.kill()
                && entry.child.try_wait()?.is_none()
            {
                return Err(err);
            }
        }
        loop {
            let mut done = Vec::new();
            for (&id, entry) in &mut state.children {
                if entry.child.try_wait()?.is_some() {
                    done.push(id);
                }
            }
            for id in done {
                state.children.remove(&id);
            }
            if state.children.is_empty() {
                return Ok(ReapedChildren { count });
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "registered child still alive: HOLD",
                ));
            }
            thread::sleep(POLL);
        }
    }
}

impl Drop for WriterProcessRegistry {
    fn drop(&mut self) {
        // Emergency kill only: Drop must NEVER supply clean-reap evidence.
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        for entry in state.children.values_mut() {
            if matches!(entry.child.try_wait(), Ok(None)) {
                let _ = entry.child.kill();
            }
        }
    }
}
