//! G2-05h3d: LAB-only typed actor + registered-child close boundary.
//!
//! The Rust affine owner (not two unrelated public gates) controls both
//! pinned FsStore actor admission and first-party child registry admission.
//! Closing consumes that owner, then requires explicit, successful OS reaping
//! before it will await actual FsStore::shutdown and construct any witness.
//! This is NOT OS child containment, authenticated IPC, production clean
//! cancellation or a File Gate permission. ActiveFsStore's emergency lock
//! retention on cancelled upstream actor startup/shutdown still applies.

use crate::{
    partial_adapter::AcceptedIntoUncommittedFsStore,
    shutdown_supervisor::{ActiveFsStore, ClosingFsStore, QuiescentFsStore},
};
use staya_custody_lab::{
    StoreLease,
    admission::{InflightPermit, Limits},
    child_registry::{ReapedChildren, WriterId, WriterProcessRegistry},
};
use staya_transfer::{ByteRange, recovery::StoreIdentity};
use std::{path::Path, process::Command, sync::atomic::AtomicBool, time::Duration};

/// An affine experimental owner; no raw registry/actor is returned to callers.
pub struct RegisteredActiveFsStore {
    active: ActiveFsStore,
    writers: Box<WriterProcessRegistry>,
}

pub struct RegisteredClosingFsStore {
    closing: ClosingFsStore,
    writers: Box<WriterProcessRegistry>,
    joined: bool,
}

/// Only constructed after the actor shuts down and every child is reaped.
pub struct RegisteredQuiescentFsStore {
    quiescent: QuiescentFsStore,
}

impl RegisteredActiveFsStore {
    pub async fn open(root: &Path, limits: Limits, max_children: usize) -> Result<Self, String> {
        let writers = Box::new(
            WriterProcessRegistry::new(max_children)
                .map_err(|e| format!("create bounded OS child registry: {e}"))?,
        );
        let active = ActiveFsStore::open(root, limits).await?;
        Ok(Self { active, writers })
    }

    /// The child executable MUST be trusted and block before its ARM byte.
    /// Command::spawn alone does not stop an adversarial early writer.
    pub fn spawn_unarmed(&self, command: Command) -> Result<WriterId, String> {
        self.writers
            .spawn_unarmed(command)
            .map_err(|e| format!("register trusted OS child: {e}"))
    }

    pub fn arm(&self, id: WriterId) -> Result<(), String> {
        self.writers
            .arm(id)
            .map_err(|e| format!("ARM registered child: {e}"))
    }

    pub async fn stage(
        &self,
        identity: StoreIdentity,
        range: ByteRange,
        wire: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<(AcceptedIntoUncommittedFsStore, InflightPermit), String> {
        self.active.stage(identity, range, wire, cancelled).await
    }

    /// Consuming the non-Clone owner closes both writer entrypoints.
    /// No caller retains a raw actor or a cloneable child-registry handle.
    pub fn begin_closing(self) -> Result<RegisteredClosingFsStore, (Self, String)> {
        let Self { active, writers } = self;
        if let Err(e) = writers.begin_closing() {
            return Err((
                Self { active, writers },
                format!("child registry HOLD: {e}"),
            ));
        }
        match active.begin_closing() {
            Ok(closing) => Ok(RegisteredClosingFsStore {
                closing,
                writers,
                joined: false,
            }),
            Err((active, error)) => Err((Self { active, writers }, error)),
        }
    }
}

impl RegisteredClosingFsStore {
    /// Real native OS kill + confirmed process exit, bounded and explicit.
    /// Returns no quiescence, fsync, actor shutdown or durable checkpoint.
    pub fn reap_registered_children(
        &mut self,
        timeout: Duration,
    ) -> Result<ReapedChildren, String> {
        let proof = self
            .writers
            .close_and_reap(timeout)
            .map_err(|e| format!("registered writers not all joined: HOLD: {e}"))?;
        self.joined = true;
        Ok(proof)
    }

    /// Child-count alone is insufficient; an explicit successful reaping
    /// call must precede the actor-shutdown witness, even if count is zero.
    pub async fn finish(self) -> Result<RegisteredQuiescentFsStore, (Self, String)> {
        if !self.joined {
            return Err((
                self,
                "registered child close/join not proven: HOLD".to_owned(),
            ));
        }
        match self.writers.active_children() {
            Ok(0) => {}
            Ok(_) => {
                return Err((
                    self,
                    "registered child handles still outstanding: HOLD".to_owned(),
                ));
            }
            Err(e) => {
                return Err((self, format!("cannot inspect child registry: HOLD: {e}")));
            }
        }
        let Self {
            closing,
            writers,
            joined,
        } = self;
        match closing.finish().await {
            Ok(quiescent) => {
                drop(writers);
                Ok(RegisteredQuiescentFsStore { quiescent })
            }
            Err((closing, error)) => Err((
                Self {
                    closing,
                    writers,
                    joined,
                },
                error,
            )),
        }
    }
}

impl RegisteredQuiescentFsStore {
    pub fn owner(&self) -> &StoreLease {
        self.quiescent.owner()
    }

    pub fn admissions_drained(&self) -> Result<bool, String> {
        self.quiescent.admissions_drained()
    }

    /// Ordinary OS handle close. Never unconditional LOCK_UN.
    pub fn finish_clean(self) {
        self.quiescent.finish_clean();
    }
}
