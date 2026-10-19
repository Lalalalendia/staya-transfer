//! STY-G2-05h2: pinned, real FsStore actor-shutdown witness (LAB ONLY).
//!
//! A drained resource ledger is not proof of an actor shutdown. This wrapper
//! retains OS custody across real FsStore::shutdown(), and constructs the
//! QuiescentFsStore witness ONLY after the actor returns success and the
//! same physical store fencing checks still succeed.
//!
//! The clean handoff intentionally relies on dropping the OS File lock:
//! it NEVER issues LOCK_UN. Under unrelated fork/exec contention the next
//! nonblocking acquisition may legitimately return WouldBlock. This code does
//! not guarantee timely reacquisition, adversarial pathname safety, or
//! power-loss durability. It is not used by Akula's production File Gate.

use crate::partial_adapter::{AcceptedIntoUncommittedFsStore, stage_with_inflight_budget};
use iroh_blobs::store::fs::FsStore;
use staya_custody_lab::{
    StoreLease,
    admission::{InflightPermit, Limits, SharedAdmission},
};
use staya_transfer::{ByteRange, recovery::StoreIdentity};
use std::{path::Path, sync::atomic::AtomicBool};

/// FsStore::load starts its own actor initialization on a spawned Tokio
/// runtime *before* the load future resolves. Cancelling that await can detach
/// the actor initialization while an ordinary local StoreLease would Drop and
/// unlock too early. Hold OS custody through that entire await.
struct OpeningFsStore {
    owner: Option<StoreLease>,
}

impl Drop for OpeningFsStore {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // Error/cancellation during upstream actor start: there is no
            // reliable actor handle available to await or abort. Fail closed
            // rather than admitting another writer during detached init.
            // LAB ONLY: the process must exit to reclaim this lease.
            eprintln!("STY_G2_05H2_ABANDONED_OPEN custody_retained_until_exit=true");
            std::mem::forget(owner);
        }
    }
}

#[cfg(test)]
pub fn simulate_cancelled_open_for_test(root: &Path) -> Result<(), String> {
    let owner = StoreLease::acquire(root).map_err(|e| format!("test opening lease: {e}"))?;
    let opening = OpeningFsStore { owner: Some(owner) };
    drop(opening);
    Ok(())
}

/// Only this wrapper receives the owned FsStore instance and OS custody.
/// Neither the actor nor the exclusive lock is exposed to an import caller.
pub struct ActiveFsStore {
    // Option permits a clean, proof-carrying transition to Quiescent without
    // allowing an unexpected Drop to close custody while the actor may live.
    owner: Option<StoreLease>,
    actor: Option<FsStore>,
    admissions: SharedAdmission,
}

impl Drop for ActiveFsStore {
    fn drop(&mut self) {
        // A cancelled async shutdown, panic or accidental early session Drop
        // must NOT give another cooperative process the same store while the
        // pinned actor could still be running. Keep OS custody until process
        // exit rather than releasing it without a successful shutdown.
        //
        // Intentional fail-closed resource leak, experimental only. Production
        // must add a supervised abort/join path to eventually reclaim it.
        if self.actor.is_some() {
            if let Some(owner) = self.owner.take() {
                eprintln!("STY_G2_05H2_ABANDONED_ACTIVE_ACTOR custody_retained_until_exit=true");
                std::mem::forget(owner);
            }
        }
    }
}

pub struct ClosingFsStore {
    active: ActiveFsStore,
}

/// The constructor is private to this module. There is no boolean flag,
/// caller-supplied token, or journal record that can manufacture this witness.
pub struct QuiescentFsStore {
    owner: StoreLease,
    admissions: SharedAdmission,
}

impl ActiveFsStore {
    pub async fn open(root: &Path, limits: Limits) -> Result<Self, String> {
        let owner = StoreLease::acquire(root).map_err(|e| format!("exclusive OS custody: {e}"))?;
        owner
            .validate_fence()
            .map_err(|e| format!("initial physical custody: {e}"))?;
        let admissions = SharedAdmission::new(limits)
            .map_err(|e| format!("create bounded admission ledger: {e}"))?;
        // The owner is kept alive while the actor loads and for its entire
        // lifetime. If load fails, no actor has been returned to the caller.
        // If this future is cancelled during the upstream spawn/await,
        // OpeningFsStore::drop MUST retain custody until process exit.
        // ActiveFsStore::drop alone cannot protect a not-yet-built object.
        let mut opening = OpeningFsStore { owner: Some(owner) };
        let actor = FsStore::load(
            opening.owner.as_ref().expect("opening custody invariant").canonical_root(),
        )
        .await
        .map_err(|e| format!("load real pinned FsStore: {e}"))?;
        let owner = opening.owner.take().expect("opening custody invariant");
        Ok(Self {
            owner: Some(owner),
            actor: Some(actor),
            admissions,
        })
    }

    /// Real Bao verification/import. The returned non-cloneable permit must
    /// remain owned by its caller until that import is fully accounted for.
    /// Successful staging never grants checkpoint or file-write authority.
    pub async fn stage(
        &self,
        expected: StoreIdentity,
        range: ByteRange,
        wire: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<(AcceptedIntoUncommittedFsStore, InflightPermit), String> {
        stage_with_inflight_budget(
            self.owner.as_ref().expect("active custody invariant"),
            &self.admissions,
            self.actor.as_ref().expect("active FsStore invariant"),
            expected,
            range,
            wire,
            cancelled,
        )
        .await
    }

    /// Closing is irreversible and linearizable against reserve() calls,
    /// including calls through a previously cloned admission ledger.
    pub fn begin_closing(self) -> Result<ClosingFsStore, (Self, String)> {
        if let Err(err) = self.admissions.stop_admissions() {
            return Err((self, format!("cannot close admissions: {err}")));
        }
        Ok(ClosingFsStore { active: self })
    }
}

impl ClosingFsStore {
    /// This is a diagnostic view of the closing gate, NOT the raw actor.
    /// Returned clones remain closed and cannot admit new work.
    pub fn admissions(&self) -> &SharedAdmission {
        &self.active.admissions
    }

    /// A failed drain, failed real actor shutdown or changed physical
    /// identity returns the STILL-OWNED session in Closing state. Nothing
    /// can produce a QuiescentFsStore witness on those paths.
    pub async fn finish(self) -> Result<QuiescentFsStore, (Self, String)> {
        match self.active.admissions.admissions_drained() {
            Ok(true) => {}
            Ok(false) => {
                return Err((self, "existing import permits have not drained".into()));
            }
            Err(err) => {
                return Err((self, format!("cannot confirm drained permits: {err}")));
            }
        }
        if let Err(err) = self
            .active
            .owner
            .as_ref()
            .expect("active custody invariant")
            .validate_fence()
        {
            return Err((
                self,
                format!("physical custody changed before actor shutdown: {err}"),
            ));
        }
        if let Err(err) = self
            .active
            .actor
            .as_ref()
            .expect("active FsStore invariant")
            .shutdown()
            .await
        {
            return Err((self, format!("real pinned FsStore shutdown failed: {err}")));
        }
        if let Err(err) = self
            .active
            .owner
            .as_ref()
            .expect("active custody invariant")
            .validate_fence()
        {
            return Err((
                self,
                format!("physical custody changed after actor shutdown: {err}"),
            ));
        }

        let ClosingFsStore { mut active } = self;
        let actor = active.actor.take().expect("shutdown actor invariant");
        drop(actor);
        let owner = active.owner.take().expect("shutdown custody invariant");
        let admissions = active.admissions.clone();
        Ok(QuiescentFsStore { owner, admissions })
    }
}

impl QuiescentFsStore {
    /// Physical Bao readback and checkpoint candidate inspection still
    /// require exclusive custody. No range is verified merely by reaching
    /// the actor-shutdown witness.
    pub fn owner(&self) -> &StoreLease {
        &self.owner
    }

    pub fn admissions_drained(&self) -> Result<bool, String> {
        self.admissions
            .admissions_drained()
            .map_err(|e| format!("closing ledger readback: {e}"))
    }

    /// Clean close uses normal OS file-handle lifetime semantics, NOT
    /// explicit LOCK_UN. No new writer is authorized until it independently
    /// acquires real OS custody. A transient WouldBlock must be surfaced.
    ///
    /// This LAB contains no child-writer registration. Future G2-05h stages
    /// must join registered child writers before allowing explicit unlock.
    pub fn finish_clean(self) {
        drop(self);
    }
}
