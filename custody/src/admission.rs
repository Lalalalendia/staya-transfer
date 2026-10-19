//! G2-05c: cooperative bounded resource admission for one partial-store owner.
//! This is in-memory accounting, NOT a filesystem quota or a durable checkpoint.
//! No peer can supply a grant; only locally configured bounds admit activity.
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_partial_objects: u32,
    pub max_reserved_bytes: u64,
    pub max_open_handles: u32,
    pub max_retries_per_object: u32,
}

impl Limits {
    pub fn validate(self) -> io::Result<()> {
        if self.max_partial_objects == 0
            || self.max_reserved_bytes == 0
            || self.max_open_handles == 0
            || self.max_retries_per_object > 100
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid store limits",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    objects: u32,
    bytes: u64,
    handles: u32,
}

impl Reservation {
    pub fn new(objects: u32, bytes: u64, handles: u32) -> io::Result<Self> {
        if objects == 0 || bytes == 0 || handles == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty admission request",
            ));
        }
        Ok(Self {
            objects,
            bytes,
            handles,
        })
    }
}

/// Entirely local, bounded reservation ledger. Not shared between processes.
/// The caller must hold the StoreLease and ensure this is the ONLY writer.
#[derive(Debug)]
pub struct Admission {
    limits: Limits,
    used: Reservation,
    // Each release must match a previously admitted *whole* reservation.
    // Without this, releasing fabricated partial resource counts corrupts quotas.
    outstanding: Vec<Reservation>,
}

impl Admission {
    pub fn new(limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            used: Reservation {
                objects: 0,
                bytes: 0,
                handles: 0,
            },
            outstanding: Vec::new(),
        })
    }

    pub fn reserve(&mut self, request: Reservation) -> io::Result<()> {
        let objects = self.used.objects.checked_add(request.objects);
        let bytes = self.used.bytes.checked_add(request.bytes);
        let handles = self.used.handles.checked_add(request.handles);
        match (objects, bytes, handles) {
            (Some(objects), Some(bytes), Some(handles))
                if objects <= self.limits.max_partial_objects
                    && bytes <= self.limits.max_reserved_bytes
                    && handles <= self.limits.max_open_handles =>
            {
                // Bounded by the number of reserved partial-object slots.
                // Allocation failure never increments resource usage.
                self.outstanding.try_reserve(1).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "reservation ledger allocation failed",
                    )
                })?;
                self.outstanding.push(request);
                self.used = Reservation {
                    objects,
                    bytes,
                    handles,
                };
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "reservation limit exceeded",
            )),
        }
    }

    /// A release must match an entire outstanding reservation.
    /// Fabricating a smaller release could otherwise undercount actual usage
    /// and admit too many remote transfers while older handles remain live.
    pub fn release(&mut self, request: Reservation) -> io::Result<()> {
        let index = self
            .outstanding
            .iter()
            .position(|reserved| *reserved == request)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "no matching active reservation")
            })?;
        let objects = self
            .used
            .objects
            .checked_sub(request.objects)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object quota underflow"))?;
        let bytes =
            self.used.bytes.checked_sub(request.bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "byte quota underflow")
            })?;
        let handles = self
            .used
            .handles
            .checked_sub(request.handles)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "handle quota underflow"))?;
        self.outstanding.swap_remove(index);
        self.used = Reservation {
            objects,
            bytes,
            handles,
        };
        Ok(())
    }

    pub fn retry_allowed(&self, failures_so_far: u32) -> bool {
        failures_so_far < self.limits.max_retries_per_object
    }

    pub fn usage(&self) -> (u32, u64, u32) {
        (self.used.objects, self.used.bytes, self.used.handles)
    }
}


/// A process-local, thread-safe logical capacity ledger. Not shared between
/// independent processes, and not a hard limit on FsStore's physical disk use.
/// The cooperative StoreLease must still be held by the caller.
#[derive(Clone, Debug)]
pub struct SharedAdmission {
    inner: std::sync::Arc<std::sync::Mutex<Admission>>,
}

impl SharedAdmission {
    pub fn new(limits: Limits) -> io::Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(Admission::new(limits)?)),
        })
    }

    /// Atomically hold the entire reservation until its unique permit drops.
    /// A poisoned ledger always refuses admission rather than using stale
    /// resource totals. Never hold the mutex across filesystem or async work.
    pub fn reserve(&self, request: Reservation) -> io::Result<InflightPermit> {
        let mut ledger = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("resource ledger poisoned"))?;
        ledger.reserve(request)?;
        Ok(InflightPermit {
            ledger: std::sync::Arc::clone(&self.inner),
            reserved: request,
        })
    }

    pub fn usage(&self) -> io::Result<(u32, u64, u32)> {
        let ledger = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("resource ledger poisoned"))?;
        Ok(ledger.usage())
    }

    pub fn retry_allowed(&self, failures_so_far: u32) -> io::Result<bool> {
        let ledger = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("resource ledger poisoned"))?;
        Ok(ledger.retry_allowed(failures_so_far))
    }
}

/// A non-cloneable in-flight reservation. Drop releases the exact allocation.
/// Unlike the old caller-managed release API, consumers cannot fabricate a
/// partial release and free resources while an import is still admitted.
#[derive(Debug)]
pub struct InflightPermit {
    ledger: std::sync::Arc<std::sync::Mutex<Admission>>,
    reserved: Reservation,
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            // Unexpected ledger corruption must fail conservatively: the
            // accounting remains reserved and future admission is refused.
            let _ = ledger.release(self.reserved);
        }
        // A poisoned lock also remains unusable by SharedAdmission::reserve.
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_partial_objects: 2,
            max_reserved_bytes: 1024,
            max_open_handles: 4,
            max_retries_per_object: 3,
        }
    }

    #[test]
    fn shared_permit_holds_across_other_threads_and_releases_exactly_once() {
        let shared = SharedAdmission::new(limits()).unwrap();
        let req = Reservation::new(2, 1024, 4).unwrap();
        let permit = shared.reserve(req).unwrap();
        assert_eq!(shared.usage().unwrap(), (2, 1024, 4));

        let separate = shared.clone();
        std::thread::spawn(move || {
            assert!(separate.reserve(Reservation::new(1, 1, 1).unwrap()).is_err());
        })
        .join()
        .unwrap();

        assert_eq!(shared.usage().unwrap(), (2, 1024, 4));
        drop(permit);
        assert_eq!(shared.usage().unwrap(), (0, 0, 0));
        let second = shared.reserve(req).unwrap();
        assert_eq!(shared.usage().unwrap(), (2, 1024, 4));
        drop(second);
        assert_eq!(shared.usage().unwrap(), (0, 0, 0));
    }

    #[test]
    fn shared_admission_rejects_overflow_and_cannot_leak_on_scope_exit() {
        let shared = SharedAdmission::new(limits()).unwrap();
        let huge = Reservation::new(u32::MAX, u64::MAX, u32::MAX).unwrap();
        assert!(shared.reserve(huge).is_err());
        assert_eq!(shared.usage().unwrap(), (0, 0, 0));
        {
            let _permit = shared.reserve(Reservation::new(1, 256, 2).unwrap()).unwrap();
            assert_eq!(shared.usage().unwrap(), (1, 256, 2));
        }
        assert_eq!(shared.usage().unwrap(), (0, 0, 0));
        assert!(shared.retry_allowed(2).unwrap());
        assert!(!shared.retry_allowed(3).unwrap());
    }

    #[test]
    fn reservation_limits_and_recovery_after_release() {
        let mut a = Admission::new(limits()).unwrap();
        let req = Reservation::new(1, 512, 2).unwrap();
        a.reserve(req).unwrap();
        a.reserve(req).unwrap();
        assert_eq!(a.usage(), (2, 1024, 4));
        assert!(a.reserve(req).is_err());
        assert_eq!(a.usage(), (2, 1024, 4));
        a.release(req).unwrap();
        assert_eq!(a.usage(), (1, 512, 2));
        a.reserve(req).unwrap();
        assert_eq!(a.usage(), (2, 1024, 4));
    }

    #[test]
    fn failure_is_atomic_and_underflow_denied() {
        let mut a = Admission::new(limits()).unwrap();
        let huge = Reservation::new(u32::MAX, u64::MAX, u32::MAX).unwrap();
        assert!(a.reserve(huge).is_err());
        assert_eq!(a.usage(), (0, 0, 0));
        assert!(a.release(Reservation::new(1, 1, 1).unwrap()).is_err());
        assert_eq!(a.usage(), (0, 0, 0));
    }

    #[test]
    fn retry_policy_and_invalid_settings_fail_closed() {
        let a = Admission::new(limits()).unwrap();
        assert!(a.retry_allowed(0));
        assert!(a.retry_allowed(2));
        assert!(!a.retry_allowed(3));
        assert!(!a.retry_allowed(u32::MAX));
        assert!(
            Admission::new(Limits {
                max_reserved_bytes: 0,
                ..limits()
            })
            .is_err()
        );
        assert!(Reservation::new(0, 1, 1).is_err());
    }

    #[test]
    fn partial_or_fabricated_release_cannot_bypass_resource_quota() {
        let mut admission = Admission::new(limits()).unwrap();
        let held = Reservation::new(1, 512, 2).unwrap();
        admission.reserve(held).unwrap();

        // An attacker or buggy caller cannot release bytes/objects separately.
        assert!(
            admission
                .release(Reservation::new(1, 1, 1).unwrap())
                .is_err()
        );
        assert!(
            admission
                .release(Reservation::new(1, 512, 1).unwrap())
                .is_err()
        );
        assert_eq!(admission.usage(), (1, 512, 2));

        let more = Reservation::new(1, 512, 2).unwrap();
        admission.reserve(more).unwrap();
        assert_eq!(admission.usage(), (2, 1024, 4));
        assert!(admission.reserve(more).is_err());

        admission.release(held).unwrap();
        assert_eq!(admission.usage(), (1, 512, 2));
        admission.release(more).unwrap();
        assert_eq!(admission.usage(), (0, 0, 0));
        assert!(admission.release(held).is_err());
        assert_eq!(admission.usage(), (0, 0, 0));
    }
}
