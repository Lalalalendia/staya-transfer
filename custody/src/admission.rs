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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid store limits"));
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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty admission request"));
        }
        Ok(Self { objects, bytes, handles })
    }
}

/// Entirely local, bounded reservation ledger. Not shared between processes.
/// The caller must hold the StoreLease and ensure this is the ONLY writer.
#[derive(Debug)]
pub struct Admission {
    limits: Limits,
    used: Reservation,
}

impl Admission {
    pub fn new(limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            used: Reservation { objects: 0, bytes: 0, handles: 0 },
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
                self.used = Reservation { objects, bytes, handles };
                Ok(())
            }
            _ => Err(io::Error::new(io::ErrorKind::OutOfMemory, "reservation limit exceeded")),
        }
    }

    /// Release exactly previously reserved capacity, with no underflow.
    pub fn release(&mut self, request: Reservation) -> io::Result<()> {
        let objects = self.used.objects.checked_sub(request.objects);
        let bytes = self.used.bytes.checked_sub(request.bytes);
        let handles = self.used.handles.checked_sub(request.handles);
        match (objects, bytes, handles) {
            (Some(objects), Some(bytes), Some(handles)) => {
                self.used = Reservation { objects, bytes, handles };
                Ok(())
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "reservation underflow")),
        }
    }

    pub fn retry_allowed(&self, failures_so_far: u32) -> bool {
        failures_so_far < self.limits.max_retries_per_object
    }

    pub fn usage(&self) -> (u32, u64, u32) {
        (self.used.objects, self.used.bytes, self.used.handles)
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
        assert!(Admission::new(Limits { max_reserved_bytes: 0, ..limits() }).is_err());
        assert!(Reservation::new(0, 1, 1).is_err());
    }
}
