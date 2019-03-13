use std::fs::File;
use std::io;
use std::path::Path;

use fs2::FileExt;
use parking_lot;

pub enum MutexGuard<'a, T> {
    ParkingLot(parking_lot::MutexGuard<'a, T>),
    Flock(FlockMutexGuard<'a>),
}

impl<'a, T> From<parking_lot::MutexGuard<'a, T>> for MutexGuard<'a, T> {
    fn from(g: parking_lot::MutexGuard<'a, T>) -> Self {
        MutexGuard::ParkingLot(g)
    }
}

impl<'a> From<FlockMutexGuard<'a>> for MutexGuard<'a, ()> {
    fn from(g: FlockMutexGuard<'a>) -> Self {
        MutexGuard::Flock(g)
    }
}

/// A minimalistic flock-based mutex.
///
/// This just barely implements enough what we need from a mutex.
pub struct FlockMutex {
    f: File,
}

impl FlockMutex {
    pub fn new<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        Ok(Self {
            f: File::open(p)?
        })
    }

    pub fn lock(&self) -> FlockMutexGuard {
        while let Err(e) = self.f.lock_exclusive() {
            // According to flock(2), possible errors returned are:
            //
            //   EBADF  fd is not an open file descriptor.
            //
            //   EINTR  While  waiting  to acquire a lock, the call
            //          was interrupted by delivery of a signal
            //          caught by a handler; see signal(7).
            //
            //   EINVAL operation is invalid.
            //
            //   ENOLCK The kernel ran out of memory for allocating
            //          lock records.
            //
            //   EWOULDBLOCK
            //          The file is locked and the LOCK_NB flag was
            //          selected.
            //
            // We entrust Rust's type system with keeping the file
            // handle valid, therefore flock should not fail with
            // EBADF.  We use only valid operations, we don't use
            // LOCK_NB, and we don't handle resource exhaustion.
            //
            // Therefore, only EINTR needs to be handled, which we do
            // by retrying.
            assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        }

        FlockMutexGuard {
            m: &self,
        }
    }
}

pub struct FlockMutexGuard<'a> {
    m: &'a FlockMutex,
}

impl<'a> Drop for FlockMutexGuard<'a> {
    fn drop(&mut self) {
        while let Err(e) = self.m.f.unlock() {
            // See above.
            assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        }
    }
}
