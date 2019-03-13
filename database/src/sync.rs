use parking_lot;

pub enum MutexGuard<'a, T> {
    ParkingLot(parking_lot::MutexGuard<'a, T>),
}

impl<'a, T> From<parking_lot::MutexGuard<'a, T>> for MutexGuard<'a, T> {
    fn from(g: parking_lot::MutexGuard<'a, T>) -> Self {
        MutexGuard::ParkingLot(g)
    }
}
