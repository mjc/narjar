/// A resource whose bytes and identity have been checked and may advance to
/// durable publication.
pub(super) struct Validated<T = ()>(T);

impl<T> Validated<T> {
    pub(super) const fn new(value: T) -> Self {
        Self(value)
    }

    pub(super) fn into_inner(self) -> T {
        self.0
    }
}

/// A resource currently receiving or producing its complete byte stream.
pub(super) struct Streaming<T = ()>(T);

impl<T> Streaming<T> {
    pub(super) const fn new(value: T) -> Self {
        Self(value)
    }

    pub(super) const fn value(&self) -> &T {
        &self.0
    }
}
