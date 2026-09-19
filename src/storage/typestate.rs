use std::marker::PhantomData;

pub(super) enum StreamingState {}
pub(super) enum ValidatedState {}

/// A value carried through a compiler-checked storage phase.
pub(super) struct Phase<State, T = ()>(T, PhantomData<fn() -> State>);

/// A resource currently receiving or producing its complete byte stream.
pub(super) type Streaming<T = ()> = Phase<StreamingState, T>;

/// A resource whose bytes and identity have been checked and may advance to
/// durable publication.
pub(super) type Validated<T = ()> = Phase<ValidatedState, T>;

impl<T> Phase<ValidatedState, T> {
    pub(super) const fn new(value: T) -> Self {
        Self(value, PhantomData)
    }

    pub(super) fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Phase<StreamingState, T> {
    pub(super) const fn new(value: T) -> Self {
        Self(value, PhantomData)
    }

    pub(super) const fn value(&self) -> &T {
        &self.0
    }
}
