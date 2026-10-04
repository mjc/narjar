//! Thread-local allocation accounting, enabled only around the measured operation.
//! Timings run separately with accounting disabled. No production allocator changes.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Allocations {
    pub calls: usize,
    pub bytes: usize,
    pub peak_bytes: usize,
    live_bytes: isize,
}

thread_local! {
    static COUNTS: Cell<Option<Allocations>> = const { Cell::new(None) };
}

pub struct CountingAllocator;

fn record_allocation(allocated: usize, released: usize) {
    let _ = COUNTS.try_with(|counts| {
        if let Some(mut value) = counts.get() {
            value.calls += usize::from(allocated != 0);
            value.bytes += allocated;
            value.live_bytes += allocated as isize - released as isize;
            value.peak_bytes = value.peak_bytes.max(value.live_bytes.max(0) as usize);
            counts.set(Some(value));
        }
    });
}

// SAFETY: All allocations and deallocations are delegated unchanged to System.
// Accounting uses only nonallocating, constant-initialized thread-local Cells;
// no pointer is dereferenced, retained, or shared by the instrumentation.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the allocation layout required by GlobalAlloc.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size(), 0);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: System receives the caller's unchanged valid allocation layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size(), 0);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller supplies a live System allocation and its original layout.
        unsafe { System.dealloc(pointer, layout) };
        record_allocation(0, layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The caller supplies a live allocation, its layout and a valid new size.
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            record_allocation(size, layout.size());
        }
        replacement
    }
}

struct Measurement;

impl Drop for Measurement {
    fn drop(&mut self) {
        COUNTS.set(None);
    }
}

pub fn measure<T>(operation: impl FnOnce() -> T) -> (T, Allocations) {
    assert!(
        COUNTS.get().is_none(),
        "allocation measurements cannot nest"
    );
    COUNTS.set(Some(Allocations::default()));
    let measurement = Measurement;
    let result = operation();
    let counts = COUNTS.get().expect("measurement remains active");
    drop(measurement);
    (result, counts)
}
