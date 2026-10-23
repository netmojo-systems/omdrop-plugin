//! What `safeplist::parse` allocates on a hostile binary plist, measured with
//! a counting allocator. One test in this binary, so no other thread's
//! allocations are counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use omdrop_identity::safeplist::{PlistError, parse};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed through.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed through.
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The most `parse(data)` holds at once beyond what was held before it.
fn peak_during_parse(data: &[u8]) -> (Result<plist::Value, PlistError>, usize) {
    let before = CURRENT.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let result = parse(data);
    (result, PEAK.load(Ordering::SeqCst) - before)
}

/// 34 nested arrays, each declaring `n` two-byte references whose list runs
/// on over the arrays after it and a shared region of references to object
/// 300. The `plist` reader allocates each array's whole reference list before
/// descending into its first member. hume's probe of the Python decoders,
/// ported.
fn nested_overlapping_arrays(n: u32) -> Vec<u8> {
    let mut body = b"bplist00".to_vec();
    let mut offsets: Vec<u32> = Vec::new();
    for i in 0..34u16 {
        offsets.push(body.len() as u32);
        body.extend([0xaf, 0x12]);
        body.extend(n.to_be_bytes());
        body.extend((i + 1).to_be_bytes());
    }
    let scalar = body.len() as u32;
    body.push(0x00);
    for _ in 0..n {
        body.extend(300u16.to_be_bytes());
    }
    offsets.resize(301, scalar);
    let table = body.len() as u64;
    body.extend(offsets.iter().flat_map(|o| o.to_be_bytes()));
    body.extend([0u8; 6]);
    body.extend([4u8, 2]);
    body.extend(301u64.to_be_bytes());
    body.extend(0u64.to_be_bytes());
    body.extend(table.to_be_bytes());
    body
}

/// One array, the root, declaring `len` one-byte references in a few bytes.
fn array_claiming(len: u64) -> Vec<u8> {
    let mut body = b"bplist00".to_vec();
    body.extend([0xaf, 0x13]);
    body.extend(len.to_be_bytes());
    let table = body.len() as u64;
    body.push(8);
    body.extend([0u8; 6]);
    body.extend([1u8, 1]);
    body.extend(1u64.to_be_bytes());
    body.extend(0u64.to_be_bytes());
    body.extend(table.to_be_bytes());
    body
}

#[test]
fn a_hostile_binary_plist_cannot_make_the_reader_allocate_more_than_its_size() {
    // Before the walk in safeplist::check_binary, 120 KB here held 33 lists
    // of 60 000 eight-byte references, about 16 MB, before MAX_DEPTH
    // stopped it; the peak grew with the input.
    for n in [5_000u32, 60_000] {
        let data = nested_overlapping_arrays(n);
        let (result, peak) = peak_during_parse(&data);
        assert_eq!(result, Err(PlistError::TooComplex), "n = {n}");
        assert!(
            peak <= data.len().max(64 << 10),
            "n = {n}: {} input bytes held {peak} bytes",
            data.len()
        );
    }
    // A declared count larger than the input is refused before anything is
    // allocated for it.
    for len in [1u64 << 40, u64::MAX, 300_000] {
        let data = array_claiming(len);
        assert!(data.len() < 64);
        let (result, peak) = peak_during_parse(&data);
        assert!(result.is_err(), "{len}");
        assert!(peak < 64 << 10, "{len}: held {peak} bytes");
    }
}
