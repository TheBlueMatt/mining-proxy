use bitcoin::util::hash::Sha256dHash;
use std::cell::UnsafeCell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::marker::Sync;

struct UnsafeObj<T> {
	cell: UnsafeCell<T>
}
impl<T> UnsafeObj<T> {
	fn new(obj: T) -> Self {
		Self{cell: UnsafeCell::new(obj)}
	}
	fn get(&self) -> *mut T {
		self.cell.get()
	}
}
unsafe impl<T> Sync for UnsafeObj<T> {}

/// A highly-specific holder of a few hash-sets of Sha256dHashs indexed by [u8; 32].
/// Used to track submitted shares by client per-prev-block, with lazy cleanup of old entries as we
/// move on to new chain tips, while effeciently getting mutable entries out. Note that clients
/// *must* be serially accessed, though cleaning up old entries can be multi-threaded.
pub struct GenerationalHashSets {
	storage: Mutex<HashMap<[u8; 32], Arc<UnsafeObj<HashSet<Sha256dHash>>>>>,
	/// While we also use access_checker to panic if our mutual-exclusion requirements aren't met,
	/// we have to perform *some* atomic operation to guarantee thread-safety or our writes may
	/// never hit memory prior to the next call on a different thread.
	access_checker: AtomicBool,
	latest_set: UnsafeObj<([u8; 32], Arc<UnsafeObj<HashSet<Sha256dHash>>>)>,
}

impl GenerationalHashSets {
	pub fn new() -> Self {
		Self {
			storage: Mutex::new(HashMap::new()),
			access_checker: AtomicBool::new(false),
			latest_set: UnsafeObj::new(([0; 32], Arc::new(UnsafeObj::new(HashSet::new())))),
		}
	}

	/// May be called in any thread, at any time. Note that wiping may be lazy!
	pub fn wipe_generation(&self, generation: &[u8; 32]) {
		self.storage.lock().unwrap().remove(generation);
	}

	/// Mutual exclusion must happen externally (but can be called on any thread)!
	/// Returns true if insertion succeeded, false if the element was already present
	pub fn try_insert(&self, generation: &[u8; 32], value: Sha256dHash) -> bool {
		if self.access_checker.swap(true, Ordering::AcqRel) {
			panic!("Mutual exclusion fail in GenerationalHashSets try_insert!");
		}

		let same_generation = unsafe { (*self.latest_set.get()).0 == *generation };
		let res = if same_generation {
			let set_ref: &mut HashSet<Sha256dHash> = unsafe { &mut *(*self.latest_set.get()).1.get() };
			(*set_ref).insert(value)
		} else {
			let mut new_set = HashSet::with_capacity(1024);
			new_set.insert(value);
			let set_arc = Arc::new(UnsafeObj::new(new_set));
			self.storage.lock().unwrap().insert(generation.clone(), set_arc.clone());
			let gen_ref: &mut ([u8; 32], Arc<UnsafeObj<HashSet<Sha256dHash>>>) = unsafe { &mut *self.latest_set.get() };
			gen_ref.0 = generation.clone();
			gen_ref.1 = set_arc;
			true
		};

		// Now ensure we flush stores to memory to ensure thread-safety
		self.access_checker.store(false, Ordering::Release);
		res
	}
}
