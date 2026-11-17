//! Memory a run can do without.
//!
//! A cache (a store held in memory instead of read page by page, objects
//! kept decoded) is paid for from the run's ledger like everything else. It
//! makes a run faster and nothing depends on it, so it is the first thing
//! given back when the ledger cannot pay for something the run does need:
//! the ledger then asks the caches of the thread that made the request to
//! give themselves up, the one used longest ago first and one at a time,
//! until there is room. Without this a cache that was granted early held
//! its memory to the end of the run, and a volume of 500,000 files was
//! refused a reservation with 2.5 GB of caches beside it.
//!
//! Because a cache can be taken back, it can be granted whenever there is
//! room. That matters most where memory is short: a store that was refused
//! a place in memory is read through pages of megabytes, and a lookup in it
//! then costs milliseconds; a volume of 200,000 files spent 50 minutes of
//! one phase that way on a machine with 8 GB.
//!
//! The caches of a run are owned by the thread that drives it and are not
//! shared between threads, so the registry is the thread's own. A request
//! that fails on another thread gives up nothing; such a request is for
//! doing more at once, and its refusal is the ordinary end of a batch.
use std::cell::{Ref, RefCell, RefMut};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// How often caches were given up in this process, for the run's report.
static GIVEN_UP: AtomicU64 = AtomicU64::new(0);
static GIVEN_UP_LAST: AtomicU64 = AtomicU64::new(0);

/// How many caches were given up.
pub fn times_given_up() -> u64 {
    GIVEN_UP.load(Relaxed)
}

/// A cache that can be given up.
pub trait Evict {
    /// Give the cache up, and what it reserved with it. Returns whether
    /// anything was given up. Must not fail, and must leave a cache that is
    /// in use at this moment alone.
    fn evict(&self) -> bool;
    /// When the cache was last used, on the thread's clock ([`now`]): the
    /// one used longest ago is given up first.
    fn last_used(&self) -> u64;
}

/// The thread's clock of cache uses: a number that only grows. A cache
/// notes it at every use.
pub fn now() -> u64 {
    CLOCK.with(|clock| {
        let next = clock.get() + 1;
        clock.set(next);
        next
    })
}

thread_local! {
    static CLOCK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static CACHES: RefCell<Vec<Weak<dyn Evict>>> = const { RefCell::new(Vec::new()) };
    static PAYERS: RefCell<Vec<Rc<dyn CachePayer>>> = const { RefCell::new(Vec::new()) };
    static LAST_RESORTS: RefCell<Vec<Weak<dyn Evict>>> = const { RefCell::new(Vec::new()) };
}

/// Make `holder` one of those asked by [`give_up_last_resort`]: something
/// the run needs and holds in memory, which it can also keep in working
/// storage at a price (the rows of a walk). It is not a cache: no cache's
/// request takes its memory, and it is asked only when a reservation the
/// run cannot do without has no room after every cache was given up.
pub fn register_last_resort<C: Evict + 'static>(holder: &Rc<C>) {
    let holder: Weak<dyn Evict> = Rc::downgrade(&(Rc::clone(holder) as Rc<dyn Evict>));
    LAST_RESORTS.with(|holders| {
        let mut holders = holders.borrow_mut();
        holders.retain(|holder| holder.strong_count() != 0);
        holders.push(holder);
    });
}

/// Ask what was registered with [`register_last_resort`] on this thread to
/// move to working storage, the one used longest ago first. Returns whether
/// one did.
pub fn give_up_last_resort() -> bool {
    let mut holders: Vec<Rc<dyn Evict>> = LAST_RESORTS.with(|holders| {
        let mut holders = holders.borrow_mut();
        holders.retain(|holder| holder.strong_count() != 0);
        holders.iter().filter_map(Weak::upgrade).collect()
    });
    holders.sort_by_key(|holder| holder.last_used());
    for holder in holders {
        if holder.evict() {
            GIVEN_UP_LAST.fetch_add(1, Relaxed);
            return true;
        }
    }
    false
}

/// How often something moved to working storage as a last resort.
pub fn times_last_resort() -> u64 {
    GIVEN_UP_LAST.load(Relaxed)
}

/// A ledger that pays for a cache decided on where no ledger is at hand: a
/// page reader that finds itself read at random holds its file in memory
/// from then on, and used to do so without a reservation, up to a gigabyte
/// a reader.
pub trait CachePayer {
    /// The ledger's limit, or `None` once the ledger is gone.
    fn limit(&self) -> Option<u64>;
    /// A reservation for a cache of `bytes`, or `None` when the ledger has
    /// no room for a cache.
    fn pay(&self, bytes: u64) -> Option<Box<dyn std::any::Any>>;
}

/// What [`pay_for_cache`] found.
pub enum CachePayment {
    /// Reserved: the cache holds this for as long as it lives.
    Paid(Box<dyn std::any::Any>),
    /// The thread's ledger has no room for a cache.
    Refused,
    /// The thread has no ledger (a tool, a test).
    NoLedger,
}

/// Make `payer` a ledger of this thread. It is forgotten once its limit is
/// `None`.
pub fn register_cache_payer(payer: Rc<dyn CachePayer>) {
    PAYERS.with(|payers| {
        let mut payers = payers.borrow_mut();
        payers.retain(|payer| payer.limit().is_some());
        payers.push(payer);
    });
}

/// Ask the thread's ledger (the largest, where a run has several) to pay
/// for a cache of `bytes`.
pub fn pay_for_cache(bytes: u64) -> CachePayment {
    let payer = PAYERS.with(|payers| {
        let mut payers = payers.borrow_mut();
        payers.retain(|payer| payer.limit().is_some());
        payers.iter().max_by_key(|payer| payer.limit()).cloned()
    });
    match payer {
        None => CachePayment::NoLedger,
        Some(payer) => match payer.pay(bytes) {
            Some(paid) => CachePayment::Paid(paid),
            None => CachePayment::Refused,
        },
    }
}

/// Make `cache` one of those [`evict_all`] gives up. It is forgotten when
/// its last owner drops it.
pub fn register<C: Evict + 'static>(cache: &Rc<C>) {
    let cache: Weak<dyn Evict> = Rc::downgrade(&(Rc::clone(cache) as Rc<dyn Evict>));
    CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        // The list is tidied as it doubles, so it stays within twice the
        // caches that are alive.
        if caches.len() >= 16 && caches.len().is_power_of_two() {
            caches.retain(|cache| cache.strong_count() != 0);
        }
        caches.push(cache);
    });
}

/// The caches of this thread that are alive, the one used longest ago
/// first. They are called outside the registry's borrow: giving one up
/// drops what it owns, which may register or drop others.
fn by_last_use() -> Vec<Rc<dyn Evict>> {
    let mut caches: Vec<Rc<dyn Evict>> = CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        caches.retain(|cache| cache.strong_count() != 0);
        caches.iter().filter_map(Weak::upgrade).collect()
    });
    caches.sort_by_key(|cache| cache.last_used());
    caches
}

/// Give up the cache of this thread that was used longest ago, among those
/// that hold something and are not in use at this moment. Returns whether
/// one was given up.
pub fn evict_oldest() -> bool {
    for cache in by_last_use() {
        if cache.evict() {
            GIVEN_UP.fetch_add(1, Relaxed);
            return true;
        }
    }
    false
}

/// Give up every cache of this thread that is not in use at this moment.
/// Returns whether any of them gave something up.
pub fn evict_all() -> bool {
    let mut any = false;
    for cache in by_last_use() {
        if cache.evict() {
            GIVEN_UP.fetch_add(1, Relaxed);
            any = true;
        }
    }
    any
}

/// A value kept only while the ledger has room for it: the cache and the
/// reservation that pays for it, together. Every use asks for it again and
/// does without when it is gone.
pub struct Evictable<T: 'static>(Rc<Slot<T>>);
struct Slot<T> {
    value: RefCell<Option<T>>,
    used: std::cell::Cell<u64>,
}

impl<T> Evict for Slot<T> {
    fn evict(&self) -> bool {
        // A value that is borrowed is in use and stays. The value is
        // dropped after the borrow has ended: its reservation is returned
        // then, and whatever that touches is free to borrow this slot.
        let taken = match self.value.try_borrow_mut() {
            Ok(mut slot) => slot.take(),
            Err(_) => None,
        };
        taken.is_some()
    }
    fn last_used(&self) -> u64 {
        self.used.get()
    }
}

/// One more owner of the same value: it is given up for all of them at
/// once.
impl<T: 'static> Clone for Evictable<T> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

/// A way back to a value that does not keep it alive.
pub struct WeakEvictable<T: 'static>(Weak<Slot<T>>);
impl<T: 'static> WeakEvictable<T> {
    /// The value's slot, while an owner still has it and it has not been
    /// given up.
    pub fn upgrade(&self) -> Option<Evictable<T>> {
        let shared = Evictable(self.0.upgrade()?);
        shared.is_held().then_some(shared)
    }
}

impl<T: 'static> Evictable<T> {
    pub fn downgrade(&self) -> WeakEvictable<T> {
        WeakEvictable(Rc::downgrade(&self.0))
    }
    pub fn new(value: T) -> Self {
        let slot = Rc::new(Slot {
            value: RefCell::new(Some(value)),
            used: std::cell::Cell::new(now()),
        });
        register(&slot);
        Self(slot)
    }
    /// The value, unless it was given up. It cannot be given up while the
    /// borrow lives. This is a use of the cache.
    pub fn get(&self) -> Option<Ref<'_, T>> {
        self.0.used.set(now());
        Ref::filter_map(self.0.value.borrow(), Option::as_ref).ok()
    }
    /// As [`Self::get`], to change it.
    pub fn get_mut(&self) -> Option<RefMut<'_, T>> {
        self.0.used.set(now());
        RefMut::filter_map(self.0.value.borrow_mut(), Option::as_mut).ok()
    }
    /// Whether the value is still held.
    pub fn is_held(&self) -> bool {
        self.0.value.try_borrow().is_ok_and(|slot| slot.is_some())
    }
    /// Give the value up now.
    pub fn clear(&self) {
        self.0.evict();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Counts(Rc<Cell<u32>>);
    impl Drop for Counts {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn a_cache_is_given_up_once_and_is_then_done_without() {
        let dropped = Rc::new(Cell::new(0));
        let cache = Evictable::new((vec![7u8; 4096], Counts(Rc::clone(&dropped))));
        assert_eq!(cache.get().unwrap().0.len(), 4096);
        assert!(evict_all());
        assert_eq!(dropped.get(), 1);
        assert!(cache.get().is_none() && !cache.is_held());
        // Nothing is left to give up.
        assert!(!evict_all());
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn the_cache_used_longest_ago_goes_first_and_one_at_a_time() {
        let dropped = Rc::new(Cell::new(0));
        let caches: Vec<Evictable<Counts>> = (0..4)
            .map(|_| Evictable::new(Counts(Rc::clone(&dropped))))
            .collect();
        // Used in the order 2, 0, 3; the second was never used after it
        // was made, but was made after the first.
        for index in [2, 0, 3] {
            assert!(caches[index].get().is_some());
        }
        let held = |caches: &[Evictable<Counts>]| -> Vec<bool> {
            caches.iter().map(Evictable::is_held).collect()
        };
        assert!(evict_oldest());
        assert_eq!(held(&caches), [true, false, true, true]);
        assert!(evict_oldest());
        assert_eq!(held(&caches), [true, false, false, true]);
        // One in use is passed over for the next, although it is the older.
        {
            let _in_use = caches[0].get().unwrap();
            assert!(caches[3].get().is_some());
            assert!(evict_oldest());
        }
        assert_eq!(held(&caches), [true, false, false, false]);
        assert!(evict_oldest());
        assert!(!evict_oldest(), "nothing is left");
        assert_eq!(dropped.get(), 4);
    }

    #[test]
    fn the_largest_live_ledger_of_the_thread_pays_for_a_cache() {
        struct Ledger {
            limit: Cell<Option<u64>>,
            paid: Rc<Cell<u64>>,
        }
        impl CachePayer for Ledger {
            fn limit(&self) -> Option<u64> {
                self.limit.get()
            }
            fn pay(&self, bytes: u64) -> Option<Box<dyn std::any::Any>> {
                (bytes <= self.limit.get()?).then(|| {
                    self.paid.set(self.paid.get() + bytes);
                    Box::new(bytes) as Box<dyn std::any::Any>
                })
            }
        }
        assert!(matches!(pay_for_cache(10), CachePayment::NoLedger));
        let (small, large) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
        let ledger = |limit, paid: &Rc<Cell<u64>>| {
            Rc::new(Ledger {
                limit: Cell::new(Some(limit)),
                paid: Rc::clone(paid),
            })
        };
        let first = ledger(100, &small);
        let second = ledger(1000, &large);
        register_cache_payer(first.clone());
        register_cache_payer(second.clone());
        assert!(matches!(pay_for_cache(500), CachePayment::Paid(_)));
        assert_eq!((small.get(), large.get()), (0, 500));
        assert!(matches!(pay_for_cache(5000), CachePayment::Refused));
        // A ledger that is gone pays for nothing, and the other one is asked.
        second.limit.set(None);
        assert!(matches!(pay_for_cache(50), CachePayment::Paid(_)));
        assert_eq!((small.get(), large.get()), (50, 500));
        first.limit.set(None);
        assert!(matches!(pay_for_cache(50), CachePayment::NoLedger));
    }

    #[test]
    fn a_shared_cache_is_given_up_for_every_owner_at_once() {
        let dropped = Rc::new(Cell::new(0));
        let first = Evictable::new(Counts(Rc::clone(&dropped)));
        let way_back = first.downgrade();
        let second = way_back.upgrade().expect("held");
        assert!(first.is_held() && second.is_held());
        // Both may read it at once.
        {
            let (_a, _b) = (first.get().unwrap(), second.get().unwrap());
            assert!(!evict_all());
        }
        assert!(evict_all());
        assert_eq!(dropped.get(), 1);
        assert!(!first.is_held() && !second.is_held());
        // What was given up is not found again, nor what has no owner left.
        assert!(way_back.upgrade().is_none());
        let other = Evictable::new(Counts(Rc::clone(&dropped)));
        let way_back = other.downgrade();
        drop(other);
        assert!(way_back.upgrade().is_none());
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    fn a_cache_in_use_is_left_alone() {
        let dropped = Rc::new(Cell::new(0));
        let cache = Evictable::new(Counts(Rc::clone(&dropped)));
        let other = Evictable::new(Counts(Rc::clone(&dropped)));
        {
            let _in_use = cache.get().unwrap();
            assert!(evict_all());
            // The other one went; this one is borrowed and stays.
            assert_eq!(dropped.get(), 1);
            assert!(!other.is_held());
        }
        assert!(cache.is_held());
        {
            let _changing = cache.get_mut().unwrap();
            assert!(!evict_all());
        }
        assert!(evict_all());
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    fn a_cache_that_was_dropped_is_forgotten_and_one_may_drop_another() {
        let dropped = Rc::new(Cell::new(0));
        drop(Evictable::new(Counts(Rc::clone(&dropped))));
        assert_eq!(dropped.get(), 1);
        assert!(!evict_all());
        // Giving one cache up may drop another that it owns.
        struct Owner(#[allow(dead_code)] Evictable<Counts>);
        let inner = Evictable::new(Counts(Rc::clone(&dropped)));
        let outer = Evictable::new(Owner(inner));
        assert!(evict_all());
        assert_eq!(dropped.get(), 2);
        assert!(!outer.is_held());
        // Many short-lived caches do not make the registry grow without end.
        for _ in 0..10_000 {
            drop(Evictable::new(0u8));
        }
        let registered = CACHES.with(|caches| caches.borrow().len());
        assert!(registered <= 32, "{registered}");
        // And each thread has its own caches.
        let here = Evictable::new(1u8);
        std::thread::spawn(|| assert!(!evict_all())).join().unwrap();
        assert!(here.is_held());
    }
}
