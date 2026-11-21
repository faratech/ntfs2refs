//! Closure-scoped byte access through the actual persistently frozen source.
//! No path constructor, raw handle, writer, online transition or serialized
//! capability is exposed. Full critical-role checks bracket the entire scope;
//! every inner state check still reads exact geometry/GPT/exclusion natively.
//! The one thing handed out is a read lane of the frozen source itself: a
//! read-only handle for aligned reads, held to the frozen route when opened.
use super::{
    GeneralDiskState, GeneralFrozenLane, GeneralFrozenPartition, NativeEvent,
    general_disk_state_held_geometry,
};
use crate::{
    general_layout::GeneralDiskBinding, shadow_native::report_memory::ReportMemoryAccountant,
};
use std::{
    cell::Cell,
    io::{self, Read, Seek, SeekFrom},
};

// Same already-accounted role/control workspace bound as the existing
// frozen_shadow_source_query witness. This is paid before either full fence.
const SCOPE_MEMORY_BYTES: u64 = 9 * 1024 * 1024;

fn native_step<T>(
    events: &mut Vec<NativeEvent>,
    call: impl FnOnce(&mut Vec<NativeEvent>) -> io::Result<T>,
) -> io::Result<T> {
    let mut batch = Vec::new();
    let result = call(&mut batch);
    events.append(&mut batch);
    result
}

/// A borrow of the actual immutable source, valid only within the issuing
/// closure. Private fields; no Clone/Deserialize/Write/AsRawHandle or owner
/// extraction. Read/Seek use the original reader and its byte accounting.
pub struct GeneralFrozenSourceReadScope<'source> {
    source: &'source mut GeneralFrozenPartition,
    poisoned: Cell<bool>,
}
impl GeneralFrozenSourceReadScope<'_> {
    pub fn binding(&self) -> &GeneralDiskBinding {
        self.source.binding()
    }
    pub fn byte_len(&self) -> u64 {
        self.source.byte_len()
    }
    /// Descriptive identity of the actual original owner, never a capability.
    pub fn original_owner_identity(&self) -> usize {
        std::ptr::from_ref(&*self.source) as usize
    }
    pub fn state(&self, events: &mut Vec<NativeEvent>) -> io::Result<GeneralDiskState> {
        if self.poisoned.get() {
            return Err(io::Error::other(
                "failed frozen source read scope cannot validate",
            ));
        }
        let _timed = crate::perf::scope(crate::perf::Point::ReadProtection);
        let result = native_step(events, |batch| {
            let actual =
                general_disk_state_held_geometry(&self.source.file, &self.source.binding, batch)?;
            if actual != self.source.frozen_state || actual.disk_attributes != 3 {
                return Err(io::Error::other(
                    "scoped source geometry or exclusion changed",
                ));
            }
            Ok(actual)
        });
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
    /// The storage transfer profile Windows reports for the frozen disk: the
    /// size of a request and how many reads may be outstanding at once.
    pub fn io_profile(&self) -> crate::io_profile::IoProfile {
        self.source.io_profile()
    }
    /// Opens `count` read lanes on the frozen source, as
    /// [`GeneralFrozenPartition::read_lanes`] does for its owner, so that
    /// several reads can be outstanding at once within the scope. Each is a
    /// fresh read-only handle whose route equalled the frozen state when it
    /// was opened; it reads aligned bytes and can change nothing.
    ///
    /// A lane owns its handle and is not tied to the scope's lifetime. The
    /// checks that bracket the scope cover what is read between them: every
    /// lane is to be dropped before the closure returns, and a lane's failed
    /// read is the closure's to return, since it does not poison the scope.
    pub fn read_lanes(
        &self,
        count: usize,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Vec<GeneralFrozenLane>> {
        if self.poisoned.get() {
            return Err(io::Error::other(
                "failed frozen source read scope cannot open read lanes",
            ));
        }
        // Opening a lane reads nothing of the source: a lane that cannot be
        // opened (its handle, its aligned buffer, the state query that
        // binds it) leaves the scope as it was. Its own reads and the
        // checks around it are what they were, and a caller that wanted the
        // lane only to read ahead reads through the scope instead.
        native_step(events, |batch| self.source.read_lanes(count, batch))
    }
}
impl Read for GeneralFrozenSourceReadScope<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned.get() {
            return Err(io::Error::other(
                "failed frozen source read scope cannot read",
            ));
        }
        let result = self.source.read(output);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
}
impl Seek for GeneralFrozenSourceReadScope<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if self.poisoned.get() {
            return Err(io::Error::other(
                "failed frozen source read scope cannot seek",
            ));
        }
        let result = self.source.seek(from);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
}
impl GeneralFrozenPartition {
    /// Supply bytes within a single exclusive borrow of this live owner.
    /// The full closing role fence runs even when the closure returns Err;
    /// no result can escape successfully before that closing fence passes.
    /// A panic returns no value and conveys no source/publication authority.
    pub fn with_readonly_source_bytes<T>(
        &mut self,
        payer: &dyn ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
        consume: impl for<'scope> FnOnce(&mut GeneralFrozenSourceReadScope<'scope>) -> io::Result<T>,
    ) -> io::Result<T> {
        let _memory = payer.reserve(SCOPE_MEMORY_BYTES)?;
        let opening = native_step(events, |batch| self.state(batch))?;
        if opening.disk_attributes != 3 {
            return Err(io::Error::other(
                "scoped source must remain offline and read-only",
            ));
        }
        let body = {
            let mut scope = GeneralFrozenSourceReadScope {
                source: self,
                poisoned: Cell::new(false),
            };
            let body = consume(&mut scope);
            if body.is_ok() && scope.poisoned.get() {
                Err(io::Error::other(
                    "source scope swallowed a failed native operation",
                ))
            } else {
                body
            }
        };
        // Deliberately independent of body/poison status. Always attempt the
        // complete original roles + geometry + persistent-exclusion closing.
        let closing = native_step(events, |batch| self.state(batch)).and_then(|actual| {
            if actual != opening || actual.disk_attributes != 3 {
                Err(io::Error::other("scoped source full closing state changed"))
            } else {
                Ok(())
            }
        });
        match (body, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(body), Ok(())) => Err(body),
            (Ok(_), Err(closing)) => Err(closing),
            (Err(body), Err(closing)) => Err(io::Error::new(
                closing.kind(),
                format!("source read scope closing failed: {closing}; body failed: {body}"),
            )),
        }
    }
}
