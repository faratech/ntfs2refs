//! Exact byte-continuity evidence for previously collected source metadata.
//! Persisted pins and range producers are inputs, never native authority.
use super::*;
use crate::attestation::NativeObservationDomain;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};
use std::{ffi::c_void, os::windows::io::FromRawHandle};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE},
    System::Threading::GetCurrentProcess,
};

const DOMAIN: &[u8] = b"ntfs2refs/source/resource-metadata-and-extents/v1\0";
const PIECE: usize = 4 * 1024 * 1024;
const QUERY_ACCESS: u32 = 0x0010_0081;
const RETAINED: u64 = 9 * 1024 * 1024;

/// Authenticated, bounded range access supplied by the owning application.
/// The SDK independently hashes actual bytes; this trait has no verified flag.
pub trait SourceCacheFingerprintDomain {
    fn partition_bytes(&self) -> u64;
    fn inspection_sha256(&self) -> [u8; 32];
    fn range_count(&self, omitted: bool) -> u64;
    fn range(&self, omitted: bool, index: u64) -> io::Result<(u64, u64)>;
    fn revalidate(&self) -> io::Result<()>;
}

#[repr(C)]
#[derive(Default)]
struct ObjectBasic {
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
    reserved: [u32; 10],
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: HANDLE,
        class: i32,
        out: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}
// Documented object identity comparison, independent of handle value/access:
// https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles
// Generate this single import directly: current Windows SDK installations do
// not necessarily ship Kernelbase.lib, although the system DLL exports it.
#[link(name = "kernelbase", kind = "raw-dylib")]
unsafe extern "system" {
    fn CompareObjectHandles(first: HANDLE, second: HANDLE) -> i32;
}

fn query_access(file: &File) -> io::Result<()> {
    let mut info = ObjectBasic::default();
    let mut returned = 0;
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            0,
            (&mut info as *mut ObjectBasic).cast(),
            56,
            &mut returned,
        )
    };
    if status != 0 || returned != 56 || info.granted_access != QUERY_ACCESS {
        return Err(invalid(
            "source-cache duplicate does not have exact query-only rights",
        ));
    }
    Ok(())
}

/// Opaque evidence issued by actual source reads under a NEW observed freeze.
/// Its duplicate retains the original FileObject. No reader, writer, pathname,
/// raw handle, clone, deserializer, or certificate constructor is exposed.
pub struct SourceCacheContinuity {
    file: File,
    binding: GeneralDiskBinding,
    expected: GeneralDiskState,
    inspection: [u8; 32],
    origin: [u8; 32],
    fingerprint: [u8; 32],
    _memory: Box<dyn ReportMemoryLease>,
}
impl std::fmt::Debug for SourceCacheContinuity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCacheContinuity")
            .field("binding", &self.binding)
            .field("inspection_sha256", &hex::encode(self.inspection))
            .field("origin_sha256", &hex::encode(self.origin))
            .finish_non_exhaustive()
    }
}
impl SourceCacheContinuity {
    pub fn inspection_sha256(&self) -> [u8; 32] {
        self.inspection
    }
    pub fn origin_sha256(&self) -> [u8; 32] {
        self.origin
    }
    pub fn fingerprint_sha256(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub fn require_source(
        &self,
        source: &GeneralFrozenPartition,
        inspection: [u8; 32],
        origin: [u8; 32],
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        query_access(&self.file)?;
        if source.freeze_observation().is_none()
            || source.binding != self.binding
            || inspection != self.inspection
            || origin != self.origin
            || unsafe {
                CompareObjectHandles(self.file.as_raw_handle(), source.file.as_raw_handle())
            } == 0
            || source.state(events)? != self.expected
            || self.expected.disk_attributes != 3
        {
            return Err(invalid(
                "source-cache proof does not bind this new actual frozen FileObject",
            ));
        }
        Ok(())
    }
}

impl GeneralFrozenPartition {
    /// Recompute the existing extent-identity fingerprint from actual source
    /// bytes. Other policies are deliberately outside this initial cache API.
    pub fn verify_cached_source_continuity(
        &mut self,
        domain: &impl SourceCacheFingerprintDomain,
        expected_fingerprint: [u8; 32],
        origin: [u8; 32],
        payer: &dyn ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<SourceCacheContinuity> {
        if self.binding.layout_profile
            != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            || self.freeze_observation().is_none()
            || domain.partition_bytes() != self.byte_len()
            || domain.inspection_sha256() == [0; 32]
            || origin == [0; 32]
        {
            return Err(invalid(
                "exact source cache requires a new actual offline-Windows freeze",
            ));
        }
        let mut memory = payer.reserve(RETAINED + PIECE as u64)?;
        domain.revalidate()?;
        let before = self.state(events)?;
        if before.disk_attributes != 3 {
            return Err(invalid("source cache requires physical OFFLINE|READ_ONLY"));
        }
        let original_position = self.position;
        let hashed = (|| -> io::Result<[u8; 32]> {
            let mut inner = Sha256::new();
            let mut buffer = vec![0; PIECE];
            for omitted in [false, true] {
                let count = domain.range_count(omitted);
                if !omitted && count == 0 {
                    return Err(invalid("cached fingerprint has no covered ranges"));
                }
                let mut previous_end = None;
                for index in 0..count {
                    let (offset, length) = domain.range(omitted, index)?;
                    let end = offset
                        .checked_add(length)
                        .filter(|end| length > 0 && *end <= self.byte_len())
                        .ok_or_else(|| invalid("cached fingerprint range escapes actual source"))?;
                    if previous_end.is_some_and(|old| old >= offset) {
                        return Err(invalid(
                            "cached fingerprint ranges are not canonical/disjoint",
                        ));
                    }
                    previous_end = Some(end);
                    if omitted {
                        continue;
                    }
                    inner.update(offset.to_le_bytes());
                    inner.update(length.to_le_bytes());
                    let mut done = 0;
                    while done < length {
                        let bytes = (length - done).min(PIECE as u64) as usize;
                        self.seek(SeekFrom::Start(offset + done))?;
                        self.read_exact(&mut buffer[..bytes])?;
                        inner.update(xxhash_rust::xxh3::xxh3_128(&buffer[..bytes]).to_be_bytes());
                        done += bytes as u64;
                    }
                }
            }
            let mut digest = Sha256::new();
            digest.update(DOMAIN);
            digest.update(self.byte_len().to_le_bytes());
            digest.update(domain.inspection_sha256());
            digest.update([1]);
            for omitted in [false, true] {
                digest.update(domain.range_count(omitted).to_le_bytes());
                for index in 0..domain.range_count(omitted) {
                    let (offset, length) = domain.range(omitted, index)?;
                    digest.update(offset.to_le_bytes());
                    digest.update(length.to_le_bytes());
                }
            }
            digest.update(inner.finalize());
            Ok(digest.finalize().into())
        })();
        let restored = self.seek(SeekFrom::Start(original_position));
        let actual = hashed?;
        restored?;
        domain.revalidate()?;
        if self.state(events)? != before || actual != expected_fingerprint {
            return Err(invalid(
                "source cache exact fingerprint differs; preserve cache/shadow and require a separate metadata refresh",
            ));
        }
        let process = unsafe { GetCurrentProcess() };
        let mut raw = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                self.file.as_raw_handle(),
                process,
                &mut raw,
                QUERY_ACCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(raw) };
        query_access(&file)?;
        if unsafe { CompareObjectHandles(file.as_raw_handle(), self.file.as_raw_handle()) } == 0 {
            return Err(invalid(
                "source cache duplicate is not the original FileObject",
            ));
        }
        memory.shrink_to(RETAINED)?;
        Ok(SourceCacheContinuity {
            file,
            binding: self.binding.clone(),
            expected: before,
            inspection: domain.inspection_sha256(),
            origin,
            fingerprint: actual,
            _memory: memory,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeSourceObservationOrigin {
    FreshCollection,
    RevalidatedCachedRows {
        origin_sha256: String,
        source_fingerprint_sha256: String,
        native_pages_sha256: String,
    },
}

impl GeneralFrozenPartition {
    /// Reuse authenticated per-file rows only after SDK actual-byte continuity.
    /// Fresh protected VSS/TxF/member observations and closing fingerprint are
    /// mandatory. This neither deserializes a live owner nor issues admission.
    pub fn observe_revalidated_cached_ntfs_files_with_memory(
        &mut self,
        selectors: &impl crate::attestation::NativeRequestDomain,
        path: &std::path::Path,
        native_sha256: &str,
        budget: crate::observation_pages::NativeObservationBudget,
        continuity: SourceCacheContinuity,
        fingerprint: &impl SourceCacheFingerprintDomain,
        memory: Arc<dyn ReportMemoryAccountant>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<GeneralLivePagedNtfsObservation> {
        crate::attestation::validate_native_request_domain(selectors)?;
        let request = selectors.header();
        if request.schema_version != 8
            || !request.has_paged_selectors()
            || self.resource_budget
                != request
                    .resource_profile
                    .unwrap()
                    .resource_admission()?
                    .map(|a| a.budget)
            || request.source_inspection_sha256 != hex::encode(continuity.inspection)
        {
            return Err(invalid(
                "cached native rows require exact extent-identity source/request bounds",
            ));
        }
        continuity.require_source(self, continuity.inspection, continuity.origin, events)?;
        let mut privileges = crate::attestation_native::Privileges::enable_for(&[
            "SeBackupPrivilege",
            "SeSecurityPrivilege",
        ])?;
        let binding = self.binding.clone();
        let mut markers = None;
        let mut objects = None;
        let collected = self.observe_ntfs_files_with_collector(request, events, true, |_| {
            let tx =
                crate::windows_txf::PendingWindowsTxfMarkers::begin(&binding, selectors, &memory)?;
            let object = match crate::windows_object_ids::PendingWindowsObjectIds::begin(
                &binding, selectors, &memory,
            ) {
                Ok(v) => v,
                Err(e) => return Err(tx.refuse(e)),
            };
            let paid = crate::observation_pages::memory::Memory::new(
                Arc::clone(&memory),
                budget,
                selectors.len(),
                path,
            )?;
            let opened = crate::observation_pages::PagedNativeObservation::open_with_memory(
                path,
                native_sha256,
                budget,
                paid,
            );
            let domain = match opened {
                Ok(v) => v,
                Err(e) => return Err(tx.refuse(object.refuse(e))),
            };
            if domain.header().request != *request {
                return Err(tx.refuse(object.refuse(invalid(
                    "cached native request differs from exact reopened source",
                ))));
            }
            markers = Some(Arc::new(tx.finish(selectors)?));
            objects = Some(Arc::new(object.finish(selectors)?));
            Ok(domain)
        })?;
        selectors.revalidate()?;
        if !collected.txf.as_ref().is_some_and(|txf| {
            txf.observation.default_rm_state() == crate::txf_native::DefaultRmState::Inactive
        }) {
            return Err(invalid(
                "cached source requires a fresh inactive protected default-RM witness",
            ));
        }
        let closing = self.verify_cached_source_continuity(
            fingerprint,
            continuity.fingerprint,
            continuity.origin,
            memory.as_ref(),
            events,
        )?;
        closing.require_source(self, continuity.inspection, continuity.origin, events)?;
        privileges.restore()?;
        events.push(NativeEvent{operation:"revalidated-cached-native-source-origin".into(),control_code:0,
            input:Vec::new(),succeeded:true,native_error:None,
            output:serde_json::to_vec(&serde_json::json!({"kind":"revalidated_cached_rows",
                "source_inspection_sha256":hex::encode(continuity.inspection),
                "origin_sha256":hex::encode(continuity.origin),"native_pages_sha256":native_sha256,
                "fresh_runtime_observation":true,"fresh_fingerprint_equal":true,
                "per_file_native_rows_recollected":false,"own_process_privileges":privileges.audit(),
                "grants_source_admission":false})).map_err(io::Error::other)?});
        Ok(GeneralLivePagedNtfsObservation {
            domain: collected.domain,
            windows_txf_markers: markers,
            windows_object_ids: objects,
            txf: collected.txf,
            txf_error: collected.txf_error,
            vss_observation: collected.vss_observation,
            before: collected.before,
            after: collected.after,
            origin: NativeSourceObservationOrigin::RevalidatedCachedRows {
                origin_sha256: hex::encode(continuity.origin),
                source_fingerprint_sha256: hex::encode(continuity.fingerprint),
                native_pages_sha256: native_sha256.to_owned(),
            },
            cache_continuity: Some(closing),
        })
    }
}
