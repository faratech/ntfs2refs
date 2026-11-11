//! Known-content reads over an already validated, accounted converted report.
//! Unknown original digests stay unknown and require the separate map proof.
use super::*;
use std::fmt;

/// Stored last in KnownContentVerification, which itself drops after the
/// native report's added hash strings. This pays retained extras on errors too.
pub(super) struct KnownContentMemory {
    lease: Box<dyn report_memory::ReportMemoryLease>,
}
impl fmt::Debug for KnownContentMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountedKnownContentMemory")
    }
}

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("known-content RAM arithmetic overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("known-content RAM arithmetic overflow"))
}

fn stream_workspace(item: &Input<'_>, root: &str, name: &[u16], maximum: u64) -> io::Result<u64> {
    // One current metadata snapshot (API/kernel SDs plus fixed EA/reparse
    // buffers) OR a <=4 MiB logical-read buffer, never a maximum for every row.
    // Path formatting, joining, UTF16 conversion and open-type queries are
    // bounded separately from the actual row owner's decoded metadata.
    let path = item
        .components
        .iter()
        .try_fold(root.len() as u64, |n, part| {
            add(n, add(part.len() as u64, 1)?)
        })?;
    let path = add(path, mul(name.len() as u64, 3)?)?;
    add(
        add(
            mul(
                maximum.max(crate::attestation::MAX_SECURITY_BYTES as u64),
                8,
            )?,
            8 * 1024 * 1024,
        )?,
        mul(add(path, 4096)?, 16)?,
    )
}

fn named_snapshot(file: &File, previous: &Snapshot, maximum: u64) -> io::Result<Snapshot> {
    let mut current = crate::attestation_native::source_snapshot_paged(
        file,
        false,
        usize::try_from(maximum).map_err(io::Error::other)?,
    );
    // Keep the exact feature scope of the already validated ADS observation,
    // while using the ORIGINAL admitted security bound for the live query.
    if previous.reparse.is_none() {
        current.reparse = None;
    }
    if previous.extended_attributes.is_none() && previous.extended_attributes_error.is_none() {
        current.extended_attributes = None;
        current.extended_attributes_error = None;
    }
    Ok(current)
}

pub fn verify_known_contents_in_accounted_report(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    verify_known_contents_in_accounted_report_with_lease(
        report,
        input,
        admission,
        payer,
        same_security,
        None,
    )
}

pub(crate) fn verify_known_contents_in_accounted_report_with_lease(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
) -> io::Result<GeneralConvertedReport> {
    verify_known_contents_in_accounted_report_with_aliases(
        report,
        input,
        admission,
        payer,
        same_security,
        protected,
        None,
    )
}
pub(crate) fn verify_known_contents_in_accounted_report_with_lease_windows_aliases(
    report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
    aliases: &windows_aliases::VerifiedWindowsAliases,
) -> io::Result<GeneralConvertedReport> {
    aliases.require_canonical_input(input)?;
    verify_known_contents_in_accounted_report_with_aliases(
        report,
        input,
        admission,
        payer,
        same_security,
        protected,
        Some(aliases),
    )
}
fn verify_known_contents_in_accounted_report_with_aliases(
    mut report: GeneralConvertedReport,
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    payer: &dyn report_memory::ReportMemoryAccountant,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    protected: Option<&dyn native::ProtectedReadonlyRefsAccess>,
    aliases: Option<&windows_aliases::VerifiedWindowsAliases>,
) -> io::Result<GeneralConvertedReport> {
    admission.validate()?;
    input.require_resource_metadata(admission)?;
    if report.native.resource_profile
        != Some(crate::attestation::ResourceProfile::ResourceBoundedV4(
            Some(admission),
        ))
        || !report.native.retained_rows_ram_accounted()
        || report.native.objects.len() != input.len()
        || report.native.binding.disk_number != report.pair.source.disk_number
        || report.native.binding.volume_guid != report.pair.source.volume_guid
        || report.native.binding.identity != report.pair.source.identity
        || protected.is_some_and(|lease| lease.binding() != &report.pair.source)
    {
        return Err(invalid(
            "known-content report lost its actual resource or source owner",
        ));
    }
    // Reuse the complete static metadata/namespace/security validator; this
    // enumerates no native tree and cannot substitute a saved report for the
    // already held, independently accounted observation.
    validate_existing_content_domain_with_memory_and_windows_aliases(
        &report.native,
        input,
        &same_security,
        false,
        None,
        false,
        true,
        Some(payer),
        aliases,
    )?;
    let observation = report
        .content_observation
        .as_ref()
        .ok_or_else(|| invalid("known-content metadata scope absent"))?;
    if !observation.metadata_and_namespace_verified
        || !observation.complete_stream_mappings_observed
        || !observation.data_storage_validity_checked
        || observation.admitted_payload_bytes_read != 0
        || observation.known_content.is_some()
        || report.native.objects.iter().any(|o| {
            o.logical_sha256.is_some() || o.named_streams.iter().any(|s| s.logical_sha256.is_some())
        })
    {
        return Err(invalid(
            "known-content requires the original unhashed metadata observation",
        ));
    }
    let mut known = 0u64;
    input.for_each(|_, item| {
        if !item.directory {
            known = add(known, u64::from(item.logical_sha256().is_some()))?;
            for stream in &item.named_streams {
                known = add(known, u64::from(stream.expected_sha256.is_some()))?;
            }
        }
        Ok(())
    })?;
    // At most one fixed hexadecimal digest is added for each actual known
    // original stream. The 64 KiB allowance includes the tiny privilege audit
    // and root path, and avoids retaining a query maximum per stream.
    let retained_maximum = add(add(mul(known, 128)?, 64 * 1024)?, payer.lease_heap_bytes())?;
    let retained = payer.reserve(retained_maximum)?;
    // Attach before mutating any report field: native drops BEFORE the
    // content-observation memory owner, including on every early return.
    report
        .content_observation
        .as_mut()
        .expect("validated observation")
        .known_content = Some(KnownContentVerification {
        streams_hashed: 0,
        streams_without_content_baseline: 0,
        payload_bytes_read: 0,
        privilege_states: Vec::new(),
        memory: Some(KnownContentMemory { lease: retained }),
    });
    let _privilege_ram = payer.reserve(add(512 * 1024, payer.lease_heap_bytes())?)?;
    let root = report.pair.source.volume_path()?;
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let mut count = 0usize;
    let mut skipped = 0usize;
    let mut bytes = 0u64;
    let mut retained_bytes = 0u64;
    let maximum = admission.budget.max_row_bytes;
    for (index, object) in report.native.objects.iter_mut().enumerate() {
        let owner = input.object(index)?;
        let item = owner.input();
        if item.directory {
            continue;
        }
        if let Some(expected) = item.logical_sha256() {
            let _query = payer.reserve(add(
                stream_workspace(&item, &root, &[], maximum)?,
                payer.lease_heap_bytes(),
            )?)?;
            let path = streams::path(&root, item.components, &[])?;
            let mut file = open_input(&path, &item, protected.is_some())?;
            if metadata_snapshot_with_limit(&file, &item, Some(maximum)) != object.before {
                return Err(invalid("known-content file identity or metadata changed"));
            }
            let actual = hash_exact_stream(&mut file, item.logical_length())?;
            if actual != expected
                || metadata_snapshot_with_limit(&file, &item, Some(maximum)) != object.after
            {
                return Err(invalid("known-content bytes, metadata or EOF differ"));
            }
            if actual.capacity() > 128 {
                return Err(invalid(
                    "known-content digest allocation exceeds prepayment",
                ));
            }
            retained_bytes = add(retained_bytes, actual.capacity() as u64)?;
            object.logical_sha256 = Some(actual);
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid("known-content count overflow"))?;
            bytes = add(bytes, item.logical_length())?;
        } else {
            skipped = skipped
                .checked_add(1)
                .ok_or_else(|| invalid("unknown-content count overflow"))?;
        }
        for named in &mut object.named_streams {
            let stream = item
                .named_streams
                .iter()
                .find(|s| s.name_utf16 == named.name_utf16)
                .ok_or_else(|| invalid("known named stream absent from actual expected row"))?;
            let Some(expected) = stream.expected_sha256 else {
                skipped = skipped
                    .checked_add(1)
                    .ok_or_else(|| invalid("unknown-content count overflow"))?;
                continue;
            };
            let _query = payer.reserve(add(
                stream_workspace(&item, &root, stream.name_utf16, maximum)?,
                payer.lease_heap_bytes(),
            )?)?;
            let path = streams::path(&root, item.components, stream.name_utf16)?;
            let mut file = if protected.is_some() {
                open_protected_readonly(&path, false)?
            } else {
                open(&path, false, false)?
            };
            if named_snapshot(&file, &named.before, maximum)? != named.before {
                return Err(invalid("known named-stream identity or metadata changed"));
            }
            let actual = hash_exact_stream(&mut file, stream.expected_length)?;
            if actual != expected || named_snapshot(&file, &named.after, maximum)? != named.after {
                return Err(invalid("known named-stream bytes, metadata or EOF differ"));
            }
            if actual.capacity() > 128 {
                return Err(invalid(
                    "known-content digest allocation exceeds prepayment",
                ));
            }
            retained_bytes = add(retained_bytes, actual.capacity() as u64)?;
            named.logical_sha256 = Some(actual);
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid("known-content count overflow"))?;
            bytes = add(bytes, stream.expected_length)?;
        }
    }
    privileges.restore()?;
    let privilege_states = privileges.audit().to_vec();
    retained_bytes = add(
        retained_bytes,
        mul(
            privilege_states.capacity() as u64,
            mem::size_of::<PrivilegeState>() as u64,
        )?,
    )?;
    for state in &privilege_states {
        retained_bytes = add(retained_bytes, state.name.capacity() as u64)?;
    }
    retained_bytes = add(retained_bytes, payer.lease_heap_bytes())?;
    if count as u64 != known || retained_bytes > retained_maximum {
        return Err(invalid(
            "known-content retained allocations differ from prepayment",
        ));
    }
    let observation = report
        .content_observation
        .as_mut()
        .expect("validated observation");
    let verification = observation
        .known_content
        .as_mut()
        .expect("actual retained memory owner");
    // Install the paid owned values before shrinking. If shrink fails, the
    // report still drops every value before releasing its original guard.
    verification.streams_hashed = count;
    verification.streams_without_content_baseline = skipped;
    verification.payload_bytes_read = bytes;
    verification.privilege_states = privilege_states;
    verification
        .memory
        .as_mut()
        .expect("actual retained memory owner")
        .lease
        .shrink_to(retained_bytes)?;
    observation.scope = "converted-metadata-and-known-content-hashes-v1";
    observation.admitted_payload_bytes_read = bytes;
    input.require_resource_metadata(admission)?;
    Ok(report)
}
