# Identities/sharing/unchanged observations are not a durable host+guest storage
# fence. No native operation exists here; absent enforcement always refuses.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-IsolatedJournalExclusionContract {
    [pscustomobject]@{
        schema_version=1;kind='isolated-journal-writer-exclusion-contract'
        backend_available=$false;durable_exclusion_established=$false
        zero_scan_permitted=$false;initialization_permitted=$false;write_authority=$false
        observed_identity_pins_are_content_fences=$false
        guest_route_sharing_is_storage_stack_exclusion=$false
        same_stream_zero_proof_rechecks_content=$false
        required=@(
            'Bind current VM, controllers and every host backing/ancestor by held native file identity.'
            'Enforce absence of host file, host virtual-disk, alias and lower-stack writes to the journal.'
            'Enforce guest write exclusion across every route to the same actual device.'
            'Drain prior writers and retain enforcement throughout the coherent zero read and proof lifetime.'
            'Process death, channel loss, revocation or replacement must not leave a usable stale proof.'
            'Native enforcement capabilities are required; JSON, PIDs and stable snapshots are not capabilities.'
        )
        limitation='No reviewed durable cross-host/storage-stack enforcement backend exists for the current writable Hyper-V journal attachment. Identity collection may run after review; native zero scanning must refuse.'
    }
}
function Assert-IsolatedJournalExclusion {
    param($HostLease,$GuestLease,$ClaimedFence)
    if($null -eq $HostLease -or $HostLease.closed){throw 'A current host identity lease is required, but is not writer exclusion.'}
    # No success branch: a JSON success flag or pure ZeroProof cannot create
    # the absent native capability, regardless of observation agreement.
    throw [NotSupportedException]::new((Get-IsolatedJournalExclusionContract).limitation)
}
Export-ModuleMember -Function Get-IsolatedJournalExclusionContract,Assert-IsolatedJournalExclusion
