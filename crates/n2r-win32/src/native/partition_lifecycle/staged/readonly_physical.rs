//! Fresh target-only BasicRO/physical-data handoff. No GPT change/private phase.
//! Construction requires actual mounted readonly native witness, then real relock
//! and a durable version2 external intent before transferring the original Files.
use super::*;

pub fn freeze_mounted_ntfs_readonly_physical(
    binding:PartitionSourceBinding,
    budget:PartitionObservationBudget,
    mut guard:PartitionPreparationGuard,
    events:&mut Vec<NativeEvent>,
)->io::Result<(PartitionScopedOwner,PartitionNtfsAdmission)>{
    require(guard.binding==binding&&guard.budget==budget
        &&guard.stage==PartitionPreparationStage::NativeReadonlyCaptured,
        "complete actual BasicRO native witness required before physical-data handoff")?;
    guard.checkpoint("readonly-physical-freeze-opening",events)?;
    let native=guard.native.take().ok_or_else(||invalid("actual nativeRO witness missing"))?;
    {let mut phase=PartitionReadonlyPhase{guard:&mut guard};native.require_phase(&mut phase,events)?;}
    // Native collector has returned/closed ALL source file reads. The actual
    // fresh BasicRO handle is locked/dismounted/DASD once by the existing guard.
    guard.lock_and_flush(events)?;
    require(guard.locked
        &&guard.current_info[32..48]==crate::layout::guid_bytes(BASIC)?
        &&crate::layout::u64_at(&guard.current_info,64)?==READONLY,
        "readonly physical handoff requires actual locked BASIC+RO target")?;
    guard.revalidate_current(events)?;
    let volume=guard.volume.as_ref().ok_or_else(||invalid("real locking volume owner absent"))?;
    guard.check_volume(volume,events)?;
    match control(volume,"readonly-physical-handoff-IS_WRITABLE-must-error19",
        IS_WRITABLE,&[],0,events){
        Err(error)if error.raw_os_error()==Some(19)=>(),
        Err(error)=>return Err(error),
        Ok(_)=>return Err(invalid("BASIC+RO physical handoff did not observe WRITE_PROTECT19")),
    }
    guard.checkpoint("readonly-physical-lock-and-protection-complete",events)?;
    let from=guard.stage;
    let desired=guard.current_info.clone();
    // This record acknowledges a real protected data-owner handoff, NOT a
    // setter. First BasicRO setter's legacy intent/frame remains byte-exact.
    guard.stage=PartitionPreparationStage::Poisoned;
    let record=Intent{
        version:2,kind:"partition-readonly-physical-pre-AP-intent-v2",
        sequence:guard.intent.sequence+1,
        stage:PartitionPreparationStage::ReadonlyPhysicalLocked,
        binding:&guard.binding,
        original_partition_info:&guard.original_info,
        current_partition_info:&guard.current_info,
        desired_partition_info:&desired,
        original_gpt:&guard.baseline.gpt,
        original_mbr:&guard.mbr,
        ntfs_primary_sha256:hex::encode(guard.primary),
        source_AP_issued:false,process_death_recovery_authority:false,
    };
    let receipt=guard.intent.persist(&record,from,&desired)?;
    require(receipt.version==2&&receipt.desired_type==crate::layout::guid_bytes(BASIC)?
        &&receipt.desired_attributes==READONLY,"durable readonlyphysical handoff record differs")?;
    guard.observer.durable_intent(&receipt)?;
    // All metadata/critical/native checks run again after durable external ACK.
    guard.revalidate_current(events)?;
    guard.stage=PartitionPreparationStage::ReadonlyPhysicalLocked;
    guard.checkpoint("readonly-physical-before-original-owner-transfer",events)?;
    let mut owner=PartitionScopedOwner::adopt_readonly_physical_owner(
        binding,budget,
        guard.volume.take().ok_or_else(||invalid("original locking source File absent"))?,
        guard.physical.take().ok_or_else(||invalid("original readonly physical File absent"))?,
        guard.observer.clone(),events,
    )?;
    require(owner.data_profile()==super::super::PartitionDataProfile::BasicReadonlyPhysicalV3,
        "readonly physical adoption did not issue its actual data profile")?;
    owner.revalidate(events)?;
    guard.checkpoint("readonly-physical-original-owner-transfer-complete",events)?;
    let admission=PartitionNtfsAdmission{owner:owner.owner_token(),guard,native};
    require_complete_fresh_ntfs_admission(&owner,&admission)?;
    Ok((owner,admission))
}
