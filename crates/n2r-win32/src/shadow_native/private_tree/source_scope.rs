//! Explicit construction source protection. Data-only state is diagnostic;
//! partition operations also require the actual original-FileObject witness.
use super::*;
#[derive(Clone, Debug)]
pub(in crate::shadow_native) enum ConstructionSourceState {
    Dedicated(native::GeneralDiskState),
    Partition(native::PartitionSourceMetadataState),
}
impl Serialize for ConstructionSourceState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Dedicated(state) => state.serialize(serializer),
            Self::Partition(state) => {
                #[derive(Serialize)]
                struct Scoped<'a> {
                    scope: &'static str,
                    partition: &'a native::PartitionSourceMetadataState,
                }
                Scoped {
                    scope: "original-private-partition-owner",
                    partition: state,
                }
                .serialize(serializer)
            }
        }
    }
}
impl ConstructionSourceState {
    pub(in crate::shadow_native) fn require(
        &self,
        pair: &GeneralSourceShadowBinding,
        partition: Option<&native::PartitionSourceMetadataWitness>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        match (self, partition) {
            (Self::Dedicated(expected), None) => {
                if expected.disk_attributes != 3
                    || native::observe_general_disk_state_readonly(pair.source.clone(), events)?
                        != *expected
                {
                    return Err(invalid("dedicated construction source exclusion changed"));
                }
            }
            (Self::Partition(expected), Some(witness)) => {
                witness.require_binding(&pair.source)?;
                witness.revalidate(events)?;
                if witness.state() != expected {
                    return Err(invalid("partition construction source witness differs"));
                }
            }
            _ => return Err(invalid("construction source scope lacks its actual owner")),
        }
        Ok(())
    }
}
pub(super) enum ConstructionSource<'a> {
    Dedicated(&'a native::GeneralFrozenPartition),
    Partition(PartitionShadowConstructionLease),
}
impl ConstructionSource<'_> {
    pub(super) fn partition(&self) -> Option<&native::PartitionSourceMetadataWitness> {
        match self {
            Self::Dedicated(_) => None,
            Self::Partition(lease) => Some(lease.witness()),
        }
    }
    pub(super) fn into_partition(self) -> Option<PartitionShadowConstructionLease> {
        match self {
            Self::Dedicated(_) => None,
            Self::Partition(lease) => Some(lease),
        }
    }
}

/// RAII lifetime for SHADOW-ONLY writes, owning the actual query-only source
/// duplicate. No Read/Seek/Write, JSON or source writer issuer is exposed.
/// Success explicitly closes with full source revalidation. On error Drop
/// releases only this query reference; Root's full closing/FP check still runs.
pub(super) struct PartitionShadowConstructionLease{
    witness:native::PartitionSourceMetadataWitness,
    pair:GeneralSourceShadowBinding,
    expected:ConstructionSourceState,
}
impl PartitionShadowConstructionLease{
    pub(super) fn begin(witness:native::PartitionSourceMetadataWitness,pair:&GeneralSourceShadowBinding,
        expected:&ConstructionSourceState,events:&mut Vec<NativeEvent>)->io::Result<Self>{
        expected.require(pair,Some(&witness),events)?;
        Ok(Self{witness,pair:pair.clone(),expected:expected.clone()})
    }
    pub(super) fn witness(&self)->&native::PartitionSourceMetadataWitness{&self.witness}
    pub(super) fn check_shadow_operation(&self,events:&mut Vec<NativeEvent>)->io::Result<()>{
        self.witness.require_binding(&self.pair.source)?;
        let ConstructionSourceState::Partition(expected)=&self.expected else{
            return Err(invalid("partition construction lease lacks actual source scope"));
        };
        self.witness.revalidate_held_shadow_identity(events)?;
        if self.witness.state()!=expected{return Err(invalid("shadow construction original witness differs"));}
        Ok(())
    }
    pub(super) fn finish(self,events:&mut Vec<NativeEvent>)->io::Result<()>{
        self.expected.require(&self.pair,Some(&self.witness),events)
    }
}
