//! One-object native views over an already authenticated immutable domain.
//! This interface grants no source or target authority; constructor owners
//! still perform complete validation and retain every native object handle.
use super::Input;
use serde::{
    Serialize, Serializer,
    ser::{Error as _, SerializeSeq},
};
use std::io;

pub trait ObjectInput {
    fn input(&self) -> Input<'_>;
}

pub trait InputDomain {
    type Object: ObjectInput;
    fn len(&self) -> usize;
    fn object(&self, index: usize) -> io::Result<Self::Object>;
    /// Optional capacity policy, never native write authority. Call only
    /// immediately before a bounded allocating operation, not on reads.
    fn before_mutation(&self, _operation_bytes: u64) -> io::Result<()> { Ok(()) }
    fn require_mutation_binding(&self, _shadow: &crate::general_layout::GeneralDiskBinding)
        -> io::Result<()> { Ok(()) }
    /// New paged admissions require an actual immutable page owner. Legacy
    /// slices intentionally cannot supply that owner from their metadata.
    fn require_paged_metadata(
        &self,
        _budget: crate::metadata_pages::PageBudget,
        _semantic_bytes: u64,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "native constructor requires authenticated paged metadata ownership",
        ))
    }
    /// ResourceBoundedV4 additionally requires the real owner to have checked
    /// each object's decode size and its retained indexes against the admitted
    /// RAM contract before decoding. A legacy page-budget flag cannot do this.
    fn require_resource_metadata(
        &self,
        _admission: crate::tree_resources::SourceResourceAdmission,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "native resource construction requires bounded typed page ownership",
        ))
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn for_each(
        &self,
        mut visit: impl FnMut(usize, &Input<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        for index in 0..self.len() {
            let object = self.object(index)?;
            visit(index, &object.input())?;
        }
        Ok(())
    }
    fn any(&self, mut predicate: impl FnMut(&Input<'_>) -> bool) -> io::Result<bool> {
        for index in 0..self.len() {
            let object = self.object(index)?;
            if predicate(&object.input()) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn position(&self, mut predicate: impl FnMut(&Input<'_>) -> bool) -> io::Result<Option<usize>> {
        for index in 0..self.len() {
            let object = self.object(index)?;
            if predicate(&object.input()) {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
}

pub struct SliceInputs<'a, 'b>(pub &'a [Input<'b>]);
impl<'a, 'b> InputDomain for SliceInputs<'a, 'b> {
    type Object = &'a Input<'b>;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn object(&self, index: usize) -> io::Result<Self::Object> {
        self.0
            .get(index)
            .ok_or_else(|| io::Error::other("native input ordinal absent"))
    }
}
impl ObjectInput for &Input<'_> {
    fn input(&self) -> Input<'_> {
        (*self).clone()
    }
}

/// Serialize exactly the legacy Input array, without allocating that array.
pub struct DomainMetadata<'a, D: InputDomain>(pub &'a D);
impl<D: InputDomain> Serialize for DomainMetadata<'_, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer.serialize_seq(Some(self.0.len()))?;
        for index in 0..self.0.len() {
            let object = self.0.object(index).map_err(S::Error::custom)?;
            output.serialize_element(&object.input())?;
        }
        output.end()
    }
}
