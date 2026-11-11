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

/// A borrowed namespace-only view. It grants no metadata/native authority and
/// cannot stand in for the complete Input used by security/content checks.
pub trait AliasObjectShape {
    fn directory(&self) -> bool;
    fn is_reparse(&self) -> bool;
    fn primary_path_matches(&self, path: &[String]) -> io::Result<bool>;
    fn contains_path(&self, path: &[String]) -> io::Result<bool>;
}

pub struct AliasObjectShapeRef<'a> {
    pub components: &'a [String],
    pub additional_names: &'a [Vec<String>],
    pub directory: bool,
    pub is_reparse: bool,
}
impl AliasObjectShape for AliasObjectShapeRef<'_> {
    fn directory(&self) -> bool {
        self.directory
    }
    fn is_reparse(&self) -> bool {
        self.is_reparse
    }
    fn primary_path_matches(&self, path: &[String]) -> io::Result<bool> {
        Ok(self.components == path)
    }
    fn contains_path(&self, path: &[String]) -> io::Result<bool> {
        Ok(self.components == path
            || self
                .additional_names
                .iter()
                .any(|name| name.as_slice() == path))
    }
}

/// Where an immutable input domain keeps its input digest between uses.
///
/// The digest covers every object of the domain; computing it decodes all of
/// them. Under the check-once policy it is computed once, and once more
/// inside each gate before a first write to the source.
#[derive(Debug, Default)]
pub struct InputDigestMemo {
    digest: std::sync::Mutex<Option<[u8; 32]>>,
    last_full: crate::verify_policy::LastFull,
}
impl InputDigestMemo {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn get(&self) -> Option<[u8; 32]> {
        if !crate::verify_policy::checks_once() {
            return None;
        }
        let known = *self
            .digest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if known.is_some() && crate::verify_policy::full(&self.last_full) {
            return None;
        }
        known
    }
    pub(crate) fn set(&self, digest: [u8; 32]) {
        *self
            .digest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(digest);
    }
}

pub trait InputDomain {
    type Object: ObjectInput;
    fn len(&self) -> usize;
    fn object(&self, index: usize) -> io::Result<Self::Object>;
    /// An immutable domain may offer a place to keep its input digest. The
    /// default keeps nothing, so the digest is computed on every use.
    fn input_digest_memo(&self) -> Option<&InputDigestMemo> {
        None
    }
    /// Diagnostic only: progress cannot fail or authorize an operation.
    fn progress(&self, _update: crate::progress::Update) {}
    /// Legacy domains keep their existing object path. Authenticated paged
    /// owners may supply a paid immutable projection from that exact domain.
    /// The callback prevents a borrowed view escaping its actual owner.
    fn with_alias_shape<T>(
        &self,
        index: usize,
        visit: impl FnOnce(&dyn AliasObjectShape) -> io::Result<T>,
    ) -> io::Result<T> {
        let owner = self.object(index)?;
        let input = owner.input();
        visit(&AliasObjectShapeRef {
            components: input.components,
            additional_names: input.additional_names,
            directory: input.directory,
            is_reparse: input.reparse.is_some(),
        })
    }
    /// Optional capacity policy, never native write authority. Call only
    /// immediately before a bounded allocating operation, not on reads.
    fn before_mutation(&self, _operation_bytes: u64) -> io::Result<()> {
        Ok(())
    }
    /// Called with a failure confined to one object in a pass where that object
    /// can be left behind. The default refuses, which stops the pass as before.
    /// A diagnostic owner may record it and return Ok so the pass continues and
    /// reports every such object; that owner must then refuse to publish.
    fn defer_failure(&self, error: io::Error) -> io::Result<()> {
        Err(error)
    }
    fn require_mutation_binding(
        &self,
        _shadow: &crate::general_layout::GeneralDiskBinding,
    ) -> io::Result<()> {
        Ok(())
    }
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
