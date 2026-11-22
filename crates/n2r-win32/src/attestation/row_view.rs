//! Borrowed access to one native row while its actual allocation lease lives.
//! No Clone/Deserialize, mutable fields or consuming payload getter is exposed.
use super::*;

pub struct NativeObservationRow<'a> {
    request: Cow<'a, NativeRequestRow>,
    observation: HeldObservation<'a>,
    logical: Option<Cow<'a, LogicalFile>>,
    namespace: Option<Cow<'a, NamespaceFile>>,
    #[cfg(windows)]
    memory: Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
}
/// A row's observation: lent by a domain that holds it, or decoded for the
/// row and held shared, so that a caller that keeps it beyond the row (the
/// comparison hands it to its workers) takes a share of it, not a copy.
enum HeldObservation<'a> {
    Borrowed(&'a Observation),
    Shared(std::sync::Arc<Observation>),
}
impl<'a> NativeObservationRow<'a> {
    pub(crate) fn new(
        request: Cow<'a, NativeRequestRow>,
        observation: Cow<'a, Observation>,
        logical: Option<Cow<'a, LogicalFile>>,
        namespace: Option<Cow<'a, NamespaceFile>>,
    ) -> Self {
        Self {
            request,
            observation: match observation {
                Cow::Borrowed(observation) => HeldObservation::Borrowed(observation),
                Cow::Owned(observation) => {
                    HeldObservation::Shared(std::sync::Arc::new(observation))
                }
            },
            logical,
            namespace,
            #[cfg(windows)]
            memory: None,
        }
    }
    #[cfg(windows)]
    pub(crate) fn with_memory(
        mut self,
        memory: Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
    ) -> Self {
        self.memory = memory;
        self
    }
    pub fn request(&self) -> &NativeRequestRow {
        self.request.as_ref()
    }
    pub fn observation(&self) -> &Observation {
        match &self.observation {
            HeldObservation::Borrowed(observation) => observation,
            HeldObservation::Shared(observation) => observation,
        }
    }
    /// The observation to keep beyond the row: a share of the one the row
    /// decoded, or a copy of one a domain lends.
    pub fn observation_shared(&self) -> std::sync::Arc<Observation> {
        match &self.observation {
            HeldObservation::Borrowed(observation) => std::sync::Arc::new((*observation).clone()),
            HeldObservation::Shared(observation) => std::sync::Arc::clone(observation),
        }
    }
    pub fn logical(&self) -> io::Result<&LogicalFile> {
        self.logical
            .as_deref()
            .ok_or_else(|| io::Error::other("native logical row absent"))
    }
    pub fn namespace(&self) -> io::Result<&NamespaceFile> {
        self.namespace
            .as_deref()
            .ok_or_else(|| io::Error::other("native namespace row absent"))
    }
    pub fn ram_accounted(&self) -> bool {
        #[cfg(windows)]
        {
            self.memory.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}
