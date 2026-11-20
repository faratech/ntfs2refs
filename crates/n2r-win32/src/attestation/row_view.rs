//! Borrowed access to one native row while its actual allocation lease lives.
//! No Clone/Deserialize, mutable fields or consuming payload getter is exposed.
use super::*;

pub struct NativeObservationRow<'a> {
    request: Cow<'a, NativeRequestRow>,
    observation: Cow<'a, Observation>,
    logical: Option<Cow<'a, LogicalFile>>,
    namespace: Option<Cow<'a, NamespaceFile>>,
    #[cfg(windows)]
    memory: Option<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
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
            observation,
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
        self.observation.as_ref()
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
    /// Whether this row holds an object's metadata snapshot and nothing of
    /// its streams, their contents or its directory listing: what every row
    /// of a report without a content pass (`content_passes` 0) must be.
    pub fn holds_metadata_only(&self) -> io::Result<bool> {
        let observation = self.observation();
        let logical = self.logical()?;
        let namespace = self.namespace()?;
        Ok(observation.streams_before.is_none()
            && observation.streams_after.is_none()
            && logical.before.is_empty()
            && logical.after.is_empty()
            && namespace.open_error.is_none()
            && namespace.identity_before.is_none()
            && namespace.identity_after.is_none()
            && namespace.standard.is_none()
            && namespace.before.is_none()
            && namespace.after.is_none())
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
