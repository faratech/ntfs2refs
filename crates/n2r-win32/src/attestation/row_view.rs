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
