//! The rows of a native report: one [`ObjectReport`] for each object of the
//! volume walk, in the order of the walk. Nothing outside this module holds
//! the rows' storage: a row is lent to a closure and to nothing longer, so
//! that the storage can become a file read back a block at a time.
use super::ObjectReport;
use crate::layout::invalid;
use serde::{Serialize, Serializer};
use std::io;

#[derive(Debug)]
pub struct Rows {
    rows: Vec<ObjectReport>,
}

impl Rows {
    /// No rows and no storage.
    pub(super) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Room for exactly the `count` rows a walk will push.
    pub(super) fn with_exact_capacity(count: usize) -> io::Result<Self> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(io::Error::other)?;
        Ok(Self { rows })
    }

    /// The rows of a walk that observed all its objects at once, in its
    /// order. The allocation is kept as it is.
    pub(super) fn from_observed(rows: Vec<ObjectReport>) -> Self {
        Self { rows }
    }

    /// Adds the row of the next index. The storage never grows beyond what
    /// was reserved for it: its memory was paid for at that size.
    pub(super) fn push(&mut self, row: ObjectReport) -> io::Result<()> {
        if self.rows.len() == self.rows.capacity() {
            return Err(invalid(
                "native object slots exceeded their initial reservation",
            ));
        }
        self.rows.push(row);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The number of row slots held, which the report's memory is bound to.
    pub(super) fn capacity(&self) -> usize {
        self.rows.capacity()
    }

    /// Every row with its index, in ascending order of index. Stops at the
    /// first error and returns it.
    pub fn for_each(
        &self,
        visit: impl FnMut(usize, &ObjectReport) -> io::Result<()>,
    ) -> io::Result<()> {
        self.try_for_each(visit)
    }

    /// [`Self::for_each`] for a visitor with an error type of its own.
    pub fn try_for_each<E: From<io::Error>>(
        &self,
        mut visit: impl FnMut(usize, &ObjectReport) -> Result<(), E>,
    ) -> Result<(), E> {
        for (index, row) in self.rows.iter().enumerate() {
            visit(index, row)?;
        }
        Ok(())
    }

    /// The row at `index`. An index beyond the rows is an error.
    pub fn with<T>(
        &self,
        index: usize,
        read: impl FnOnce(&ObjectReport) -> io::Result<T>,
    ) -> io::Result<T> {
        self.try_with(index, read)
    }

    /// [`Self::with`] for a reader with an error type of its own.
    pub fn try_with<T, E: From<io::Error>>(
        &self,
        index: usize,
        read: impl FnOnce(&ObjectReport) -> Result<T, E>,
    ) -> Result<T, E> {
        let count = self.rows.len();
        read(self.rows.get(index).ok_or_else(|| absent(index, count))?)
    }

    /// Records the digest of the default stream of the row at `index`.
    pub(super) fn set_logical_sha256(
        &mut self,
        index: usize,
        digest: Option<String>,
    ) -> io::Result<()> {
        self.row_mut(index)?.logical_sha256 = digest;
        Ok(())
    }

    /// Records the digest of the named stream at `stream`, in the order of
    /// the row's `named_streams`, of the row at `index`.
    pub(super) fn set_named_stream_logical_sha256(
        &mut self,
        index: usize,
        stream: usize,
        digest: Option<String>,
    ) -> io::Result<()> {
        self.row_mut(index)?
            .named_streams
            .get_mut(stream)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native report row {index} has no named stream {stream}"),
                )
            })?
            .logical_sha256 = digest;
        Ok(())
    }

    fn row_mut(&mut self, index: usize) -> io::Result<&mut ObjectReport> {
        let count = self.rows.len();
        self.rows.get_mut(index).ok_or_else(|| absent(index, count))
    }
}

fn absent(index: usize, count: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("native report row {index} was asked of {count} rows"),
    )
}

/// A JSON array of the rows, as the vector of them was.
impl Serialize for Rows {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Snapshot;

    fn snapshot() -> Snapshot {
        Snapshot {
            queries: vec![],
            security: vec![],
            security_error: None,
            kernel_security: None,
            extended_attributes: None,
            extended_attributes_error: None,
            reparse: None,
            directory_case_sensitivity: None,
        }
    }

    fn row(name: &str) -> ObjectReport {
        ObjectReport {
            components: vec![name.to_owned()],
            additional_names: vec![],
            named_streams: vec![],
            sparse: None,
            before: snapshot(),
            after: snapshot(),
            logical_sha256: None,
            retrieval: vec![1, 2, 3],
            retrieval_page_proof: None,
            resident_data: false,
            cached_validity: vec![],
            storage_validity: vec![],
            cached_validity_pages: None,
            storage_validity_pages: None,
            integrity: vec![],
            namespace: vec![],
            source_candidate: None,
            streams: vec![],
        }
    }

    #[test]
    fn rows_are_the_vector_they_replace() {
        let names = ["a", "b", "c"];
        let plain: Vec<ObjectReport> = names.iter().map(|name| row(name)).collect();
        let mut rows = Rows::with_exact_capacity(names.len()).unwrap();
        for name in names {
            rows.push(row(name)).unwrap();
        }
        assert_eq!((rows.len(), rows.is_empty()), (3, false));
        assert!(Rows::new().is_empty());
        // No row is taken beyond the slots that were reserved.
        if rows.len() == rows.capacity() {
            assert!(rows.push(row("d")).is_err());
        }

        assert_eq!(
            serde_json::to_vec(&rows).unwrap(),
            serde_json::to_vec(&plain).unwrap()
        );
        rows.set_logical_sha256(1, Some("digest".to_owned()))
            .unwrap();
        assert_eq!(
            serde_json::to_value(&rows).unwrap()[1]["logical_sha256"],
            "digest"
        );
        assert!(rows.set_logical_sha256(3, None).is_err());
        assert!(rows.set_named_stream_logical_sha256(0, 0, None).is_err());

        let mut seen = Vec::new();
        rows.for_each(|index, row| {
            seen.push((index, row.components[0].clone()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (0, "a".to_owned()),
                (1, "b".to_owned()),
                (2, "c".to_owned())
            ]
        );
        // The first error ends the walk and is what the walk returns.
        let mut visited = 0;
        let stopped = rows.for_each(|index, _| {
            visited += 1;
            if index == 1 {
                Err(invalid("stop"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            (visited, stopped.unwrap_err().to_string()),
            (2, "stop".to_owned())
        );

        assert_eq!(
            rows.with(2, |row| Ok(row.components[0].clone())).unwrap(),
            "c"
        );
        let refused = rows.with(3, |_| Ok(())).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    }
}
