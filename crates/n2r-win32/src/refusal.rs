//! The mark of a refusal that is the converter's own decision about
//! something it read in full and understood: a reparse point of a kind it
//! does not recreate, two names in a directory that differ only by case.
//!
//! Every other error of an inspection means that a structure could not be
//! read as expected. On a frozen source the two stop a run alike. On a
//! volume that is still in use they differ: a structure that could not be
//! read may only have been caught while it changed, and a refusal that
//! carries this mark was not.
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub struct Refusal(pub String);

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for Refusal {}

/// Such a refusal as the I/O error the layout decoders return. It reads
/// exactly as `text`.
pub fn io_error(text: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Refusal(text))
}

/// Whether `error`, or anything it was caused by, carries the mark.
pub fn is_refusal(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(cause) = current {
        if cause.is::<Refusal>() {
            return true;
        }
        // An I/O error holds what it was made from beside its chain.
        if cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .is_some_and(|inner| inner.is::<Refusal>())
        {
            return true;
        }
        current = cause.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mark_is_found_through_an_io_error_and_reads_as_its_text() {
        let refusal = io_error("a reparse point of tag 0x80000017 is not recreated".into());
        assert_eq!(
            refusal.to_string(),
            "a reparse point of tag 0x80000017 is not recreated"
        );
        assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
        assert!(is_refusal(&refusal));
        assert!(is_refusal(&Refusal("two names differ only by case".into())));

        // A structure that could not be read is not one.
        let unread = io::Error::new(io::ErrorKind::InvalidData, "invalid INDX signature/size");
        assert!(!is_refusal(&unread));
        assert!(!is_refusal(&io::Error::from_raw_os_error(5)));
    }
}
