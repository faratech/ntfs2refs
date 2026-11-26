//! The system's upper-case table, as NTFS's `$UpCase` holds it on a volume
//! Windows formats: one UTF-16 unit for each of the 65,536, each the
//! system's own upper-case mapping (`RtlUpcaseUnicodeChar`). chkdsk holds a
//! volume's `$UpCase` to it ("Correcting errors in the uppercase file").

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlUpcaseUnicodeChar(source: u16) -> u16;
}

/// The 65,536 mappings, in order.
#[cfg(windows)]
pub fn system() -> Vec<u16> {
    (0..=u16::MAX)
        // SAFETY: a lookup of one 16-bit value in the loaded NLS table; no
        // pointers, no state.
        .map(|unit| unsafe { RtlUpcaseUnicodeChar(unit) })
        .collect()
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn the_system_table_maps_ascii_and_is_idempotent() {
        let table = super::system();
        assert_eq!(table.len(), 65536);
        for c in b'a'..=b'z' {
            assert_eq!(table[usize::from(c)], u16::from(c - 32));
        }
        // NTFS's name order needs upper-casing to be idempotent.
        assert!((0..table.len()).all(|i| table[usize::from(table[i])] == table[i]));
    }
}
