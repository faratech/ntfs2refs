//! LZNT1 chunk decoding, against vectors built by hand from the format in
//! MS-XCA 2.5: a two-byte chunk header (low 12 bits: stored size minus one;
//! bits 12-14: signature 3; bit 15: compressed), then for a compressed chunk
//! groups of one flag byte and up to eight elements, each a literal byte or a
//! two-byte match whose length/distance split depends on the position reached.
use ntfs2refs::ntfs_compression::decode_lznt1;

/// A compressed chunk holding `payload` (flag groups).
fn compressed(payload: &[u8]) -> Vec<u8> {
    let header = 0xb000u16 | (payload.len() as u16 - 1);
    [header.to_le_bytes().as_slice(), payload].concat()
}

/// A stored (uncompressed) chunk holding `data`.
fn stored(data: &[u8]) -> Vec<u8> {
    let header = 0x3000u16 | (data.len() as u16 - 1);
    [header.to_le_bytes().as_slice(), data].concat()
}

fn decode(input: &[u8], room: usize) -> anyhow::Result<Vec<u8>> {
    let mut output = vec![0xee; room];
    let produced = decode_lznt1(input, &mut output)?;
    output.truncate(produced);
    Ok(output)
}

#[test]
fn a_stored_chunk_is_copied_and_a_zero_header_ends_the_stream() {
    let data: Vec<u8> = (0..4096u32).map(|n| (n % 251) as u8).collect();
    let mut input = stored(&data);
    input.extend_from_slice(&[0, 0, 0xaa, 0xbb]); // terminator, then slack that is never read
    assert_eq!(decode(&input, 65536).unwrap(), data);
}

#[test]
fn literals_and_an_overlapping_match_expand_a_run() {
    // Flags 0b10: a literal, then a match. One byte in, the token keeps 12
    // length bits: distance 1, length 11 -> twelve 'a' in all.
    let input = compressed(&[0b10, b'a', 0x08, 0x00]);
    assert_eq!(decode(&input, 65536).unwrap(), b"aaaaaaaaaaaa");
}

#[test]
fn the_length_and_distance_split_moves_with_the_position_in_the_chunk() {
    // Seventeen literals, then a match. Past sixteen bytes the token keeps
    // eleven length bits, so distance 17 with length 3 is (16 << 11) | 0.
    let literals: Vec<u8> = (b'a'..=b'q').collect();
    assert_eq!(literals.len(), 17);
    let mut payload = vec![0x00];
    payload.extend_from_slice(&literals[..8]);
    payload.push(0x00);
    payload.extend_from_slice(&literals[8..16]);
    payload.extend_from_slice(&[0b10, literals[16], 0x00, 0x80]);
    let expected = [literals.as_slice(), b"abc"].concat();
    assert_eq!(decode(&compressed(&payload), 65536).unwrap(), expected);

    // The same token read with twelve length bits would be distance 9, length
    // 3: placed after only eight literals it copies from before the chunk.
    let mut early = vec![0x00];
    early.extend_from_slice(&literals[..8]);
    early.extend_from_slice(&[0b01, 0x00, 0x80]);
    let error = decode(&compressed(&early), 65536).unwrap_err();
    assert!(
        error.to_string().contains("precedes chunk start"),
        "{error:#}"
    );
}

#[test]
fn full_chunks_follow_one_another_and_only_the_last_may_be_short() {
    // 4,096 'A' as one literal and one maximal match, then 904 'B'.
    let first = compressed(&[0b10, b'A', 0xfc, 0x0f]);
    let second = compressed(&[0b10, b'B', 0x84, 0x03]);
    let input = [first.as_slice(), second.as_slice(), &[0, 0]].concat();
    let output = decode(&input, 65536).unwrap();
    assert_eq!(output.len(), 5000);
    assert!(output[..4096].iter().all(|byte| *byte == b'A'));
    assert!(output[4096..].iter().all(|byte| *byte == b'B'));

    // A short chunk followed by another chunk has no defined placement.
    let misplaced = [second.as_slice(), first.as_slice()].concat();
    let error = decode(&misplaced, 65536).unwrap_err();
    assert!(error.to_string().contains("short output"), "{error:#}");
}

#[test]
fn malformed_streams_are_refused_and_output_never_exceeds_its_room() {
    for (input, message) in [
        // Signature bits are not 3.
        (
            vec![0x03, 0x80, 0, 0, 0, 0],
            "invalid LZNT1 chunk signature",
        ),
        // The header promises four payload bytes; two follow.
        (
            vec![0x03, 0xb0, 0b10, b'a'],
            "truncated LZNT1 chunk payload",
        ),
        // A flag byte with nothing after it.
        (compressed(&[0b10]), "flag group has no elements"),
        // A match token cut in half.
        (
            compressed(&[0b10, b'a', 0x08]),
            "truncated LZNT1 match token",
        ),
        // A lone header byte.
        (vec![0x03], "truncated LZNT1 chunk header"),
    ] {
        let error = decode(&input, 65536).unwrap_err();
        assert!(error.to_string().contains(message), "{message}: {error:#}");
    }
    // Twelve bytes do not fit in eight.
    let error = decode(&compressed(&[0b10, b'a', 0x08, 0x00]), 8).unwrap_err();
    assert!(
        error.to_string().contains("exceeds chunk output"),
        "{error:#}"
    );
    // Nothing at all decodes to nothing.
    assert!(decode(&[], 16).unwrap().is_empty());
    assert!(decode(&[0, 0], 16).unwrap().is_empty());
}

fn geometry(cluster: u32, volume: u64) -> ntfs2refs::ntfs_inspect::NtfsGeometry {
    ntfs2refs::ntfs_inspect::NtfsGeometry {
        bytes_per_sector: 512,
        sectors_per_cluster: cluster / 512,
        cluster_size: cluster,
        total_sectors: volume / 512,
        volume_size: volume,
        total_clusters: volume / u64::from(cluster),
        mft_lcn: 4,
        mftmirr_lcn: 8,
        file_record_size: 1024,
        index_record_size: 4096,
        serial_number: 1,
    }
}

/// NTFS compresses in units of sixteen clusters whatever the cluster size:
/// 8 KiB units on 512-byte clusters up to 64 KiB units on 4 KiB clusters.
/// One stream holds a unit stored raw, a unit encoded into one cluster with
/// the rest of it padding, and a raw tail that ends at EOF.
#[test]
fn a_compressed_stream_reads_the_same_on_every_cluster_size_ntfs_compresses_on() {
    use ntfs2refs::ntfs_compression::{Reader, supported};
    use ntfs2refs::ntfs_inspect::{AttributeInventory, Extent};
    for cluster in [512u64, 1024, 2048, 4096] {
        let unit = 16 * cluster;
        let tail = 3 * cluster + 17;
        let logical = 2 * unit + tail;
        // The logical content: a pattern, then one letter per 4096 bytes,
        // then a second pattern.
        let raw: Vec<u8> = (0..unit).map(|n| (n % 251) as u8).collect();
        let chunks = (unit / 4096) as u8;
        let mut encoded = Vec::new();
        let mut letters = Vec::new();
        for chunk in 0..chunks {
            // A literal, then a match of 4095 bytes one byte back.
            encoded.extend(compressed(&[0b10, b'a' + chunk, 0xfc, 0x0f]));
            letters.extend(std::iter::repeat_n(b'a' + chunk, 4096));
        }
        assert!(encoded.len() as u64 <= cluster);
        let last: Vec<u8> = (0..tail).map(|n| (n % 241) as u8 ^ 0x55).collect();
        let expected = [raw.as_slice(), &letters, &last].concat();
        assert_eq!(expected.len() as u64, logical);

        // The volume: each run somewhere of its own, on cluster boundaries.
        let (at_raw, at_encoded, at_last) = (64 * cluster, 100 * cluster, 130 * cluster);
        let volume = 256 * cluster;
        let mut image = vec![0xee; volume as usize];
        image[at_raw as usize..(at_raw + unit) as usize].copy_from_slice(&raw);
        image[at_encoded as usize..at_encoded as usize + encoded.len()].copy_from_slice(&encoded);
        image[at_encoded as usize + encoded.len()..(at_encoded + cluster) as usize].fill(0);
        image[at_last as usize..at_last as usize + last.len()].copy_from_slice(&last);
        let run = |logical_offset, physical_offset, length| Extent {
            logical_offset,
            physical_offset,
            length,
        };
        let attribute = AttributeInventory {
            type_code: 0x80,
            instance: 1,
            name_utf16: vec![],
            flags: 1,
            resident: false,
            logical_size: logical,
            initialized_size: logical,
            allocated_size: 2 * unit + 4 * cluster,
            lowest_vcn: 0,
            compression_unit: 4,
            total_allocated_size: Some(unit + cluster + 4 * cluster),
            extents: vec![
                run(0, Some(at_raw), unit),
                run(unit, Some(at_encoded), cluster),
                run(unit + cluster, None, unit - cluster),
                run(2 * unit, Some(at_last), 4 * cluster),
            ],
            resident_sha256: None,
            resident_metadata_hex: None,
        };
        let geometry = geometry(cluster as u32, volume);
        supported(&attribute, &geometry).unwrap_or_else(|error| panic!("{cluster}: {error:#}"));
        let mut reader = Reader::new(&attribute, &geometry).unwrap();
        let mut source = std::io::Cursor::new(&image);
        let mut whole = vec![0; logical as usize];
        reader.read_range(&mut source, 0, &mut whole).unwrap();
        assert!(
            whole == expected,
            "{cluster}-byte clusters: content differs"
        );
        // A range that starts in one unit and ends in the next but one.
        let (from, length) = (unit - 5, unit + 11);
        let mut part = vec![0; length as usize];
        reader.read_range(&mut source, from, &mut part).unwrap();
        assert!(part == expected[from as usize..(from + length) as usize]);
    }
}

#[test]
fn compression_is_refused_on_clusters_ntfs_does_not_compress_on() {
    use ntfs2refs::ntfs_inspect::AttributeInventory;
    let attribute = AttributeInventory {
        type_code: 0x80,
        instance: 1,
        name_utf16: vec![],
        flags: 1,
        resident: false,
        logical_size: 0,
        initialized_size: 0,
        allocated_size: 0,
        lowest_vcn: 0,
        compression_unit: 4,
        total_allocated_size: Some(0),
        extents: vec![],
        resident_sha256: None,
        resident_metadata_hex: None,
    };
    let error =
        ntfs2refs::ntfs_compression::supported(&attribute, &geometry(8192, 1 << 24)).unwrap_err();
    assert!(
        error.to_string().contains("8192-byte clusters"),
        "{error:#}"
    );
}
