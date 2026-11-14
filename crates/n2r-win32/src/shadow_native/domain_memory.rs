//! Prepaid compact namespace/identity/source-placement indexes. These bounds
//! describe the pinned Rust BTree representation and actual input bytes, never
//! an object-count fixture or permission to omit validation.
use super::*;

pub(super) struct InputPlan {
    pub source_ranges: usize,
    pub preflight_bytes: u64,
    pub validation_bytes: u64,
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("native domain index RAM overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("native domain index RAM overflow"))
}

// Rust's pinned BTree nodes have eleven key/value slots and twelve child
// edges; `complete_node` is more than one of them takes, inner or leaf.
//
// Every node but the root holds five entries at least, so a tree of N
// entries has at most N/5 leaves and fewer than N/25 inner nodes: under a
// quarter of a node for an entry. A third of a complete node is charged for
// each entry. (Three complete nodes an entry were charged before, which is
// what one insertion can allocate when it splits, and nine times what the
// tree holds once the entries are in: a volume of 500,000 files was refused
// for an index of 5.5 GiB that takes some tens of megabytes.) What an
// insertion in flight allocates beyond that, and the roots of small trees,
// are in `TREES_IN_FLIGHT`, charged once.
fn complete_node(key: usize, value: usize) -> io::Result<u64> {
    add(
        256,
        mul(16, (key + value + mem::size_of::<usize>()) as u64)?,
    )
}
fn node(key: usize, value: usize) -> io::Result<u64> {
    Ok(complete_node(key, value)?.div_ceil(3))
}
/// Splits in flight and root nodes of every tree these plans pay for: far
/// more than the eight trees, each splitting at each of eight levels, take.
const TREES_IN_FLIGHT: u64 = 256 * 1024;

/// The bytes of a path joined with separators, which is what its key is
/// made from.
fn joined(path: &[String]) -> u64 {
    path.iter()
        .fold(path.len() as u64, |n, part| n + part.len() as u64)
}
/// What the uppercase key of `bytes` of UTF-8 can take on the heap. Unicode
/// uppercasing makes of one scalar at most three, and of its UTF-8 bytes
/// at most three times as many (U+0390 does); a `String` that grew by
/// pushes holds at most twice its length. The join and the keys made for a
/// lookup are freed before the next, and are in `TREES_IN_FLIGHT`.
fn folded_key(bytes: u64) -> io::Result<u64> {
    add(mul(bytes, 6)?, 64)
}
fn path_heap(path: &[String]) -> io::Result<u64> {
    path.iter().try_fold(
        mul(path.len() as u64, mem::size_of::<String>() as u64)?,
        |n, part| add(n, part.len() as u64),
    )
}
pub(super) fn input_plan(input: &impl InputDomain) -> io::Result<InputPlan> {
    let mut source_ranges = 0usize;
    let mut preflight = add(4096, TREES_IN_FLIGHT)?;
    let mut validation = add(
        add(4096, TREES_IN_FLIGHT)?,
        mul(
            input.len() as u64,
            2 * (mem::size_of::<(usize, Vec<String>, bool)>() as u64),
        )?,
    )?;
    let folded_node = node(mem::size_of::<String>(), 0)?;
    let identity_node = node(mem::size_of::<Vec<String>>(), mem::size_of::<Vec<u8>>())?;
    let parent_node = node(
        mem::size_of::<Vec<String>>(),
        mem::size_of::<std::collections::BTreeMap<Vec<u16>, (usize, u32)>>(),
    )?;
    let child_node = node(mem::size_of::<Vec<u16>>(), mem::size_of::<(usize, u32)>())?;
    let id_node = node(mem::size_of::<Vec<u8>>(), 0)?;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
        source_ranges = source_ranges
            .checked_add(usize::from(item.source_offset.is_some()))
            .and_then(|n| n.checked_add(item.source_runs.len()))
            .ok_or_else(|| invalid("source range index count overflow"))?;
        for path in hard_links::paths(&item) {
            let heap = path_heap(path)?;
            // The path's key and its entry, twice: a directory's key is
            // kept in the set of names and in the set of directories.
            let folded = folded_key(joined(path))?;
            preflight = add(preflight, mul(add(folded, folded_node)?, 2)?)?;
            validation = add(
                validation,
                add(
                    mul(heap, 6)?,
                    add(identity_node, add(parent_node, child_node)?)?,
                )?,
            )?;
        }
        validation = add(validation, add(id_node, 128)?)?;
        // Named-stream validation retains only this bounded object's names.
        let mut names = 0u64;
        for named in &item.named_streams {
            names = add(
                names,
                // A UTF-16 unit is at most three bytes of UTF-8.
                add(
                    folded_key(mul(named.name_utf16.len() as u64, 3)?)?,
                    folded_node,
                )?,
            )?;
        }
        preflight = add(preflight, names)?;
    }
    let scalar = mul(
        source_ranges as u64,
        (mem::size_of::<(u64, u64)>() as u64) * 2,
    )?;
    Ok(InputPlan {
        source_ranges,
        preflight_bytes: add(preflight, scalar)?,
        validation_bytes: validation,
    })
}
pub(super) fn validation_bytes(report: &Report, input: &impl InputDomain) -> io::Result<u64> {
    let mut bytes = input_plan(input)?.validation_bytes;
    // Directory membership's seen-name set exists for one directory at a time.
    let seen_node = node(mem::size_of::<Vec<u16>>(), 0)?;
    let mut maximum = 0u64;
    for object in &report.objects {
        let mut seen = 0u64;
        for entry in &object.namespace {
            seen = add(
                seen,
                add(mul(entry.name_utf16.len() as u64, 4)?, seen_node)?,
            )?;
        }
        maximum = maximum.max(seen);
    }
    bytes = add(bytes, maximum)?;
    Ok(bytes)
}

pub(super) fn expected_vector_bytes(
    objects: usize,
    pair: &GeneralSourceShadowBinding,
) -> io::Result<u64> {
    let mut bytes = mul(
        objects as u64,
        2 * (mem::size_of::<Option<String>>() as u64 + 64),
    )?;
    for binding in [&pair.source, &pair.shadow] {
        bytes = add(
            bytes,
            add(
                binding.volume_guid.len() as u64,
                add(
                    binding.identity.disk_guid.len() as u64,
                    binding.identity.partition_guid.len() as u64,
                )?,
            )?,
        )?;
    }
    add(bytes, 4096)
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn a_keys_charge_covers_the_key_whatever_its_letters() {
        // ASCII, letters that uppercase into more letters, and the scalar
        // whose uppercase takes three times its bytes.
        for name in [
            "file-0000001.dat",
            "stra\u{df}e",
            "\u{fb03}",
            "\u{149}",
            "\u{390}\u{390}\u{390}\u{390}",
        ] {
            for depth in [1usize, 4, 16] {
                let path = vec![name.to_owned(); depth];
                let key = crate::shadow_names::conservative_path_key(&path);
                let charged = folded_key(joined(&path)).unwrap();
                assert!(
                    key.capacity() as u64 <= charged,
                    "{name:?} x{depth}: a key of capacity {} was charged {charged}",
                    key.capacity()
                );
            }
        }
    }

    #[test]
    fn an_entry_is_charged_more_than_its_share_of_the_tree() {
        // N entries fill at most N/5 leaves and fewer than N/25 inner
        // nodes, each smaller than a complete node: 0.24 of one an entry.
        for (key, value) in [(24usize, 0usize), (24, 24), (24, 16)] {
            let complete = complete_node(key, value).unwrap();
            // An inner node: eleven slots, twelve edges, its header.
            assert!(complete >= (11 * (key + value) + 12 * 8 + 16) as u64);
            let entry = node(key, value).unwrap();
            assert!(entry * 100 >= complete * 24, "{entry} of {complete}");
            // And the charge for a million entries stays what it says.
            assert!(entry <= complete.div_ceil(3));
        }
        // The roots and the splits in flight: eight trees, eight levels.
        assert!(TREES_IN_FLIGHT >= 8 * 8 * 3 * complete_node(24, 24).unwrap());
    }

    #[test]
    fn half_a_million_paths_are_charged_megabytes_not_gigabytes() {
        // The lab's volume: paths of four components and 41 bytes.
        let path = [
            "feature-manyfiles".to_owned(),
            "04".to_owned(),
            "00499".to_owned(),
            "file-0499999.dat".to_owned(),
        ];
        let entry = 2 * (folded_key(joined(&path)).unwrap() + node(24, 0).unwrap());
        assert!(entry < 1400, "{entry} bytes a path");
        assert!(500_000 * entry < 700 << 20);
    }
}
