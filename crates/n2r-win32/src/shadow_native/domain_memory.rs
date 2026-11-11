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
// edges. Charge three complete internal nodes per insertion, covering a split
// and root growth, as well as each retained heap key and its temporary copy.
fn node(key: usize, value: usize) -> io::Result<u64> {
    mul(
        add(
            256,
            mul(16, (key + value + mem::size_of::<usize>()) as u64)?,
        )?,
        3,
    )
}
fn path_heap(path: &[String]) -> io::Result<u64> {
    path.iter().try_fold(
        mul(path.len() as u64, mem::size_of::<String>() as u64)?,
        |n, part| add(n, part.len() as u64),
    )
}
pub(super) fn input_plan(input: &impl InputDomain) -> io::Result<InputPlan> {
    let mut source_ranges = 0usize;
    let mut preflight = 4096u64;
    let mut validation = add(
        4096,
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
            // Unicode uppercase may expand scalars and String growth may keep
            // spare capacity. This also covers join/key lookup temporaries.
            let folded = add(mul(heap, 24)?, 256)?;
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
                add(mul(named.name_utf16.len() as u64, 48)?, folded_node)?,
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
