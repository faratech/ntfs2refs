use super::*;

pub(super) fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("resource preparation size overflow"))
}
pub(super) fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("resource preparation size overflow"))
}
pub(super) fn count(value: &impl Serialize) -> io::Result<u64> {
    struct Count(u64);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 = add(self.0, b.len() as u64)?;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut size = Count(0);
    serde_json::to_writer(&mut size, value).map_err(io::Error::other)?;
    Ok(size.0)
}
pub(super) fn query_bytes(budget: ResourceBudget) -> io::Result<u64> {
    add(mul(budget.max_row_bytes, 8)?, 2 * 1024 * 1024)
}
pub(super) fn window_cluster_capacity(budget: ResourceBudget) -> io::Result<u64> {
    let returned = budget.max_row_bytes / 4;
    require(
        returned >= 17 && budget.max_row_bytes / 1024 > 0,
        "resource NTFS bitmap has no complete response space",
    )?;
    // Every complete bitmap response includes a 16-byte native header. This
    // is a request ceiling, not a prediction of driver rounding or paging;
    // the live collector must independently close every requested bit.
    mul((budget.max_row_bytes / 4).min(returned - 16), 8)
}
pub(super) fn window_limits(
    clusters: u32,
    budget: ResourceBudget,
) -> io::Result<bitmap_window::Limits> {
    let bytes = usize::try_from(u64::from(clusters).div_ceil(8)).map_err(io::Error::other)?;
    let returned = usize::try_from(budget.max_row_bytes / 4).map_err(io::Error::other)?;
    let pages = usize::try_from(budget.max_row_bytes / 1024).map_err(io::Error::other)?;
    require(
        clusters > 0
            && u64::from(clusters) <= window_cluster_capacity(budget)?
            && returned >= 17
            && pages > 0,
        "requested NTFS bitmap window exceeds resource working space",
    )?;
    Ok(bitmap_window::Limits {
        max_window_bytes: bytes,
        max_pages: pages,
        max_returned_bytes: returned,
        page_bytes: (budget.page_bytes as usize)
            .min(crate::bitmap_paging::PAGE_BYTES)
            .max(17),
    })
}
pub(super) fn move_bytes(budget: ResourceBudget, window: bitmap_window::Limits) -> io::Result<u64> {
    let queries = mul(budget.max_row_bytes, 16)?;
    add(
        add(
            add(queries, mul(window.max_returned_bytes as u64, 8)?)?,
            mul(window.max_pages as u64, 1024)?,
        )?,
        4 * 1024 * 1024,
    )
}
pub(super) fn complete_proof_bound(
    budget: ResourceBudget,
    request: &MoveRequest,
    before: &FileObservation,
    destination: &bitmap_window::Proof,
) -> io::Result<u64> {
    let limits = retrieval_paging::Limits::for_resource_bytes(
        usize::try_from(budget.max_row_bytes).map_err(io::Error::other)?,
    )?;
    let canonical = add(16, mul(limits.max_extents as u64, 16)?)?;
    // Actual BEFORE bytes and actual lossless destination transcript, plus
    // every accepted AFTER canonical byte/page, widest scalars and five
    // bounded escaped error strings. The callback adds its own envelope.
    let actual = add(add(count(before)?, count(destination)?)?, count(request)?)?;
    let after = add(
        add(mul(canonical, 4)?, mul(limits.max_pages as u64, 4096)?)?,
        5 * 4096 * 6 + 16384,
    )?;
    add(actual, after)
}
