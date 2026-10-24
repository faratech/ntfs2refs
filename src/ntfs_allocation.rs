//! Pure consistency assessment of supplied NTFS attribute intervals and a bitmap.
//! No source parsing, source authentication, certificate, or write authority.
//! Cluster units are relative to an independently established bitmap domain.

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeKey {
    pub record_number: u64,
    pub sequence_number: u16,
    pub type_code: u32,
    pub name_utf16: Vec<u16>,
    pub instance: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalInterval {
    pub owner: AttributeKey,
    pub vcn_start: u64,
    pub lcn_start: u64,
    pub clusters: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_intervals: usize,
    pub max_bitmap_bytes: usize,
    pub max_cluster_checks: u64,
    pub max_total_name_units: usize,
    pub max_sort_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_intervals: 4096,
            max_bitmap_bytes: 2 * 1024 * 1024,
            max_cluster_checks: 16 * 1024 * 1024,
            max_total_name_units: 16 * 1024,
            max_sort_bytes: 4096 * std::mem::size_of::<usize>(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    EmptyDomain,
    BudgetExceeded(&'static str),
    BitmapLength {
        expected: usize,
        actual: usize,
    },
    InvalidOwner {
        input: usize,
    },
    EmptyInterval {
        input: usize,
    },
    Overflow {
        input: usize,
        coordinate: &'static str,
    },
    OutsideDomain {
        input: usize,
    },
    VcnOverlap {
        first: usize,
        second: usize,
    },
    PhysicalOverlap {
        first: usize,
        second: usize,
        lcn: u64,
    },
    ClaimedFree {
        input: usize,
        lcn: u64,
    },
    AllocatedUnowned {
        lcn: u64,
    },
    AllocationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Consistency {
    pub domain_clusters: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub physical_intervals: usize,
    pub distinct_attributes: usize,
    pub bitmap_bytes_checked: usize,
    pub cluster_checks: u64,
    /// Outside-domain padding is reported, not mistaken for volume allocation.
    pub padding_bits_set: u32,
    pub sorting_storage_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Assessment {
    /// Only the supplied interval/bitmap model reconciles. Not source admission.
    Consistent(Consistency),
    /// No partially accepted tree or ledger is returned.
    Rejected(Refusal),
}

impl Assessment {
    /// This assessment never supplies a conversion capability or certificate.
    pub fn grants_write_authority(&self) -> bool {
        false
    }
}

pub fn assess(
    domain_clusters: u64,
    bitmap: &[u8],
    intervals: &[PhysicalInterval],
    limits: Limits,
) -> Assessment {
    match reconcile(domain_clusters, bitmap, intervals, limits) {
        Ok(summary) => Assessment::Consistent(summary),
        Err(reason) => Assessment::Rejected(reason),
    }
}

fn reconcile(
    domain: u64,
    bitmap: &[u8],
    intervals: &[PhysicalInterval],
    limits: Limits,
) -> Result<Consistency, Refusal> {
    if domain == 0 {
        return Err(Refusal::EmptyDomain);
    }
    if domain > limits.max_cluster_checks {
        return Err(Refusal::BudgetExceeded("cluster checks"));
    }
    let needed = usize::try_from(domain.div_ceil(8))
        .map_err(|_| Refusal::BudgetExceeded("bitmap addressability"))?;
    if needed > limits.max_bitmap_bytes || bitmap.len() > limits.max_bitmap_bytes {
        return Err(Refusal::BudgetExceeded("bitmap bytes"));
    }
    if bitmap.len() != needed {
        return Err(Refusal::BitmapLength {
            expected: needed,
            actual: bitmap.len(),
        });
    }
    if intervals.len() > limits.max_intervals {
        return Err(Refusal::BudgetExceeded("interval count"));
    }
    let sort_bytes = intervals
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(Refusal::BudgetExceeded("sorting storage"))?;
    if sort_bytes > limits.max_sort_bytes {
        return Err(Refusal::BudgetExceeded("sorting storage"));
    }
    let mut name_units = 0usize;
    for (input, interval) in intervals.iter().enumerate() {
        let key = &interval.owner;
        if key.record_number > 0x0000_ffff_ffff_ffff
            || key.sequence_number == 0
            || key.type_code == 0
            || !key.type_code.is_multiple_of(16)
            || key.name_utf16.len() > 255
        {
            return Err(Refusal::InvalidOwner { input });
        }
        name_units = name_units
            .checked_add(key.name_utf16.len())
            .ok_or(Refusal::BudgetExceeded("attribute name units"))?;
        if name_units > limits.max_total_name_units {
            return Err(Refusal::BudgetExceeded("attribute name units"));
        }
        if interval.clusters == 0 {
            return Err(Refusal::EmptyInterval { input });
        }
        let end = interval
            .lcn_start
            .checked_add(interval.clusters)
            .ok_or(Refusal::Overflow {
                input,
                coordinate: "LCN",
            })?;
        interval
            .vcn_start
            .checked_add(interval.clusters)
            .ok_or(Refusal::Overflow {
                input,
                coordinate: "VCN",
            })?;
        if end > domain {
            return Err(Refusal::OutsideDomain { input });
        }
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(intervals.len())
        .map_err(|_| Refusal::AllocationFailed)?;
    let actual_sort_bytes = order
        .capacity()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(Refusal::BudgetExceeded("sorting storage"))?;
    if actual_sort_bytes > limits.max_sort_bytes {
        return Err(Refusal::BudgetExceeded("sorting storage"));
    }
    order.extend(0..intervals.len());
    order.sort_unstable_by(|&a, &b| {
        intervals[a]
            .owner
            .cmp(&intervals[b].owner)
            .then(intervals[a].vcn_start.cmp(&intervals[b].vcn_start))
            .then(a.cmp(&b))
    });
    let mut distinct_attributes = usize::from(!order.is_empty());
    for pair in order.windows(2) {
        let (a, b) = (&intervals[pair[0]], &intervals[pair[1]]);
        if a.owner == b.owner {
            if a.vcn_start + a.clusters > b.vcn_start {
                return Err(Refusal::VcnOverlap {
                    first: pair[0],
                    second: pair[1],
                });
            }
        } else {
            distinct_attributes += 1;
        }
    }
    order.sort_unstable_by_key(|&i| (intervals[i].lcn_start, i));
    for pair in order.windows(2) {
        let (a, b) = (&intervals[pair[0]], &intervals[pair[1]]);
        if a.lcn_start + a.clusters > b.lcn_start {
            return Err(Refusal::PhysicalOverlap {
                first: pair[0],
                second: pair[1],
                lcn: b.lcn_start,
            });
        }
    }
    let mut next = 0usize;
    let mut allocated = 0u64;
    for lcn in 0..domain {
        while next < order.len() {
            let interval = &intervals[order[next]];
            if interval.lcn_start + interval.clusters > lcn {
                break;
            }
            next += 1;
        }
        let claim = order
            .get(next)
            .copied()
            .filter(|&i| intervals[i].lcn_start <= lcn);
        let bit = bitmap[(lcn / 8) as usize] & (1 << (lcn % 8)) != 0;
        match (bit, claim) {
            (true, None) => return Err(Refusal::AllocatedUnowned { lcn }),
            (false, Some(input)) => return Err(Refusal::ClaimedFree { input, lcn }),
            (true, Some(_)) => allocated += 1,
            (false, None) => {}
        }
    }
    let valid_last_bits = (domain % 8) as u32;
    let padding_bits_set = if valid_last_bits == 0 {
        0
    } else {
        (bitmap[needed - 1] & !((1u8 << valid_last_bits) - 1)).count_ones()
    };
    Ok(Consistency {
        domain_clusters: domain,
        allocated_clusters: allocated,
        free_clusters: domain - allocated,
        physical_intervals: intervals.len(),
        distinct_attributes,
        bitmap_bytes_checked: needed,
        cluster_checks: domain,
        padding_bits_set,
        sorting_storage_bytes: actual_sort_bytes,
    })
}
