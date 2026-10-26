// Synthetic image shared by internal-policy unit and integration tests.
#[allow(dead_code, reason = "shared synthetic NTFS fixtures")]
#[path = "mod.rs"]
mod support;
pub(crate) const MFT: usize = 4 * 4096;
pub(crate) const ID: [u8; 16] = [
    0xd0, 0xfc, 0xc3, 0x59, 0xa4, 0x62, 0x87, 0x4f, 0xb8, 0xf1, 0xba, 0xa2, 0x1b, 0xc3, 0x95, 0xb9,
];

fn name(text: &str, parent: u64) -> Vec<u8> {
    let units: Vec<_> = text.encode_utf16().collect();
    let mut bytes = vec![0; 66 + 2 * units.len()];
    bytes[..8].copy_from_slice(&((1u64 << 48) | parent).to_le_bytes());
    bytes[64] = units.len() as u8;
    bytes[65] = 1;
    for (i, unit) in units.iter().enumerate() {
        bytes[66 + 2 * i..68 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    support::resident(0x30, "", &bytes, 1)
}
fn root(collation: u32, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut rows = Vec::new();
    for (key, value) in entries {
        let data = (16 + key.len() + 7) & !7;
        let length = (data + value.len() + 7) & !7;
        let at = rows.len();
        rows.resize(at + length, 0);
        rows[at..at + 2].copy_from_slice(&(data as u16).to_le_bytes());
        rows[at + 2..at + 4].copy_from_slice(&(value.len() as u16).to_le_bytes());
        rows[at + 8..at + 10].copy_from_slice(&(length as u16).to_le_bytes());
        rows[at + 10..at + 12].copy_from_slice(&(key.len() as u16).to_le_bytes());
        rows[at + 16..at + 16 + key.len()].copy_from_slice(key);
        rows[at + data..at + data + value.len()].copy_from_slice(value);
    }
    let terminal = rows.len();
    rows.resize(terminal + 16, 0);
    rows[terminal + 8] = 16;
    rows[terminal + 12] = 2;
    let mut bytes = vec![0; 32];
    bytes[4..8].copy_from_slice(&collation.to_le_bytes());
    bytes[8..12].copy_from_slice(&4096u32.to_le_bytes());
    bytes[12] = 1;
    bytes[16] = 16;
    let used = (16 + rows.len()) as u32;
    bytes[20..24].copy_from_slice(&used.to_le_bytes());
    bytes[24..28].copy_from_slice(&used.to_le_bytes());
    bytes.extend(rows);
    bytes
}
pub(crate) fn index_value(record: u64, sequence: u16) -> Vec<u8> {
    let mut bytes = vec![0; 56];
    bytes[..8].copy_from_slice(&((u64::from(sequence) << 48) | record).to_le_bytes());
    bytes
}
pub(crate) fn fixture(
    volume_id: Option<&[u8]>,
    entries: &[(Vec<u8>, Vec<u8>)],
    user_id: bool,
) -> Vec<u8> {
    let mut bytes = support::image();
    let mut bitmap = [0u8; 3];
    for n in [0usize, 3, 5, 6, 11, 16, 17, 18, 19] {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    let mut put = |n: usize, attributes: Vec<Vec<u8>>, directory: bool, sequence: u16| {
        let mut record = support::record(&attributes, if directory { 3 } else { 1 }, 1);
        record[16..18].copy_from_slice(&sequence.to_le_bytes());
        bytes[MFT + n * 1024..MFT + (n + 1) * 1024].copy_from_slice(&record);
    };
    put(
        0,
        vec![
            support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5),
            support::resident(0xb0, "", &bitmap, 1),
        ],
        false,
        1,
    );
    let mut volume = vec![0; 12];
    volume[8] = 3;
    volume[9] = 1;
    let mut attrs = vec![name("$Volume", 5), support::resident(0x70, "", &volume, 5)];
    if let Some(id) = volume_id {
        attrs.push(support::resident(0x40, "", id, 6));
    }
    put(3, attrs, false, 3);
    put(11, vec![name("$Extend", 5)], true, 1);
    put(
        17,
        vec![
            name("$ObjId", 11),
            support::resident(0x90, "$O", &root(0x13, entries), 2),
        ],
        false,
        1,
    );
    put(
        18,
        vec![
            name("$Reparse", 11),
            support::resident(0x90, "$R", &root(0x13, &[]), 2),
        ],
        false,
        1,
    );
    let mut quotas = vec![0; 48];
    quotas[..4].copy_from_slice(&2u32.to_le_bytes());
    quotas[4..8].copy_from_slice(&1u32.to_le_bytes());
    quotas[24..40].fill(0xff);
    put(
        19,
        vec![
            name("$Quota", 11),
            support::resident(0x90, "$O", &root(0x11, &[]), 2),
            support::resident(
                0x90,
                "$Q",
                &root(0x10, &[(1u32.to_le_bytes().to_vec(), quotas)]),
                3,
            ),
        ],
        false,
        1,
    );
    if user_id {
        put(
            16,
            vec![
                name("user.bin", 5),
                support::resident(0x80, "", b"user", 3),
                support::resident(0x40, "", &ID, 6),
            ],
            false,
            1,
        );
    }
    bytes
}
