//! Bounds validation for a Windows SECURITY_DESCRIPTOR_RELATIVE before native
//! code can follow its offsets. No ACL, control flag, SID, ACE or application
//! bytes are rewritten. This validates layout, not access decisions or claims.
//!
//! Layouts follow Microsoft's SECURITY_DESCRIPTOR_RELATIVE, SID, ACL, ACE_HEADER
//! and documented ordinary/object/callback/system ACE structures. Application
//! data in callback, resource-attribute and access-filter ACEs stays opaque.
use serde::Serialize;
use std::io;

pub const MAX_DESCRIPTOR_BYTES: usize = 65_536;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_BYTES: usize = 20;
const MAX_ACES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Absent,
    Null,
    Present,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SidRange {
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AclLayout {
    pub presence: Presence,
    /// None for both Absent and Null; inspect presence before choosing a native
    /// security-information mask. An absent ACL is not a null ACL setter.
    pub offset: Option<usize>,
    pub length: usize,
    pub revision: Option<u8>,
    pub ace_count: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Layout {
    pub control: u16,
    pub rm_control: Option<u8>,
    pub owner: Option<SidRange>,
    pub group: Option<SidRange>,
    pub dacl: AclLayout,
    pub sacl: AclLayout,
    /// Includes complete declared ACL storage, including any unused capacity.
    /// Trailing descriptor padding is allowed and remains unchanged.
    pub minimum_length: usize,
}
impl Layout {
    pub fn dacl_protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }
    pub fn sacl_protected(&self) -> bool {
        self.control & SE_SACL_PROTECTED != 0
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn span(bytes: &[u8], offset: usize, length: usize, limit: usize) -> io::Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= limit && *end <= bytes.len())
        .ok_or_else(|| invalid("security component exceeds its enclosing bounds"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("security component range is invalid"))
}
fn word(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        span(bytes, offset, 2, bytes.len())?.try_into().unwrap(),
    ))
}
fn dword(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        span(bytes, offset, 4, bytes.len())?.try_into().unwrap(),
    ))
}
fn component_offset(bytes: &[u8], field: usize) -> io::Result<Option<usize>> {
    let offset = dword(bytes, field)? as usize;
    if offset == 0 {
        return Ok(None);
    }
    if offset < HEADER_BYTES || !offset.is_multiple_of(4) || offset >= bytes.len() {
        return Err(invalid(
            "unaligned or out-of-bounds self-relative security offset",
        ));
    }
    Ok(Some(offset))
}
fn sid(bytes: &[u8], offset: usize, limit: usize) -> io::Result<SidRange> {
    let prefix = span(bytes, offset, 8, limit)?;
    if prefix[0] != 1 || prefix[1] > 15 {
        return Err(invalid("unsupported SID revision or subauthority count"));
    }
    let length = 8 + usize::from(prefix[1]) * 4;
    span(bytes, offset, length, limit)?;
    Ok(SidRange { offset, length })
}

fn ace(bytes: &[u8], start: usize, acl_end: usize, acl_revision: u8) -> io::Result<usize> {
    let header = span(bytes, start, 8, acl_end)?;
    let kind = header[0];
    let size = usize::from(u16::from_le_bytes(header[2..4].try_into().unwrap()));
    if size < 16 || !size.is_multiple_of(4) || !matches!(kind, 0..=3 | 5..=21) {
        return Err(invalid("unsupported ACE kind or invalid ACE length"));
    }
    // Reject every unknown layout before letting Windows follow its fields.
    // Type 4 (compound ACE) is intentionally outside the source parser profile.
    span(bytes, start, size, acl_end)?;
    let end = start + size;
    let object = matches!(kind, 5..=8 | 11 | 12 | 15 | 16);
    let application = matches!(kind, 9..=16 | 18 | 21);
    let mut sid_offset = start + 8;
    if object {
        if acl_revision != 4 {
            return Err(invalid("object ACE requires ACL revision four"));
        }
        let flags = u32::from_le_bytes(span(bytes, start + 8, 4, end)?.try_into().unwrap());
        if flags & !3 != 0 {
            return Err(invalid("unknown object ACE GUID flags"));
        }
        sid_offset = start + 12;
        for flag in [1, 2] {
            if flags & flag != 0 {
                span(bytes, sid_offset, 16, end)?;
                sid_offset += 16;
            }
        }
    }
    let trustee = sid(bytes, sid_offset, end)?;
    let sid_end = trustee.offset + trustee.length;
    if !application && sid_end != end {
        return Err(invalid("non-application ACE has bytes beyond its SID"));
    }
    // Application/condition/claim bytes remain inside this checked ACE span.
    // They are preserved verbatim, never interpreted or normalized here.
    Ok(end)
}

fn acl(bytes: &[u8], field: usize, present: bool) -> io::Result<AclLayout> {
    let offset = component_offset(bytes, field)?;
    if !present {
        if offset.is_some() {
            return Err(invalid("absent ACL has a nonzero relative offset"));
        }
        return Ok(AclLayout {
            presence: Presence::Absent,
            offset: None,
            length: 0,
            revision: None,
            ace_count: 0,
        });
    }
    let Some(offset) = offset else {
        return Ok(AclLayout {
            presence: Presence::Null,
            offset: None,
            length: 0,
            revision: None,
            ace_count: 0,
        });
    };
    let header = span(bytes, offset, 8, bytes.len())?;
    let revision = header[0];
    let length = usize::from(u16::from_le_bytes(header[2..4].try_into().unwrap()));
    let count = u16::from_le_bytes(header[4..6].try_into().unwrap());
    if !matches!(revision, 2 | 4)
        || header[1] != 0
        || header[6..8] != [0; 2]
        || length < 8
        || !length.is_multiple_of(4)
        || usize::from(count) > MAX_ACES
    {
        return Err(invalid(
            "invalid ACL revision, size, count or reserved header",
        ));
    }
    span(bytes, offset, length, bytes.len())?;
    let end = offset + length;
    let mut cursor = offset + 8;
    for _ in 0..count {
        cursor = ace(bytes, cursor, end, revision)?;
    }
    Ok(AclLayout {
        presence: Presence::Present,
        offset: Some(offset),
        length,
        revision: Some(revision),
        ace_count: count,
    })
}

/// Validate all pointer-bearing components of a bounded self-relative SD.
/// A valid layout is not proof of source provenance, successful native restore,
/// or the semantics of opaque conditions/claims. Native validity and exact
/// kernel/API descriptor readback remain independent requirements.
pub fn validate(bytes: &[u8]) -> io::Result<Layout> {
    if !(HEADER_BYTES..=MAX_DESCRIPTOR_BYTES).contains(&bytes.len())
        || !bytes.len().is_multiple_of(4)
        || bytes[0] != 1
    {
        return Err(invalid(
            "security descriptor size, alignment or revision differs",
        ));
    }
    let control = word(bytes, 2)?;
    if control & SE_SELF_RELATIVE == 0 || (control & SE_RM_CONTROL_VALID == 0 && bytes[1] != 0) {
        return Err(invalid(
            "security descriptor is not valid relative/RM-control form",
        ));
    }
    let owner = component_offset(bytes, 4)?
        .map(|offset| sid(bytes, offset, bytes.len()))
        .transpose()?;
    let group = component_offset(bytes, 8)?
        .map(|offset| sid(bytes, offset, bytes.len()))
        .transpose()?;
    let sacl = acl(bytes, 12, control & SE_SACL_PRESENT != 0)?;
    let dacl = acl(bytes, 16, control & SE_DACL_PRESENT != 0)?;
    let mut minimum_length = HEADER_BYTES;
    for range in [owner, group].into_iter().flatten() {
        minimum_length = minimum_length.max(range.offset + range.length);
    }
    for acl in [sacl, dacl] {
        if let Some(offset) = acl.offset {
            minimum_length = minimum_length.max(offset + acl.length);
        }
    }
    Ok(Layout {
        control,
        rm_control: (control & SE_RM_CONTROL_VALID != 0).then_some(bytes[1]),
        owner,
        group,
        dacl,
        sacl,
        minimum_length,
    })
}
