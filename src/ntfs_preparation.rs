//! Optional NTFS-owned collision preparation before the converter's freeze.
//! Every later inspection/certificate is obtained anew; this plan/log cannot
//! authorize raw conversion or recovery. NTFS performs and journals all moves.
pub(crate) mod resource;
