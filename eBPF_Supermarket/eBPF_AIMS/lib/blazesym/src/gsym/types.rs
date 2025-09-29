use crate::util::Pod;

pub const GSYM_MAGIC: u32 = 0x4753594d;
pub const GSYM_VERSION: u16 = 1;


/// GSYM File Header
pub struct Header {
    pub magic: u32,
    pub version: u16,
    pub addr_off_size: u8,
    pub uuid_size: u8,
    pub base_address: u64,
    pub num_addrs: u32,
    pub strtab_offset: u32,
    pub strtab_size: u32,
    pub uuid: [u8; 20],
}

#[repr(C)]
pub struct FileInfo {
    pub directory: u32,
    pub filename: u32,
}

// SAFETY: `FileInfo` is valid for any bit pattern.
unsafe impl Pod for FileInfo {}

pub struct AddrInfo<'a> {
    pub size: u32,
    pub name: u32,
    /// The raw data comprises a list of [`AddrData`].
    pub data: &'a [u8],
}

pub struct AddrData<'a> {
    /// The data type. Its value should be one of `INFO_TYPE_*`.
    pub typ: u32,
    pub length: u32,
    pub data: &'a [u8],
}

pub const INFO_TYPE_END_OF_LIST: u32 = 0;
pub const INFO_TYPE_LINE_TABLE_INFO: u32 = 1;
pub const INFO_TYPE_INLINE_INFO: u32 = 2;
