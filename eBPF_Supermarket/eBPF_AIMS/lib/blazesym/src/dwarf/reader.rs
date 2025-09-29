use gimli::EndianSlice;
use gimli::SectionId;

use crate::elf::ElfParser;
use crate::Result;


#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;

/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(crate) type R<'dat> = EndianSlice<'dat, Endianess>;


pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    let result = parser.find_section(id.name())?;
    let data = match result {
        Some(idx) => parser.section_data(idx)?,
        // Make sure to return empty data if a section does not exist.
        None => &[],
    };

    #[cfg(target_endian = "little")]
    let reader = EndianSlice::new(data, gimli::LittleEndian);
    #[cfg(target_endian = "big")]
    let reader = EndianSlice::new(data, gimli::BigEndian);
    Ok(reader)
}
