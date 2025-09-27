/// Specification of ZIP file format can be found here:
/// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
/// For a high level overview of the structure of a ZIP file see
/// sections 4.3.1 - 4.3.6.
///
/// Data structures appearing in ZIP files do not contain any
/// padding and they might be misaligned. To allow us to safely
/// operate on pointers to such structures and their members, we
/// declare the types as packed.
use std::cmp::min;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use crate::mmap::Mmap;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Error;
use crate::IntoError as _;
use crate::Result;

const CD_FILE_HEADER_MAGIC: u32 = 0x02014b50;
const END_OF_CD_RECORD_MAGIC: u32 = 0x06054b50;
const LOCAL_FILE_HEADER_MAGIC: u32 = 0x04034b50;
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_HAS_DATA_DESCRIPTOR: u16 = 1 << 3;


/// See section 4.3.16 of the spec.
#[repr(C, packed)]
struct EndOfCdRecord {
    /// Magic value equal to END_OF_CD_RECORD_MAGIC.
    magic: u32,
    /// Number of the file containing this structure or 0xFFFF if ZIP64 archive.
    /// Zip archive might span multiple files (disks).
    this_disk: u16,
    /// Number of the file containing the beginning of the central directory or
    /// 0xFFFF if ZIP64 archive.
    cd_disk: u16,
    /// Number of central directory records on this disk or 0xFFFF if ZIP64
    /// archive.
    cd_records: u16,
    /// Number of central directory records on all disks or 0xFFFF if ZIP64
    /// archive.
    cd_records_total: u16,
    /// Size of the central directory record or 0xFFFFFFFF if ZIP64 archive.
    cd_size: u32,
    /// Offset of the central directory from the beginning of the archive or
    /// 0xFFFFFFFF if ZIP64 archive.
    cd_offset: u32,
    /// Length of comment data following end of central directory record.
    comment_length: u16,
    // Up to 64k of arbitrary bytes. */
    // uint8_t comment[comment_length] */
}

// SAFETY: `EndOfCdRecord` is valid for any bit pattern.
unsafe impl Pod for EndOfCdRecord {}


/// See section 4.3.12 of the spec.
#[repr(C, packed)]
struct CdFileHeader {
    /// Magic value equal to CD_FILE_HEADER_MAGIC.
    magic: u32,
    version: u16,
    /// Minimum zip version needed to extract the file.
    min_version: u16,
    flags: u16,
    compression: u16,
    last_modified_time: u16,
    last_modified_date: u16,
    crc: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,
    file_comment_length: u16,
    /// Number of the disk where the file starts or 0xFFFF if ZIP64 archive.
    disk: u16,
    internal_attributes: u16,
    external_attributes: u32,
    /// Offset from the start of the disk containing the local file header to the
    /// start of the local file header.
    offset: u32,
}

// SAFETY: `CdFileHeader` is valid for any bit pattern.
unsafe impl Pod for CdFileHeader {}


/// See section 4.3.7 of the spec.
#[repr(C, packed)]
struct LocalFileHeader {
    /// Magic value equal to LOCAL_FILE_HEADER_MAGIC.
    magic: u32,
    /// Minimum zip version needed to extract the file.
    min_version: u16,
    flags: u16,
    compression: u16,
    last_modified_time: u16,
    last_modified_date: u16,
    crc: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,
}

// SAFETY: `LocalFileHeader` is valid for any bit pattern.
unsafe impl Pod for LocalFileHeader {}


/// Carries information on path, compression method, and data corresponding to a
/// file in a zip archive.
pub struct Entry<'archive> {
    /// Compression method as defined in pkzip spec. 0 means data is uncompressed.
    pub compression: u16,
    /// The path to the file inside the archive.
    pub path: &'archive Path,
    /// The offset of the data from the beginning of the archive.
    pub data_offset: u64,
    /// Pointer to the file data.
    pub data: &'archive [u8],
}

impl Debug for Entry<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Entry {
            compression,
            path,
            data_offset,
            data,
        } = self;

        f.debug_struct(stringify!(Entry))
            .field("compression", compression)
            .field("path", path)
            .field("data_offset", data_offset)
            .field("data", &data.get(0..(min(data.len(), 32))))
            .finish()
    }
}


/// An iterator over the entries of an [`Archive`].
pub struct EntryIter<'archive> {
    /// The data of the archive.
    archive_data: &'archive [u8],
    /// Pointer to the central directory records.
    ///
    /// This read pointer will be advanced as entries are read.
    cd_record_data: &'archive [u8],
    /// The number of remaining records.
    remaining_records: u16,
}

impl<'archive> EntryIter<'archive> {
    fn parse_entry_at_offset(data: &[u8], offset: u32) -> Result<Entry<'_>> {
        fn entry_impl(data: &[u8], offset: u32) -> Option<Result<Entry<'_>>> {
            let mut data = data.get(offset as usize..)?;
            let start = data.as_ptr();

            let lfh = data.read_pod::<LocalFileHeader>()?;
            if lfh.magic != LOCAL_FILE_HEADER_MAGIC {
                return Some(Err(Error::with_invalid_data(
                    "local file header contains invalid magic number",
                )))
            }

            if (lfh.flags & FLAG_ENCRYPTED) != 0 || (lfh.flags & FLAG_HAS_DATA_DESCRIPTOR) != 0 {
                return Some(Err(Error::with_invalid_data(
                    "attempted lookup of unsupported entry",
                )))
            }

            let path = data.read_slice(lfh.file_name_length.into())?;
            let path = Path::new(OsStr::from_bytes(path));

            let _extra = data.read_slice(lfh.extra_field_length.into())?;
            // SAFETY: Both pointers point into the same underlying byte array.
            let data_offset = u64::from(offset)
                + u64::try_from(unsafe { data.as_ptr().offset_from(start) }).unwrap();
            let data = data.read_slice(lfh.compressed_size as usize)?;

            let entry = Entry {
                compression: lfh.compression,
                path,
                data_offset,
                data,
            };

            Some(Ok(entry))
        }

        entry_impl(data, offset)
            .unwrap_or_else(|| Err(Error::with_invalid_data("failed to read archive entry")))
    }

    fn parse_next_entry(&mut self) -> Result<Entry<'archive>> {
        fn entry_impl<'archive>(iter: &mut EntryIter<'archive>) -> Option<Result<Entry<'archive>>> {
            let cdfh = iter.cd_record_data.read_pod::<CdFileHeader>()?;

            if cdfh.magic != CD_FILE_HEADER_MAGIC {
                return Some(Err(Error::with_invalid_data(
                    "central directory file header contains invalid magic number",
                )))
            }

            let _name = iter
                .cd_record_data
                .read_slice(cdfh.file_name_length.into())?;
            let _extra = iter
                .cd_record_data
                .read_slice(cdfh.extra_field_length.into())?;
            let _comment = iter
                .cd_record_data
                .read_slice(cdfh.file_comment_length.into())?;

            Some(EntryIter::parse_entry_at_offset(
                iter.archive_data,
                cdfh.offset,
            ))
        }

        entry_impl(self).unwrap_or_else(|| {
            Err(Error::with_invalid_data(
                "failed to read central directory record data",
            ))
        })
    }
}

impl<'archive> Iterator for EntryIter<'archive> {
    type Item = Result<Entry<'archive>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining_records = self.remaining_records.checked_sub(1)?;
        Some(self.parse_next_entry())
    }
}


/// An open zip archive.
///
/// Only basic ZIP files are supported, in particular the following are not
/// supported:
/// - encryption
/// - streaming
/// - multi-part ZIP files
/// - ZIP64
#[derive(Debug)]
pub(crate) struct Archive {
    mmap: Mmap,
    cd_offset: u32,
    cd_records: u16,
}

impl Archive {
    /// Open a zip archive at the provided `path`.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let mmap = Mmap::builder().open(path)?;
        Self::with_mmap(mmap)
    }

    /// Create an `Archive` instance using the provided `Mmap`.
    pub fn with_mmap(mmap: Mmap) -> Result<Self> {
        // Check that a central directory is present as at least some form
        // of validation that we are in fact dealing with a valid zip file.
        let (cd_offset, cd_records) = Archive::find_cd(&mmap)?;
        let slf = Archive {
            mmap,
            cd_offset,
            cd_records,
        };
        Ok(slf)
    }

    fn try_parse_end_of_cd(mut data: &[u8]) -> Option<Result<(u32, u16)>> {
        let eocd = data.read_pod::<EndOfCdRecord>()?;
        if eocd.magic != END_OF_CD_RECORD_MAGIC {
            return None
        }

        // Make sure that another `comment_length` bytes exist after the end of
        // cd record.
        let () = data.ensure(eocd.comment_length.into())?;

        if eocd.this_disk != 0 || eocd.cd_disk != 0 || eocd.cd_records_total != eocd.cd_records {
            // This is a valid eocd, but we only support single-file non-ZIP64 archives.
            Some(Err(Error::with_invalid_data(
                "archive is unsupported and cannot be opened",
            )))
        } else {
            Some(Ok((eocd.cd_offset, eocd.cd_records)))
        }
    }

    /// Search for the central directory at the end of the archive (represented
    /// by the provided slice of bytes).
    fn find_cd(data: &[u8]) -> Result<(u32, u16)> {
        // Because the end of central directory ends with a variable length
        // array of up to 0xFFFF bytes we can't know exactly where it starts and
        // need to search for it at the end of the file, scanning the [start,
        // end] range.
        let end = data
            .len()
            .checked_sub(size_of::<EndOfCdRecord>())
            .ok_or_invalid_data(|| {
                "archive is too small to contain end of central directory object"
            })?;
        let start = end.saturating_sub(1 << 16);

        for offset in (start..=end).rev() {
            let result = Self::try_parse_end_of_cd(data.get(offset..).unwrap());
            match result {
                None => continue,
                Some(Ok((cd_offset, cd_records))) => {
                    // Validate the offset and records quickly to eliminate
                    // potential error cases later on.
                    let cd_range = cd_offset as usize
                        ..cd_offset as usize + usize::from(cd_records) * size_of::<CdFileHeader>();
                    let _cd = data.get(cd_range).ok_or_unexpected_eof(|| {
                        "failed to retrieve central directory entries; archive is corrupted"
                    })?;
                    return Ok((cd_offset, cd_records))
                }
                Some(Err(err)) => return Err(err),
            }
        }

        Err(Error::with_invalid_data(
            "archive does not contain central directory",
        ))
    }

    /// Create an iterator over the entries of the archive.
    pub fn entries(&self) -> EntryIter<'_> {
        let archive_data = &self.mmap;
        // SANITY: The offset has been validated during construction.
        let cd_record_data = self.mmap.get(self.cd_offset as usize..).unwrap();
        let remaining_records = self.cd_records;

        let iter = EntryIter {
            archive_data,
            cd_record_data,
            remaining_records,
        };
        iter
    }

    /// Retrieve the [`Mmap`] object used by this `Archive`.
    #[inline]
    pub fn mmap(&self) -> &Mmap {
        &self.mmap
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::io::copy;
    use std::io::Write as _;
    use std::ops::Deref as _;

    use tempfile::tempfile;
    use tempfile::NamedTempFile;

    use test_log::test;

    use crate::elf::ElfParser;
    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");
        let archive = Archive::open(zip).unwrap();
        assert_ne!(format!("{archive:?}"), "");

        let entry = Entry {
            compression: 42,
            path: Path::new("some-entry-path.so"),
            data_offset: 56,
            data: &[1, 2, 3, 4],
        };

        let dbg = format!("{entry:?}");
        assert_eq!(
            dbg,
            r#"Entry { compression: 42, path: "some-entry-path.so", data_offset: 56, data: Some([1, 2, 3, 4]) }"#
        );
    }

    /// Check that we can properly open a zip archive.
    #[test]
    fn zip_opening() {
        let zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");
        let _archive = Archive::open(zip).unwrap();
    }

    /// Check that we can iterate over the entries of a zip archive.
    #[test]
    fn zip_entry_iteration() {
        let zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");
        let archive = Archive::open(zip).unwrap();
        assert_eq!(
            archive
                .entries()
                .inspect(|result| assert!(result.is_ok(), "{result:?}"))
                .count(),
            4
        );
    }

    /// Check that we can find archive entries by name.
    #[test]
    fn zip_entry_reading() {
        let zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");
        let archive = Archive::open(zip).unwrap();

        let result = archive
            .entries()
            .find(|entry| entry.as_ref().unwrap().path == Path::new("non-existent"));
        assert!(result.is_none());

        let entry = archive
            .entries()
            .find(|entry| entry.as_ref().unwrap().path == Path::new("zip-dir/test-no-debug.bin"))
            .unwrap()
            .unwrap();
        assert_eq!(entry.compression, 0);
        assert_eq!(entry.path, Path::new("zip-dir/test-no-debug.bin"));
        assert_eq!(
            entry.data,
            archive
                .mmap
                .get(entry.data_offset as usize..entry.data_offset as usize + entry.data.len())
                .unwrap()
        );

        // Sanity check that the entry actually references a valid ELF binary,
        // which is what we expect.
        let mut file = tempfile().unwrap();
        let () = file.write_all(entry.data).unwrap();

        let elf = ElfParser::open_file(file).unwrap();
        assert!(elf.find_section(".text").is_ok());
    }

    /// Check that we fail `Archive` creation for corrupted archives.
    #[test]
    fn zip_creation_corrupted() {
        let zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let archive = Archive::open(zip).unwrap();

        let mut corrupted_zip = NamedTempFile::new().unwrap();
        let mut partial_data = archive
            .mmap
            .deref()
            .get(
                ..archive.cd_offset as usize
                    + usize::from(archive.cd_records) * size_of::<CdFileHeader>()
                    - 1,
            )
            .unwrap();
        let _cnt = copy(&mut partial_data, &mut corrupted_zip).unwrap();

        // The archive only contains a corrupted central directory and no end of
        // central directory marker at all.
        let err = Archive::open(corrupted_zip.path()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    }
}
