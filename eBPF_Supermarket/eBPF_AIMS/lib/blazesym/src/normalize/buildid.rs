use std::fs::File;
use std::path::Path;

use crate::elf;
use crate::elf::types::Elf64_Nhdr;
use crate::elf::ElfParser;
use crate::log::warn;
use crate::util::ReadRaw as _;
use crate::IntoError as _;
use crate::Result;


/// Typedefs for functions reading build IDs.
pub(crate) type BuildIdFn = dyn Fn(&Path) -> Result<Option<Vec<u8>>>;


/// Iterate over all note sections to find one of type
/// [`NT_GNU_BUILD_ID`][elf::types::NT_GNU_BUILD_ID].
fn read_build_id_from_notes(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
    let shdrs = parser.section_headers()?;
    for (idx, shdr) in shdrs.iter().enumerate() {
        if shdr.sh_type == elf::types::SHT_NOTE {
            // SANITY: We just found the index so the section data should always
            //         be found.
            let mut bytes = parser.section_data(idx).unwrap();
            let header = bytes
                .read_pod_ref::<Elf64_Nhdr>()
                .ok_or_invalid_data(|| "failed to read build ID section header")?;
            if header.n_type == elf::types::NT_GNU_BUILD_ID {
                // Type check is assumed to suffice, but we still need
                // to skip the name bytes.
                let _name = bytes
                    .read_slice(header.n_namesz as _)
                    .ok_or_invalid_data(|| "failed to read build ID section name")?;
                let build_id = bytes
                    .read_slice(header.n_descsz as _)
                    .ok_or_invalid_data(|| "failed to read build ID section contents")?
                    .to_vec();
                return Ok(Some(build_id))
            }
        }
    }
    Ok(None)
}

/// Attempt to read an ELF binary's build ID from the .note.gnu.build-id section.
fn read_build_id_from_section_name(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
    let build_id_section = ".note.gnu.build-id";
    // The build ID is contained in the `.note.gnu.build-id` section. See
    // elf(5).
    if let Ok(Some(idx)) = parser.find_section(build_id_section) {
        // SANITY: We just found the index so the section should always be
        //         found.
        let shdr = parser.section_headers()?.get(idx).unwrap();
        if shdr.sh_type != elf::types::SHT_NOTE {
            warn!(
                "build ID section {build_id_section} is of unsupported type ({})",
                shdr.sh_type
            );
            return Ok(None)
        }

        // SANITY: We just found the index so the section should always be
        //         found.
        let mut bytes = parser.section_data(idx).unwrap();
        let header = bytes
            .read_pod_ref::<Elf64_Nhdr>()
            .ok_or_invalid_data(|| "failed to read build ID section header")?;
        let name = bytes
            .read_slice(header.n_namesz as _)
            .and_then(|mut name| name.read_cstr())
            .ok_or_invalid_data(|| "failed to read build ID section name")?;
        if name.to_bytes() != b"GNU" {
            warn!("encountered unsupported build ID type {:?}; ignoring", name);
            Ok(None)
        } else {
            let build_id = bytes
                .read_slice(header.n_descsz as _)
                .ok_or_invalid_data(|| "failed to read build ID section contents")?
                .to_vec();
            Ok(Some(build_id))
        }
    } else {
        Ok(None)
    }
}

pub(super) trait BuildIdReader: 'static {
    fn read_build_id_from_elf(path: &Path) -> Result<Option<Vec<u8>>>;
    fn read_build_id(parser: &ElfParser) -> Result<Option<Vec<u8>>>;
}


pub(super) struct DefaultBuildIdReader;

impl BuildIdReader for DefaultBuildIdReader {
    /// Attempt to read an ELF binary's build ID.
    #[cfg_attr(feature = "tracing", crate::log::instrument)]
    fn read_build_id(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
        if let Some(build_id) = read_build_id_from_section_name(parser)? {
            Ok(Some(build_id))
        } else if let Some(build_id) = read_build_id_from_notes(parser)? {
            Ok(Some(build_id))
        } else {
            Ok(None)
        }
    }

    /// Attempt to read an ELF binary's build ID from a file.
    #[cfg_attr(feature = "tracing", crate::log::instrument)]
    fn read_build_id_from_elf(path: &Path) -> Result<Option<Vec<u8>>> {
        let file = File::open(path)?;
        let parser = ElfParser::open_file(file)?;
        Self::read_build_id(&parser)
    }
}


pub(super) struct NoBuildIdReader;

impl BuildIdReader for NoBuildIdReader {
    fn read_build_id_from_elf(_path: &Path) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn read_build_id(_parser: &ElfParser) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}


/// Read the build ID of an ELF file located at the given path.
///
/// Build IDs can have variable length, depending on which flavor is used (e.g.,
/// 20 bytes for `sha1` flavor). They are reported as "raw" bytes. If you need a
/// hexadecimal representation as reported by tools such as `readelf(1)`, a post
/// processing step is necessary.
///
/// Returns [`None`] if the file does not contain a build ID.
///
/// ```
/// # use std::path::Path;
/// # let retrieve_path_to_elf_file = || {
/// #   Path::new(&env!("CARGO_MANIFEST_DIR"))
/// #       .join("data")
/// #       .join("libtest-so.so")
/// #       // Convert to string here for more convenient formatting in example
/// #       // code.
/// #       .to_str()
/// #       .unwrap()
/// #       .to_string()
/// # };
/// let path = retrieve_path_to_elf_file();
/// let build_id = blazesym::helper::read_elf_build_id(&path).unwrap();
/// match build_id {
///     Some(bytes) => {
///        let build_id = bytes
///            .iter()
///            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
///                let () = s.push_str(&format!("{b:02x}"));
///                s
///            });
///        println!("{path} has build ID {build_id}");
///     },
///     None => println!("{path} has no build ID"),
/// }
/// ```
#[inline]
pub fn read_elf_build_id<P>(path: &P) -> Result<Option<Vec<u8>>>
where
    P: AsRef<Path>,
{
    DefaultBuildIdReader::read_build_id_from_elf(path.as_ref())
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can read a binary's build ID based on the ELF section name as well as ELF section type.
    #[test]
    fn build_id_reading_from_name_and_notes() {
        fn test(f: fn(&ElfParser) -> Result<Option<Vec<u8>>>) {
            let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("libtest-so.so");

            let file = File::open(elf).unwrap();
            let parser = ElfParser::open_file(file).unwrap();
            let build_id = f(&parser).unwrap().unwrap();
            // The file contains a sha1 build ID, which is always 40 hex digits.
            assert_eq!(build_id.len(), 20, "'{build_id:?}'");
        }

        test(read_build_id_from_section_name);
        test(read_build_id_from_notes);
    }

    /// Check that we can read a binary's build ID.
    #[test]
    fn build_id_reading() {
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let build_id = read_elf_build_id(&elf).unwrap().unwrap();
        // The file contains a sha1 build ID, which is always 20 bytes in length.
        assert_eq!(build_id.len(), 20, "'{build_id:?}'");

        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so-no-separate-code.so");
        let build_id = read_elf_build_id(&elf).unwrap().unwrap();
        // The file contains an md5 build ID, which is always 16 bytes long.
        assert_eq!(build_id.len(), 16, "'{build_id:?}'");

        // The shared object is explicitly built without build ID.
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");
        let build_id = read_elf_build_id(&elf).unwrap();
        assert_eq!(build_id, None);
    }
}
