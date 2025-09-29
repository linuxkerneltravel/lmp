use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Error;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;

use crate::maps;
use crate::maps::PathMapsEntry;
use crate::Addr;
use crate::Pid;
use crate::Result;

use super::buildid::BuildIdFn;
use super::buildid::BuildIdReader;
use super::buildid::DefaultBuildIdReader;
use super::buildid::NoBuildIdReader;
use super::meta::Apk;
use super::meta::Elf;
use super::meta::Unknown;
use super::meta::UserMeta;
use super::normalizer::Output;


pub(crate) fn create_apk_elf_path(apk: &Path, elf: &Path) -> Result<PathBuf> {
    let mut extension = apk
        .extension()
        .unwrap_or_else(|| OsStr::new("apk"))
        .to_os_string();
    // Append '!' to indicate separation from archive internal contents
    // that follow. This is an Android convention.
    let () = extension.push("!");

    let mut apk = apk.to_path_buf();
    if !apk.set_extension(extension) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("path {} is not valid", apk.display()),
        )
        .into())
    }

    let path = apk.join(elf);
    Ok(path)
}


/// Make a [`UserMeta::Elf`] variant.
fn make_elf_meta(entry: &PathMapsEntry, get_build_id: &BuildIdFn) -> Result<UserMeta> {
    let elf = Elf {
        path: entry.path.symbolic_path.to_path_buf(),
        build_id: get_build_id(&entry.path.maps_file)?,
        _non_exhaustive: (),
    };
    let meta = UserMeta::Elf(elf);
    Ok(meta)
}


/// Make a [`UserMeta::Apk`] variant.
fn make_apk_meta(entry: &PathMapsEntry) -> Result<UserMeta> {
    let apk = Apk {
        path: entry.path.symbolic_path.to_path_buf(),
        _non_exhaustive: (),
    };
    let meta = UserMeta::Apk(apk);
    Ok(meta)
}


/// A type representing the output of user addresses normalization.
pub type UserOutput = Output<UserMeta>;

impl UserOutput {
    /// Add an unknown (non-normalizable) address to this object.
    ///
    /// This function accepts `unknown_idx` which, if not `None`, should
    /// contain the index into [`Self::meta`] at which an [`Unknown`]
    /// without any build ID resides.
    ///
    /// It returns the index of the inserted [`Unknown`] variant. The
    /// return type is an `Option` only for convenience of callers.
    /// Returned is always a `Some`.
    fn add_unknown_addr(&mut self, addr: Addr, unknown_idx: Option<usize>) -> Option<usize> {
        let unknown_idx = if let Some(unknown_idx) = unknown_idx {
            debug_assert_eq!(self.meta[unknown_idx], Unknown::default().into());
            unknown_idx
        } else {
            let unknown_idx = self.meta.len();
            let unknown = Unknown::default();
            let () = self.meta.push(UserMeta::Unknown(unknown));
            unknown_idx
        };

        let () = self.outputs.push((addr, unknown_idx));
        Some(unknown_idx)
    }

    /// Add a (normalized) file offset to this object.
    fn add_normalized_offset<F>(
        &mut self,
        file_offset: Addr,
        key: &Path,
        meta_lookup: &mut HashMap<PathBuf, usize>,
        create_meta: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<UserMeta>,
    {
        let meta_idx = if let Some(meta_idx) = meta_lookup.get(key) {
            *meta_idx
        } else {
            let meta = create_meta()?;
            let meta_idx = self.meta.len();
            let () = self.meta.push(meta);
            let _ref = meta_lookup.insert(key.to_path_buf(), meta_idx);
            meta_idx
        };

        let () = self.outputs.push((file_offset, meta_idx));
        Ok(())
    }
}


pub(crate) trait Handler {
    /// Handle an unknown address.
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()>;

    /// Handle an address residing in the provided [`PathMapsEntry`].
    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()>;
}


struct NormalizationHandler<R> {
    /// The user output we are building up.
    normalized: UserOutput,
    /// Lookup table from path (as used in each proc maps entry) to index into
    /// `output.meta`.
    meta_lookup: HashMap<PathBuf, usize>,
    /// The index of the `Unknown` entry in `meta_lookup`, used for all unknown
    /// addresses.
    unknown_idx: Option<usize>,
    #[doc(hidden)]
    _phanton: PhantomData<R>,
}

impl<R> NormalizationHandler<R> {
    /// Instantiate a new `NormalizationHandler` object.
    fn new(addr_cnt: usize) -> Self {
        Self {
            normalized: UserOutput {
                outputs: Vec::with_capacity(addr_cnt),
                meta: Vec::new(),
            },
            meta_lookup: HashMap::<PathBuf, usize>::new(),
            unknown_idx: None,
            _phanton: PhantomData,
        }
    }
}

impl<R> Handler for NormalizationHandler<R>
where
    R: BuildIdReader,
{
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"))))]
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()> {
        self.unknown_idx = self.normalized.add_unknown_addr(addr, self.unknown_idx);
        Ok(())
    }

    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
        let file_off = addr - entry.range.start + entry.offset;
        let ext = entry
            .path
            .symbolic_path
            .extension()
            .unwrap_or_else(|| OsStr::new(""));
        match ext.to_str() {
            Some("apk") | Some("zip") => self.normalized.add_normalized_offset(
                file_off,
                &entry.path.symbolic_path,
                &mut self.meta_lookup,
                || make_apk_meta(entry),
            ),
            _ => self.normalized.add_normalized_offset(
                file_off,
                &entry.path.symbolic_path,
                &mut self.meta_lookup,
                || make_elf_meta(entry, &R::read_build_id_from_elf),
            ),
        }
    }
}


pub(crate) fn normalize_sorted_user_addrs_with_entries<A, E, H>(
    addrs: A,
    entries: E,
    mut handler: H,
) -> Result<H>
where
    A: ExactSizeIterator<Item = Addr> + Clone,
    E: Iterator<Item = Result<maps::MapsEntry>>,
    H: Handler,
{
    let mut entries = entries.filter_map(|result| match result {
        Ok(entry) => maps::filter_map_relevant(entry).map(Ok),
        Err(err) => Some(Err(err)),
    });

    let mut entry = entries.next().ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "proc maps does not contain relevant entries",
        )
    })??;

    let mut prev_addr = addrs.clone().next().unwrap_or_default();
    // We effectively do a single pass over `addrs`, advancing to the next
    // proc maps entry whenever the current address is not (or no longer)
    // contained in the current entry's range.
    'main: for addr in addrs {
        if addr < prev_addr {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "addresses to normalize are not sorted",
            )
            .into())
        }
        prev_addr = addr;

        while addr >= entry.range.end {
            entry = if let Some(entry) = entries.next() {
                entry?
            } else {
                // If there are no proc maps entries left to check, we
                // cannot normalize. We have to assume that addresses
                // were valid and the ELF object was just unmapped,
                // similar to above.
                let () = handler.handle_unknown_addr(addr)?;
                continue 'main
            };
        }

        // proc maps entries are always sorted by start address. If the
        // current address lies before the start address at this point,
        // that means that we cannot find a suitable entry. This could
        // happen, for example, if an ELF object was unmapped between
        // address capture and normalization.
        if addr < entry.range.start {
            let () = handler.handle_unknown_addr(addr)?;
            continue 'main
        }

        let () = handler.handle_entry_addr(addr, &entry)?;
    }

    Ok(handler)
}

/// Normalize all `addrs` in a given process to the corresponding file offsets,
/// which are suitable for later symbolization. The `addrs` array has to be
/// sorted in ascending order or an error will be returned.
///
/// Unknown addresses are not normalized. They are reported as
/// [`Unknown`] meta entries in the returned [`UserOutput`]
/// object. The cause of an address to be unknown (and, hence, not
/// normalized), could have a few reasons, including, but not limited
/// to:
/// - user error (if a bogus address was provided)
/// - they belonged to an ELF object that has been unmapped since the
///   address was captured
///
/// The process' ID should be provided in `pid`.
///
/// File offsets are reported in the exact same order in which the
/// non-normalized addresses ones were provided.
pub(super) fn normalize_user_addrs_sorted_impl<A>(
    addrs: A,
    pid: Pid,
    read_build_ids: bool,
) -> Result<UserOutput>
where
    A: ExactSizeIterator<Item = Addr> + Clone,
{
    let addrs_cnt = addrs.len();
    let entries = maps::parse(pid)?;

    if read_build_ids {
        let handler = NormalizationHandler::<DefaultBuildIdReader>::new(addrs_cnt);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
        Ok(handler.normalized)
    } else {
        let handler = NormalizationHandler::<NoBuildIdReader>::new(addrs_cnt);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
        Ok(handler.normalized)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));
    }

    /// Check that we correctly handle normalization of an address not
    /// in any executable segment.
    #[test]
    fn user_address_normalization_static_maps() {
        fn test(unknown_addr: Addr) {
            let maps = r#"
55d3195b7000-55d3195b9000 r--p 00000000 00:12 2015701                    /bin/cat
55d3195b9000-55d3195be000 r-xp 00002000 00:12 2015701                    /bin/cat
55d3195be000-55d3195c1000 r--p 00007000 00:12 2015701                    /bin/cat
55d3195c1000-55d3195c2000 r--p 00009000 00:12 2015701                    /bin/cat
55d3195c2000-55d3195c3000 rw-p 0000a000 00:12 2015701                    /bin/cat
55d31b4dc000-55d31b4fd000 rw-p 00000000 00:00 0                          [heap]
7fd5b9c3d000-7fd5b9c5f000 rw-p 00000000 00:00 0
7fd5b9c5f000-7fd5ba034000 r--p 00000000 00:12 7689533                    /usr/lib/locale/locale-archive
7fd5ba034000-7fd5ba037000 rw-p 00000000 00:00 0
7fd5ba037000-7fd5ba059000 r--p 00000000 00:12 2088876                    /lib64/libc.so.6
7fd5ba059000-7fd5ba1a8000 r-xp 00022000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1a8000-7fd5ba1fa000 r--p 00171000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1fa000-7fd5ba1fe000 r--p 001c3000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1fe000-7fd5ba200000 rw-p 001c7000 00:12 2088876                    /lib64/libc.so.6
7fd5ba200000-7fd5ba208000 rw-p 00000000 00:00 0
7fd5ba214000-7fd5ba216000 rw-p 00000000 00:00 0
7fd5ba216000-7fd5ba217000 r--p 00000000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba217000-7fd5ba23c000 r-xp 00001000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba23c000-7fd5ba246000 r--p 00026000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba246000-7fd5ba248000 r--p 00030000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba248000-7fd5ba24a000 rw-p 00032000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7ffe102a2000-7ffe102c4000 rw-p 00000000 00:00 0                          [stack]
7ffe103f6000-7ffe103fa000 r--p 00000000 00:00 0                          [vvar]
7ffe103fa000-7ffe103fc000 r-xp 00000000 00:00 0                          [vdso]
"#;

            let pid = Pid::Slf;
            let entries = maps::parse_file(maps.as_bytes(), pid);
            let addrs = [unknown_addr as Addr];

            let handler = NormalizationHandler::<NoBuildIdReader>::new(addrs.len());
            let normalized = normalize_sorted_user_addrs_with_entries(
                addrs.as_slice().iter().copied(),
                entries,
                handler,
            )
            .unwrap()
            .normalized;
            assert_eq!(normalized.outputs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);
            assert_eq!(normalized.meta[0], Unknown::default().into());
        }

        test(0x0);
        test(0x1);
        test(0x1000);
        test(0xa0000);
        test(0x7fd5ba1fe000);
        test(0x7fffffff0000);
        test(0x7fffffff1000);
        test(0x7fffffff1001);
        test(0x7fffffffffff);
    }
}
