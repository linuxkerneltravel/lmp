use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Debug;
use std::mem;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

#[cfg(doc)]
use crate::inspect;
use crate::inspect::Elf;
use crate::inspect::Inspector;
use crate::inspect::Source;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::log::error;
use crate::util::slice_from_user_array;
use crate::Addr;


/// An object representing an ELF inspection source.
///
/// C ABI compatible version of [`inspect::Elf`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_inspect_elf_src {
    /// The path to the ELF file. This member is always present.
    pub path: *const c_char,
    /// Whether or not to consult debug information to satisfy the request (if
    /// present).
    pub debug_info: bool,
}

impl From<Elf> for blaze_inspect_elf_src {
    fn from(other: Elf) -> Self {
        let Elf {
            path,
            debug_info,
            _non_exhaustive: (),
        } = other;
        Self {
            path: CString::new(path.into_os_string().into_vec())
                .expect("encountered path with NUL bytes")
                .into_raw(),
            debug_info,
        }
    }
}

impl From<blaze_inspect_elf_src> for Elf {
    fn from(other: blaze_inspect_elf_src) -> Self {
        let blaze_inspect_elf_src { path, debug_info } = other;

        Elf {
            path: PathBuf::from(OsString::from_vec(
                unsafe { CString::from_raw(path as *mut _) }.into_bytes(),
            )),
            debug_info,
            _non_exhaustive: (),
        }
    }
}

impl From<&blaze_inspect_elf_src> for Elf {
    fn from(other: &blaze_inspect_elf_src) -> Self {
        let blaze_inspect_elf_src { path, debug_info } = other;

        Elf {
            path: Path::new(OsStr::from_bytes(
                unsafe { CStr::from_ptr(*path) }.to_bytes(),
            ))
            .to_path_buf(),
            debug_info: *debug_info,
            _non_exhaustive: (),
        }
    }
}


/// The type of a symbol.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum blaze_sym_type {
    /// That type could not be determined (possibly because the source does not
    /// contains information about the type).
    BLAZE_SYM_UNKNOWN,
    /// The symbol is a function.
    BLAZE_SYM_FUNC,
    /// The symbol is a variable.
    BLAZE_SYM_VAR,
}

impl From<SymType> for blaze_sym_type {
    fn from(other: SymType) -> Self {
        match other {
            SymType::Unknown => blaze_sym_type::BLAZE_SYM_UNKNOWN,
            SymType::Function => blaze_sym_type::BLAZE_SYM_FUNC,
            SymType::Variable => blaze_sym_type::BLAZE_SYM_VAR,
        }
    }
}


/// Information about a looked up symbol.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_sym_info {
    /// See [`inspect::SymInfo::name`].
    pub name: *const c_char,
    /// See [`inspect::SymInfo::addr`].
    pub addr: Addr,
    /// See [`inspect::SymInfo::size`].
    pub size: usize,
    /// See [`inspect::SymInfo::file_offset`].
    pub file_offset: u64,
    /// See [`inspect::SymInfo::obj_file_name`].
    pub obj_file_name: *const c_char,
    /// See [`inspect::SymInfo::sym_type`].
    pub sym_type: blaze_sym_type,
}


/// Convert [`SymInfo`] objects as returned by
/// [`Symbolizer::find_addrs`] to a C array.
fn convert_syms_list_to_c(syms_list: Vec<Vec<SymInfo>>) -> *const *const blaze_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.obj_file_name.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = (mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        / mem::size_of::<u64>()
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blaze_sym_info>() * sym_cnt;
    let buf_size = array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blaze_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blaze_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut c_char;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymInfo {
            name,
            addr,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } in syms
        {
            let name_ptr = str_ptr.cast();
            unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
                let obj_fname_ptr = str_ptr;
                unsafe { ptr::copy_nonoverlapping(fname.as_ptr().cast(), str_ptr, fname.len()) };
                str_ptr = unsafe { str_ptr.add(fname.len()) };
                unsafe { *str_ptr = 0 };
                str_ptr = unsafe { str_ptr.add(1) };
                obj_fname_ptr
            } else {
                ptr::null()
            };

            unsafe {
                (*sym_ptr) = blaze_sym_info {
                    name: name_ptr,
                    addr,
                    size,
                    sym_type: match sym_type {
                        SymType::Function => blaze_sym_type::BLAZE_SYM_FUNC,
                        SymType::Variable => blaze_sym_type::BLAZE_SYM_VAR,
                        SymType::Unknown => blaze_sym_type::BLAZE_SYM_UNKNOWN,
                    },
                    file_offset,
                    obj_file_name,
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blaze_sym_info {
                name: ptr::null(),
                addr: 0,
                size: 0,
                sym_type: blaze_sym_type::BLAZE_SYM_UNKNOWN,
                file_offset: 0,
                obj_file_name: ptr::null(),
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blaze_sym_info
}


/// Lookup symbol information in an ELF file.
///
/// Return an array with the same size as the input names. The caller should
/// free the returned array by calling [`blaze_inspect_syms_free`].
///
/// Every name in the input name list may have more than one address.
/// The respective entry in the returned array is an array containing
/// all addresses and ended with a null (0x0).
///
/// The returned pointer should be freed by [`blaze_inspect_syms_free`].
///
/// # Safety
/// The `inspector` object should have been created using
/// [`blaze_inspector_new`], `src` needs to point to a valid object, and `names`
/// needs to be a valid pointer to `name_cnt` strings.
#[no_mangle]
pub unsafe extern "C" fn blaze_inspect_syms_elf(
    inspector: *const Inspector,
    src: *const blaze_inspect_elf_src,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blaze_sym_info {
    // SAFETY: The caller ensures that the pointer is valid.
    let inspector = unsafe { &*inspector };
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::Elf(Elf::from(unsafe { &*src }));
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let names = unsafe { slice_from_user_array(names, name_cnt) };
    let names = names
        .iter()
        .map(|&p| {
            // SAFETY: The caller ensures that the pointer is valid.
            unsafe { CStr::from_ptr(p) }.to_str().unwrap()
        })
        .collect::<Vec<_>>();
    let result = inspector.lookup(&names, &src);
    match result {
        Ok(syms) => convert_syms_list_to_c(syms),
        Err(err) => {
            error!("failed to lookup symbols: {err}");
            ptr::null()
        }
    }
}


/// Free an array returned by [`blaze_inspect_syms_elf`].
///
/// # Safety
///
/// The pointer must be returned by [`blaze_inspect_syms_elf`].
///
#[no_mangle]
pub unsafe extern "C" fn blaze_inspect_syms_free(syms: *const *const blaze_sym_info) {
    if syms.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}


/// Create an instance of a blazesym inspector.
///
/// The returned pointer should be released using
/// [`blaze_inspector_free`] once it is no longer needed.
#[no_mangle]
pub extern "C" fn blaze_inspector_new() -> *mut Inspector {
    let inspector = Inspector::new();
    let inspector_box = Box::new(inspector);
    Box::into_raw(inspector_box)
}


/// Free a blazesym inspector.
///
/// Release resources associated with a inspector as created by
/// [`blaze_inspector_new`], for example.
///
/// # Safety
/// The provided inspector should have been created by
/// [`blaze_inspector_new`].
#[no_mangle]
pub unsafe extern "C" fn blaze_inspector_free(inspector: *mut Inspector) {
    if !inspector.is_null() {
        // SAFETY: The caller needs to ensure that `inspector` is a
        //         valid pointer.
        drop(unsafe { Box::from_raw(inspector) });
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let elf = blaze_inspect_elf_src {
            path: ptr::null(),
            debug_info: true,
        };
        assert_eq!(
            format!("{elf:?}"),
            "blaze_inspect_elf_src { path: 0x0, debug_info: true }"
        );

        let info = blaze_sym_info {
            name: ptr::null(),
            addr: 42,
            size: 1337,
            file_offset: 31,
            obj_file_name: ptr::null(),
            sym_type: blaze_sym_type::BLAZE_SYM_VAR,
        };
        assert_eq!(
            format!("{info:?}"),
            "blaze_sym_info { name: 0x0, addr: 42, size: 1337, file_offset: 31, obj_file_name: 0x0, sym_type: BLAZE_SYM_VAR }"
        );
    }

    /// Check that we can properly convert a "syms list" into the corresponding
    /// C representation.
    #[test]
    fn syms_list_conversion() {
        fn test(syms: Vec<Vec<SymInfo>>) {
            let copy = syms.clone();
            let ptr = convert_syms_list_to_c(syms);

            for (i, list) in copy.into_iter().enumerate() {
                for (j, sym) in list.into_iter().enumerate() {
                    let c_sym = unsafe { &(*(*ptr.add(i)).add(j)) };
                    assert_eq!(
                        unsafe { CStr::from_ptr(c_sym.name) }.to_bytes(),
                        CString::new(sym.name).unwrap().to_bytes()
                    );
                    assert_eq!(c_sym.addr, sym.addr);
                    assert_eq!(c_sym.size, sym.size);
                    assert_eq!(c_sym.sym_type, blaze_sym_type::from(sym.sym_type));
                    assert_eq!(c_sym.file_offset, sym.file_offset);
                    assert_eq!(
                        unsafe { CStr::from_ptr(c_sym.obj_file_name) }.to_bytes(),
                        CString::new(
                            sym.obj_file_name
                                .as_deref()
                                .unwrap()
                                .as_os_str()
                                .to_os_string()
                                .into_vec()
                        )
                        .unwrap()
                        .to_bytes()
                    );
                }
            }

            let () = unsafe { blaze_inspect_syms_free(ptr) };
        }

        // Test conversion of no symbols.
        let syms = vec![];
        test(syms);

        // Test conversion with a single symbol.
        let syms = vec![vec![SymInfo {
            name: "sym1".to_string(),
            addr: 0xdeadbeef,
            size: 42,
            sym_type: SymType::Function,
            file_offset: 1337,
            obj_file_name: Some(PathBuf::from("/tmp/foobar.so")),
        }]];
        test(syms);

        // Test conversion of two symbols in one result.
        let syms = vec![vec![
            SymInfo {
                name: "sym1".to_string(),
                addr: 0xdeadbeef,
                size: 42,
                sym_type: SymType::Function,
                file_offset: 1337,
                obj_file_name: Some(PathBuf::from("/tmp/foobar.so")),
            },
            SymInfo {
                name: "sym2".to_string(),
                addr: 0xdeadbeef + 52,
                size: 45,
                sym_type: SymType::Unknown,
                file_offset: 1338,
                obj_file_name: Some(PathBuf::from("other.so")),
            },
        ]];
        test(syms);

        // Test conversion of two symbols spread over two results.
        let syms = vec![
            vec![SymInfo {
                name: "sym1".to_string(),
                addr: 0xdeadbeef,
                size: 42,
                sym_type: SymType::Function,
                file_offset: 1337,
                obj_file_name: Some(PathBuf::from("/tmp/foobar.so")),
            }],
            vec![SymInfo {
                name: "sym2".to_string(),
                addr: 0xdeadbeef + 52,
                size: 45,
                sym_type: SymType::Unknown,
                file_offset: 1338,
                obj_file_name: Some(PathBuf::from("other.so")),
            }],
        ];
        test(syms);

        // Test conversion of a `SymInfo` vector with many elements.
        let sym = SymInfo {
            name: "sym1".to_string(),
            addr: 0xdeadbeef,
            size: 42,
            sym_type: SymType::Function,
            file_offset: 1337,
            obj_file_name: Some(PathBuf::from("/tmp/foobar.so")),
        };
        let syms = vec![(0..200).map(|_| sym.clone()).collect()];
        test(syms);

        // Test conversion of many `SymInfo` vectors.
        let syms = (0..200).map(|_| vec![sym.clone()]).collect();
        test(syms);
    }
}
