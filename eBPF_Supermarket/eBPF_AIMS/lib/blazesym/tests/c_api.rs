#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::ffi::CStr;
use std::ffi::CString;
use std::fs::read as read_file;
use std::path::Path;
use std::ptr;
use std::slice;

use blazesym::inspect;
use blazesym::symbolize;

use blazesym::c_api::blaze_inspect_elf_src;
use blazesym::c_api::blaze_inspect_syms_elf;
use blazesym::c_api::blaze_inspect_syms_free;
use blazesym::c_api::blaze_inspector_free;
use blazesym::c_api::blaze_inspector_new;
use blazesym::c_api::blaze_normalize_user_addrs;
use blazesym::c_api::blaze_normalize_user_addrs_sorted;
use blazesym::c_api::blaze_normalizer_free;
use blazesym::c_api::blaze_normalizer_new;
use blazesym::c_api::blaze_result;
use blazesym::c_api::blaze_result_free;
use blazesym::c_api::blaze_symbolize_elf_file_addrs;
use blazesym::c_api::blaze_symbolize_gsym_data_file_addrs;
use blazesym::c_api::blaze_symbolize_gsym_file_file_addrs;
use blazesym::c_api::blaze_symbolize_process_virt_addrs;
use blazesym::c_api::blaze_symbolize_src_elf;
use blazesym::c_api::blaze_symbolize_src_gsym_data;
use blazesym::c_api::blaze_symbolize_src_gsym_file;
use blazesym::c_api::blaze_symbolize_src_process;
use blazesym::c_api::blaze_symbolizer;
use blazesym::c_api::blaze_symbolizer_free;
use blazesym::c_api::blaze_symbolizer_new;
use blazesym::c_api::blaze_symbolizer_new_opts;
use blazesym::c_api::blaze_symbolizer_opts;
use blazesym::c_api::blaze_user_output_free;
use blazesym::Addr;


/// Make sure that we can create and free a symbolizer instance.
#[test]
fn symbolizer_creation() {
    let symbolizer = blaze_symbolizer_new();
    let () = unsafe { blaze_symbolizer_free(symbolizer) };
}


/// Make sure that we can create and free a symbolizer instance with the
/// provided options.
#[test]
fn symbolizer_creation_with_opts() {
    let opts = blaze_symbolizer_opts {
        debug_syms: true,
        code_info: false,
        inlined_fns: false,
        demangle: true,
    };
    let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
    let () = unsafe { blaze_symbolizer_free(symbolizer) };
}


/// Make sure that we can symbolize an address using ELF, DWARF, and
/// GSYM.
#[test]
fn symbolize_elf_dwarf_gsym() {
    fn test<F>(symbolize: F, has_code_info: bool)
    where
        F: FnOnce(*mut blaze_symbolizer, *const Addr, usize) -> *const blaze_result,
    {
        let symbolizer = blaze_symbolizer_new();
        let addrs = [0x2000100];
        let result = symbolize(symbolizer, addrs.as_ptr(), addrs.len());

        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        assert_eq!(
            unsafe { CStr::from_ptr(sym.name) },
            CStr::from_bytes_with_nul(b"factorial\0").unwrap()
        );
        assert_eq!(sym.addr, 0x2000100);
        assert_eq!(sym.offset, 0);

        if has_code_info {
            assert!(!sym.code_info.dir.is_null());
            assert!(!sym.code_info.file.is_null());
            assert_eq!(
                unsafe { CStr::from_ptr(sym.code_info.file) },
                CStr::from_bytes_with_nul(b"test-stable-addresses.c\0").unwrap()
            );
            assert_eq!(sym.code_info.line, 8);
        } else {
            assert!(sym.code_info.dir.is_null());
            assert!(sym.code_info.file.is_null());
            assert_eq!(sym.code_info.line, 0);
        }

        let () = unsafe { blaze_result_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();
    let elf_src = blaze_symbolize_src_elf {
        path: path_c.as_ptr(),
    };
    let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
        blaze_symbolize_elf_file_addrs(symbolizer, &elf_src, addrs, addr_cnt)
    };
    test(symbolize, false);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();
    let elf_src = blaze_symbolize_src_elf {
        path: path_c.as_ptr(),
    };
    let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
        blaze_symbolize_elf_file_addrs(symbolizer, &elf_src, addrs, addr_cnt)
    };
    test(symbolize, true);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();
    let gsym_src = blaze_symbolize_src_gsym_file {
        path: path_c.as_ptr(),
    };
    let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
        blaze_symbolize_gsym_file_file_addrs(symbolizer, &gsym_src, addrs, addr_cnt)
    };
    test(symbolize, true);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let data = read_file(path).unwrap();
    let gsym_src = blaze_symbolize_src_gsym_data {
        data: data.as_ptr(),
        data_len: data.len(),
    };
    let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
        blaze_symbolize_gsym_data_file_addrs(symbolizer, &gsym_src, addrs, addr_cnt)
    };
    test(symbolize, true);
}


/// Symbolize an address inside a DWARF file, with and without auto-demangling
/// enabled.
#[test]
fn symbolize_dwarf_demangle() {
    fn test(path: &Path, addr: Addr) -> Result<(), ()> {
        let opts = blaze_symbolizer_opts {
            debug_syms: true,
            code_info: true,
            inlined_fns: true,
            demangle: false,
        };

        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
        };
        let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
        let addrs = [addr];
        let result = unsafe {
            blaze_symbolize_elf_file_addrs(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
        };
        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        let name = unsafe { CStr::from_ptr(sym.name) };
        assert!(
            name.to_str().unwrap().contains("test13test_function"),
            "{:?}",
            name
        );

        if sym.inlined_cnt == 0 {
            let () = unsafe { blaze_result_free(result) };
            let () = unsafe { blaze_symbolizer_free(symbolizer) };
            return Err(())
        }

        assert_eq!(sym.inlined_cnt, 1);
        let name = unsafe { CStr::from_ptr((*sym.inlined).name) };
        assert!(
            name.to_str().unwrap().contains("test12inlined_call"),
            "{:?}",
            name
        );

        let () = unsafe { blaze_result_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };

        // Do it again, this time with demangling enabled.
        let opts = blaze_symbolizer_opts {
            debug_syms: true,
            code_info: true,
            inlined_fns: true,
            demangle: true,
        };

        let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
        let addrs = [addr];
        let result = unsafe {
            blaze_symbolize_elf_file_addrs(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
        };
        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        assert_eq!(
            unsafe { CStr::from_ptr(sym.name) },
            CStr::from_bytes_with_nul(b"test::test_function\0").unwrap()
        );


        assert_eq!(sym.inlined_cnt, 1);
        assert_eq!(
            unsafe { CStr::from_ptr((*sym.inlined).name) },
            CStr::from_bytes_with_nul(b"test::inlined_call\0").unwrap()
        );

        let () = unsafe { blaze_result_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let elf = inspect::Elf::new(&test_dwarf);
    let src = inspect::Source::Elf(elf);

    let inspector = inspect::Inspector::new();
    let results = inspector
        .lookup(&["_RNvCs69hjMPjVIJK_4test13test_function"], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!results.is_empty());

    let addr = results[0].addr;
    let src = symbolize::Source::Elf(symbolize::Elf::new(&test_dwarf));
    let symbolizer = symbolize::Symbolizer::builder()
        .enable_demangling(false)
        .build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
        .unwrap()
        .into_sym()
        .unwrap();

    let addr = result.addr;
    let size = result.size.unwrap() as u64;
    for inst_addr in addr..addr + size {
        if test(&test_dwarf, inst_addr).is_ok() {
            return
        }
    }

    panic!("failed to find inlined function call");
}


/// Make sure that we can symbolize an address in a process.
#[test]
fn symbolize_in_process() {
    let process_src = blaze_symbolize_src_process { pid: 0 };

    let symbolizer = blaze_symbolizer_new();
    let addrs = [blaze_symbolizer_new as Addr];
    let result = unsafe {
        blaze_symbolize_process_virt_addrs(symbolizer, &process_src, addrs.as_ptr(), addrs.len())
    };

    assert!(!result.is_null());

    let result = unsafe { &*result };
    assert_eq!(result.cnt, 1);
    let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
    let sym = &syms[0];
    assert_eq!(
        unsafe { CStr::from_ptr(sym.name) },
        CStr::from_bytes_with_nul(b"blaze_symbolizer_new\0").unwrap()
    );

    let () = unsafe { blaze_result_free(result) };
    let () = unsafe { blaze_symbolizer_free(symbolizer) };
}


/// Make sure that we can create and free a normalizer instance.
#[test]
fn normalizer_creation() {
    let normalizer = blaze_normalizer_new();
    let () = unsafe { blaze_normalizer_free(normalizer) };
}


/// Check that we can normalize user space addresses.
#[test]
fn normalize_user_addrs() {
    let addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        lookup_dwarf as Addr,
        normalize_user_addrs as Addr,
    ];

    let normalizer = blaze_normalizer_new();
    assert_ne!(normalizer, ptr::null_mut());

    let result = unsafe {
        blaze_normalize_user_addrs(normalizer, addrs.as_slice().as_ptr(), addrs.len(), 0)
    };
    assert_ne!(result, ptr::null_mut());

    let user_addrs = unsafe { &*result };
    assert_eq!(user_addrs.meta_cnt, 2);
    assert_eq!(user_addrs.output_cnt, 5);

    let () = unsafe { blaze_user_output_free(result) };
    let () = unsafe { blaze_normalizer_free(normalizer) };
}


/// Check that we can normalize sorted user space addresses.
#[test]
fn normalize_user_addrs_sorted() {
    let mut addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        lookup_dwarf as Addr,
        normalize_user_addrs as Addr,
    ];
    let () = addrs.sort();

    let normalizer = blaze_normalizer_new();
    assert_ne!(normalizer, ptr::null_mut());

    let result = unsafe {
        blaze_normalize_user_addrs_sorted(normalizer, addrs.as_slice().as_ptr(), addrs.len(), 0)
    };
    assert_ne!(result, ptr::null_mut());

    let user_addrs = unsafe { &*result };
    assert_eq!(user_addrs.meta_cnt, 2);
    assert_eq!(user_addrs.output_cnt, 5);

    let () = unsafe { blaze_user_output_free(result) };
    let () = unsafe { blaze_normalizer_free(normalizer) };
}


/// Make sure that we can create and free an inspector instance.
#[test]
fn inspector_creation() {
    let inspector = blaze_inspector_new();
    let () = unsafe { blaze_inspector_free(inspector) };
}


/// Make sure that we can lookup a function's address using DWARF information.
#[test]
fn lookup_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");

    let src = blaze_inspect_elf_src::from(inspect::Elf::new(test_dwarf));
    let factorial = CString::new("factorial").unwrap();
    let names = [factorial.as_ptr()];

    let inspector = blaze_inspector_new();
    let result = unsafe { blaze_inspect_syms_elf(inspector, &src, names.as_ptr(), names.len()) };
    let _src = inspect::Elf::from(src);

    let sym_infos = unsafe { slice::from_raw_parts(result, names.len()) };
    let sym_info = unsafe { &*sym_infos[0] };
    assert_eq!(
        unsafe { CStr::from_ptr(sym_info.name) },
        CStr::from_bytes_with_nul(b"factorial\0").unwrap()
    );
    assert_eq!(sym_info.addr, 0x2000100);

    let () = unsafe { blaze_inspect_syms_free(result) };
    let () = unsafe { blaze_inspector_free(inspector) };
}
