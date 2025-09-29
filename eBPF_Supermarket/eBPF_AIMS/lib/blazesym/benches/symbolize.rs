#![allow(clippy::fn_to_numeric_cast)]

use std::hint::black_box;
use std::path::Path;

use blazesym::c_api;
use blazesym::symbolize::Elf;
use blazesym::symbolize::GsymFile;
use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Symbolize addresses in the current process.
fn symbolize_process() {
    let src = Source::Process(Process::new(Pid::Slf));
    let addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        symbolize_process as Addr,
        c_api::blaze_inspector_free as Addr,
    ];

    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(black_box(&src), black_box(Input::AbsAddr(&addrs)))
        .unwrap();
    assert_eq!(results.len(), addrs.len());
}

/// Symbolize an address in an ELF file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_elf() {
    let elf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.elf");
    let src = Source::Elf(Elf::new(elf_vmlinux));
    let symbolizer = Symbolizer::builder()
        .enable_debug_syms(false)
        .enable_code_info(false)
        .build();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
}

/// Symbolize an address in a DWARF file, excluding line information,
/// end-to-end, i.e., including all necessary setup.
fn symbolize_dwarf_no_lines() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = Source::Elf(Elf::new(dwarf_vmlinux));
    let symbolizer = Symbolizer::builder().enable_code_info(false).build();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.code_info.as_ref(), None);
}

/// Symbolize an address in a DWARF file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_dwarf() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = Source::Elf(Elf::new(dwarf_vmlinux));
    let symbolizer = Symbolizer::new();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}

/// Symbolize an address in a GSYM file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_gsym() {
    let gsym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.gsym");
    let src = Source::from(GsymFile::new(gsym_vmlinux));
    let symbolizer = Symbolizer::new();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_fn!(group, symbolize_process);
    if cfg!(feature = "generate-large-test-files") {
        bench_fn!(group, symbolize_elf);
        bench_fn!(group, symbolize_dwarf_no_lines);
        bench_fn!(group, symbolize_dwarf);
        bench_fn!(group, symbolize_gsym);
    }
}
