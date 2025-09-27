#![allow(clippy::let_unit_value)]

use std::cmp::min;
use std::mem::size_of;
use std::mem::transmute;
use std::ptr;

use blazesym::symbolize::CodeInfo;
use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

const ADDR_WIDTH: usize = 16;


fn print_frame(name: &str, addr_info: Option<(Addr, Addr, usize)>, code_info: &Option<CodeInfo>) {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        println!(
            "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
    } else {
        // Otherwise we are dealing with an inlined call.
        println!(
            "{:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
    }
}

fn symbolize_current_bt() {
    assert_eq!(size_of::<*mut libc::c_void>(), size_of::<Addr>());
    // Retrieve up to 64 stack frames of the calling thread.
    const MAX_CNT: usize = 64;

    let mut bt_buf = [ptr::null_mut::<libc::c_void>(); MAX_CNT];
    let bt_cnt = unsafe { libc::backtrace(bt_buf.as_mut_ptr(), MAX_CNT as _) } as usize;
    let bt = &mut bt_buf[0..min(bt_cnt, MAX_CNT)];
    let bt = unsafe { transmute::<&mut [*mut libc::c_void], &mut [Addr]>(bt) };

    // For all but the top most address in the call stack, adjust for
    // the fact that we captured the address we will return to, but not
    // the one we called from.
    let () = bt.iter_mut().skip(1).for_each(|addr| *addr -= 1);

    // Symbolize the addresses for the current process, as that's where
    // they were captured.
    let src = Source::Process(Process::new(Pid::Slf));
    let symbolizer = Symbolizer::new();

    let syms = symbolizer.symbolize(&src, Input::VirtOffset(bt)).unwrap();
    let addrs = bt;

    for (input_addr, sym) in addrs.iter().copied().zip(syms) {
        match sym {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(&name, Some((input_addr, addr, offset)), &code_info);
                for frame in inlined.iter() {
                    print_frame(&frame.name, None, &frame.code_info);
                }
            }
            Symbolized::Unknown => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }
}


#[inline(never)]
fn f() {
    g()
}

#[inline(always)]
fn g() {
    h()
}

#[inline(never)]
fn h() {
    symbolize_current_bt()
}

fn main() {
    f();
}
