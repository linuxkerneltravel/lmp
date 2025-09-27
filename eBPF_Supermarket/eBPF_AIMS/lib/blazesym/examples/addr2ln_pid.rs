use std::env;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

use blazesym::symbolize::CodeInfo;
use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

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


fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        bail!(
            "Usage: {} <pid> <address>
Resolve an address in the process of the given pid, and
print its symbol, the file name of the source, and the line number.",
            args.first().map(String::as_str).unwrap_or("addr2ln_pid")
        );
    }

    let pid = args[1].parse::<u32>().unwrap();
    let addr_str = &args[2][..];
    println!("PID: {pid}");

    let addr = Addr::from_str_radix(addr_str.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {addr_str}"))?;

    let src = Source::Process(Process::new(pid.into()));
    let addrs = [addr];
    let symbolizer = Symbolizer::new();
    let syms = symbolizer
        .symbolize(&src, Input::VirtOffset(&addrs))
        .with_context(|| format!("failed to symbolize address {addr:#x}"))?;

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
    Ok(())
}
