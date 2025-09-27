#![allow(clippy::let_and_return, clippy::let_unit_value)]

mod args;

use anyhow::Context;
use anyhow::Result;

use blazesym::normalize;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

use clap::Parser as _;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

const ADDR_WIDTH: usize = 16;


fn format_build_id_bytes(build_id: &[u8]) -> String {
    build_id
        .iter()
        .fold(String::with_capacity(build_id.len() * 2), |mut s, b| {
            let () = s.push_str(&format!("{b:02x}"));
            s
        })
}

fn format_build_id(build_id: Option<&[u8]>) -> String {
    if let Some(build_id) = build_id {
        format!(" (build ID: {})", format_build_id_bytes(build_id))
    } else {
        String::new()
    }
}

fn normalize(normalize: args::Normalize) -> Result<()> {
    let normalizer = Normalizer::new();
    match normalize {
        args::Normalize::User(args::User { pid, addrs }) => {
            let normalized = normalizer
                .normalize_user_addrs(addrs.as_slice(), pid)
                .context("failed to normalize addresses")?;
            for (addr, (output, meta_idx)) in addrs.iter().zip(&normalized.outputs) {
                print!("{addr:#016x}: ");

                let meta = &normalized.meta[*meta_idx];
                match meta {
                    normalize::UserMeta::Apk(normalize::Apk { path, .. }) => {
                        println!("file offset {output:#x} in {}", path.display())
                    }
                    normalize::UserMeta::Elf(normalize::Elf { path, build_id, .. }) => {
                        let build_id = format_build_id(build_id.as_deref());
                        println!("file offset {output:#x} in {}{build_id}", path.display())
                    }
                    normalize::UserMeta::Unknown(normalize::Unknown { .. }) => {
                        println!("<unknown>")
                    }
                    // This is a bug and should be reported as such.
                    _ => panic!("encountered unsupported user meta data: {meta:?}"),
                }
            }
        }
    }
    Ok(())
}

fn print_frame(
    name: &str,
    addr_info: Option<(Addr, Addr, usize)>,
    code_info: &Option<symbolize::CodeInfo>,
) {
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

/// The handler for the 'symbolize' command.
fn symbolize(symbolize: args::Symbolize) -> Result<()> {
    let symbolizer = Symbolizer::new();
    let (src, addrs) = match symbolize {
        args::Symbolize::Elf(args::Elf { path, addrs }) => {
            let src = symbolize::Source::from(symbolize::Elf::new(path));
            (src, addrs)
        }
        args::Symbolize::Process(args::Process { pid, addrs }) => {
            let src = symbolize::Source::from(symbolize::Process::new(pid));
            (src, addrs)
        }
    };

    let syms = symbolizer
        .symbolize(&src, symbolize::Input::VirtOffset(&addrs))
        .context("failed to symbolize addresses")?;

    for (input_addr, sym) in addrs.iter().copied().zip(syms) {
        match sym {
            symbolize::Symbolized::Sym(symbolize::Sym {
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
            symbolize::Symbolized::Unknown => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }
    Ok(())
}


fn main() -> Result<()> {
    let args = args::Args::parse();
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_span_events(FmtSpan::FULL)
        .with_timer(SystemTime)
        .finish();

    let () =
        set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;

    match args.command {
        args::Command::Normalize(normalize) => self::normalize(normalize),
        args::Command::Symbolize(symbolize) => self::symbolize(symbolize),
    }
}
