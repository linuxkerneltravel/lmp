use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::Result;

use blazesym::Addr;
use blazesym::Pid;

use clap::ArgAction;
use clap::Args as Arguments;
use clap::Parser;
use clap::Subcommand;


/// Parse a PID from a string.
fn parse_pid(s: &str) -> Result<Pid> {
    let pid = if let Some(s) = s.strip_prefix("0x") {
        u32::from_str_radix(s, 16)
    } else {
        s.parse::<u32>()
    }
    .with_context(|| format!("failed to parse PID: {s}"))?;

    Ok(Pid::from(pid))
}

/// Parse an address from a string.
fn parse_addr(s: &str) -> Result<Addr> {
    // In our world addresses are always represented in hex, with or without 0x
    // prefix.
    Addr::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {s}"))
}


/// A command line interface for blazesym.
#[derive(Debug, Parser)]
#[clap(version = env!("VERSION"))]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
    /// Increase verbosity (can be supplied multiple times).
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbosity: u8,
}


#[derive(Debug, Subcommand)]
pub enum Command {
    /// Normalize one or more addresses.
    #[command(subcommand)]
    Normalize(Normalize),
    /// Symbolize one or more addresses.
    #[command(subcommand)]
    Symbolize(Symbolize),
}


/// A type representing the `normalize` command.
#[derive(Debug, Subcommand)]
pub enum Normalize {
    /// Normalize user space addresses.
    User(User),
}

#[derive(Debug, Arguments)]
pub struct User {
    /// The PID of the process the provided addresses belong to.
    #[clap(short, long)]
    #[arg(value_parser = parse_pid)]
    pub pid: Pid,
    /// The addresses to normalize.
    #[arg(value_parser = parse_addr)]
    pub addrs: Vec<Addr>,
}


/// A type representing the `symbolize` command.
#[derive(Debug, Subcommand)]
pub enum Symbolize {
    Elf(Elf),
    Process(Process),
}

#[derive(Debug, Arguments)]
pub struct Elf {
    /// The path to the ELF file.
    #[clap(short, long)]
    pub path: PathBuf,
    /// The addresses to symbolize.
    ///
    /// Addresses are assumed to already be normalized to the file
    /// itself (i.e., with relocation and address randomization effects
    /// removed).
    #[arg(value_parser = parse_addr)]
    pub addrs: Vec<Addr>,
}

#[derive(Debug, Arguments)]
pub struct Process {
    /// The PID of the process the provided addresses belong to.
    #[clap(short, long)]
    #[arg(value_parser = parse_pid)]
    pub pid: Pid,
    /// The addresses to symbolize.
    #[arg(value_parser = parse_addr)]
    pub addrs: Vec<Addr>,
}
