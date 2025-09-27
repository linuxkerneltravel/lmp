//! Functionality for inspecting files such as ELF or Gsym.
//!
//! ```no_run
//! use blazesym::inspect;
//! use blazesym::inspect::Inspector;
//!
//! let src = inspect::Source::Elf(inspect::Elf::new("/usr/bin/libc.so"));
//! let inspector = Inspector::new();
//! let results = inspector
//!     .lookup(&["fopen"], &src)
//!     .unwrap();
//!
//! // `results` contains a list of addresses of `fopen` symbols in `libc`.
//! // There probably will only be a single one.
//! ```

#[cfg_attr(not(feature = "dwarf"), allow(unused_variables))]
mod inspector;
mod source;

use std::path::PathBuf;

use crate::Addr;

pub use inspector::Inspector;
pub use source::Elf;
pub use source::Source;


/// The type of a symbol.
#[derive(Clone, Copy, Debug, Default)]
pub enum SymType {
    /// The symbol type is unknown.
    #[default]
    Unknown,
    /// The symbol is a function.
    Function,
    /// The symbol is a variable.
    Variable,
}


/// Information about a symbol.
#[derive(Clone, Debug)]
pub struct SymInfo {
    /// The name of the symbol; for example, a function name.
    pub name: String,
    /// Start address (the first byte) of the symbol.
    pub addr: Addr,
    /// The size of the symbol. The size of a function for example.
    pub size: usize,
    /// A function or a variable.
    pub sym_type: SymType,
    /// The offset in the object file.
    pub file_offset: u64,
    /// The file name of the shared object.
    pub obj_file_name: Option<PathBuf>,
}


/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[derive(Debug, Default)]
pub(crate) struct FindAddrOpts {
    /// Return the offset of the symbol from the first byte of the
    /// object file if it is true. (False by default)
    pub offset_in_file: bool,
    /// Return the name of the object file if it is true. (False by default)
    pub obj_file_name: bool,
    /// Return the symbol(s) matching a given type. Unknown, by default,
    /// means all types.
    pub sym_type: SymType,
}
