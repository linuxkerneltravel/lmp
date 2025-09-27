//! Functionality for symbolizing addresses.
//!
//! This module contains functionality for symbolizing addresses, i.e., finding
//! symbol names and other information based on "raw" addresses.
//!
//! For example, here we symbolize the backtrace captured via `libc`'s
//! `backtrace` function:
//! ```no_run
//! # use std::cmp::min;
//! # use std::mem::size_of;
//! # use std::mem::transmute;
//! # use std::ptr;
//! use blazesym::symbolize::CodeInfo;
//! use blazesym::symbolize::Input;
//! use blazesym::symbolize::Process;
//! use blazesym::symbolize::Source;
//! use blazesym::symbolize::Sym;
//! use blazesym::symbolize::Symbolized;
//! use blazesym::symbolize::Symbolizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! const ADDR_WIDTH: usize = 16;
//!
//! fn print_frame(
//!     name: &str,
//!     addr_info: Option<(Addr, Addr, usize)>,
//!     code_info: &Option<CodeInfo>,
//! ) {
//!     let code_info = code_info.as_ref().map(|code_info| {
//!         let path = code_info.to_path();
//!         let path = path.display();
//!
//!         match (code_info.line, code_info.column) {
//!             (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
//!             (Some(line), None) => format!(" {path}:{line}"),
//!             (None, _) => format!(" {path}"),
//!         }
//!     });
//!
//!     if let Some((input_addr, addr, offset)) = addr_info {
//!         // If we have various address information bits we have a new symbol.
//!         println!(
//!             "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
//!             code_info = code_info.as_deref().unwrap_or(""),
//!             width = ADDR_WIDTH
//!         )
//!     } else {
//!         // Otherwise we are dealing with an inlined call.
//!         println!(
//!             "{:width$}  {name}{code_info} [inlined]",
//!             " ",
//!             code_info = code_info
//!                 .map(|info| format!(" @{info}"))
//!                 .as_deref()
//!                 .unwrap_or(""),
//!             width = ADDR_WIDTH
//!         )
//!     }
//! }
//!
//! # assert_eq!(size_of::<*mut libc::c_void>(), size_of::<Addr>());
//! // Retrieve up to 64 stack frames of the calling thread.
//! const MAX_CNT: usize = 64;
//!
//! let mut addrs_buf = [ptr::null_mut::<libc::c_void>(); MAX_CNT];
//! let addr_cnt = unsafe { libc::backtrace(addrs_buf.as_mut_ptr(), MAX_CNT as _) } as usize;
//! let addrs = &addrs_buf[0..min(addr_cnt, MAX_CNT)];
//! # let addrs = unsafe { transmute::<&[*mut libc::c_void], &[Addr]>(addrs) };
//!
//! // Symbolize the addresses for the current process, as that's where
//! // they were captured.
//! let src = Source::Process(Process::new(Pid::Slf));
//! let symbolizer = Symbolizer::new();
//! let syms = symbolizer.symbolize(&src, Input::AbsAddr(addrs)).unwrap();
//!
//! for (input_addr, sym) in addrs.iter().copied().zip(syms) {
//!     match sym {
//!         Symbolized::Sym(Sym {
//!             name,
//!             addr,
//!             offset,
//!             code_info,
//!             inlined,
//!             ..
//!         }) => {
//!             print_frame(&name, Some((input_addr, addr, offset)), &code_info);
//!             for frame in inlined.iter() {
//!                 print_frame(&frame.name, None, &frame.code_info);
//!             }
//!         }
//!         Symbolized::Unknown => {
//!             println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
//!         }
//!     }
//! }
//! ```

mod source;
mod symbolizer;

use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

pub use source::Apk;
pub use source::Elf;
pub use source::Gsym;
pub use source::GsymData;
pub use source::GsymFile;
pub use source::Kernel;
pub use source::Process;
pub use source::Source;
pub use symbolizer::Builder;
pub use symbolizer::Symbolizer;

use crate::Addr;


/// A enumeration of the different input types the symbolization APIs
/// support.
#[derive(Clone, Copy, Debug)]
pub enum Input<T> {
    /// An absolute address.
    ///
    /// A absolute address is an address as a process would see it, for example.
    /// It may include relocation or address space randomization artifacts.
    AbsAddr(T),
    /// A virtual offset.
    ///
    /// A virtual offset is an address as it would appear in a binary or debug
    /// symbol file.
    VirtOffset(T),
    /// A file offset.
    ///
    /// A file offset is the linear offset of a symbol in a file.
    FileOffset(T),
}

#[cfg(test)]
impl<T> Input<&[T]>
where
    T: Copy,
{
    fn try_to_single(&self) -> Option<Input<T>> {
        match self {
            Self::AbsAddr([addr]) => Some(Input::AbsAddr(*addr)),
            Self::VirtOffset([addr]) => Some(Input::VirtOffset(*addr)),
            Self::FileOffset([offset]) => Some(Input::FileOffset(*offset)),
            _ => None,
        }
    }
}


#[derive(Debug, PartialEq)]
pub(crate) struct FrameCodeInfo<'src> {
    pub dir: &'src Path,
    pub file: &'src OsStr,
    pub line: Option<u32>,
    pub column: Option<u16>,
}

impl From<&FrameCodeInfo<'_>> for CodeInfo {
    fn from(other: &FrameCodeInfo<'_>) -> Self {
        Self {
            dir: Some(other.dir.to_path_buf()),
            file: other.file.to_os_string(),
            line: other.line,
            column: other.column,
            _non_exhaustive: (),
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct AddrCodeInfo<'src> {
    /// Source information about the top-level frame belonging to an
    /// address.
    ///
    /// It also contains an optional name, which is necessary for
    /// formats where inline information can "correct" (overwrite) the
    /// name of the symbol.
    pub direct: (Option<&'src str>, FrameCodeInfo<'src>),
    /// Source information about inlined functions, along with their names.
    pub inlined: Vec<(&'src str, Option<FrameCodeInfo<'src>>)>,
}


/// Source code location information for a symbol or inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct CodeInfo {
    /// The directory in which the source file resides.
    pub dir: Option<PathBuf>,
    /// The file that defines the symbol.
    pub file: OsString,
    /// The line number of the symbolized instruction in the source
    /// code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line: Option<u32>,
    /// The column number of the symbolized instruction in the source
    /// code.
    pub column: Option<u16>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}

impl CodeInfo {
    /// Helper method to retrieve the path to the represented source file,
    /// on a best-effort basis. It depends on the symbolization source data
    /// whether this path is absolute or relative and, if its the latter, what
    /// directory it is relative to. In general this path is mostly intended for
    /// displaying purposes.
    #[inline]
    pub fn to_path(&self) -> Cow<'_, Path> {
        self.dir.as_ref().map_or_else(
            || Cow::Borrowed(Path::new(&self.file)),
            |dir| Cow::Owned(dir.join(&self.file)),
        )
    }
}


/// A type representing an inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct InlinedFn {
    /// The symbol name of the inlined function.
    pub name: String,
    /// Source code location information for the call to the function.
    pub code_info: Option<CodeInfo>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}


/// The result of address symbolization by [`Symbolizer`].
#[derive(Clone, Debug, PartialEq)]
pub struct Sym {
    /// The symbol name that an address belongs to.
    pub name: String,
    /// The address at which the symbol is located (i.e., its "start").
    ///
    /// This is the "normalized" address of the symbol, as present in
    /// the file (and reported by tools such as `readelf(1)`,
    /// `llvm-gsymutil`, or similar).
    pub addr: Addr,
    /// The byte offset of the address that got symbolized from the
    /// start of the symbol (i.e., from `addr`).
    ///
    /// E.g., when normalizing address 0x1337 of a function that starts at
    /// 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
    /// member is especially useful in contexts when input addresses are not
    /// already normalized, such as when normalizing an address in a process
    /// context (which may have been relocated and/or have layout randomizations
    /// applied).
    pub offset: usize,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// Source code location information for the symbol.
    pub code_info: Option<CodeInfo>,
    /// Inlined function information, if requested and available.
    ///
    /// Availability depends on both the underlying symbolization source (e.g.,
    /// ELF does not contain inline information, but DWARF does) as well as
    /// whether a function was actually inlined at the address in question.
    ///
    /// Inlined functions are reported in the order in which their calls are
    /// nested. For example, if the instruction at the address to symbolize
    /// falls into a function `f` at an inlined call to `g`, which in turn
    /// contains an inlined call to `h`, the symbols will be reported in the
    /// order `f`, `g`, `h`.
    pub inlined: Box<[InlinedFn]>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}


/// An enumeration used as reporting vehicle for address symbolization.
// We keep this enum as exhaustive because additions to it, should they occur,
// are expected to be backwards-compatibility breaking.
#[derive(Clone, Debug, PartialEq)]
pub enum Symbolized {
    /// The input address was symbolized as the provided symbol.
    Sym(Sym),
    /// The input address was not found and could not be symbolized.
    Unknown,
}

impl Symbolized {
    /// Convert the object into a [`Sym`] reference, if the corresponding
    /// variant is active.
    #[inline]
    pub fn as_sym(&self) -> Option<&Sym> {
        match self {
            Self::Sym(sym) => Some(sym),
            Self::Unknown => None,
        }
    }

    /// Convert the object into a [`Sym`] object, if the corresponding variant
    /// is active.
    #[inline]
    pub fn into_sym(self) -> Option<Sym> {
        match self {
            Self::Sym(sym) => Some(sym),
            Self::Unknown => None,
        }
    }
}
