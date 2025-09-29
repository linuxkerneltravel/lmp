use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::PathBuf;

use crate::Pid;

#[cfg(doc)]
use super::Symbolizer;


/// A single APK file.
///
/// This type is used in the [`Source::Apk`] variant.
#[derive(Clone)]
pub struct Apk {
    /// The path to an APK file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Apk {
    /// Create a new [`Apk`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<Apk> for Source<'static> {
    fn from(apk: Apk) -> Self {
        Source::Apk(apk)
    }
}

impl Debug for Apk {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Apk {
            path,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Apk)).field(path).finish()
    }
}


/// A single ELF file.
///
/// This type is used in the [`Source::Elf`] variant.
#[derive(Clone)]
pub struct Elf {
    /// The path to an ELF file.
    ///
    /// It can be an executable or shared object.
    /// For example, passing `"/bin/sh"` will load symbols and debug information from `sh`.
    /// Whereas passing `"/lib/libc.so.xxx"` will load symbols and debug information from the libc.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Source<'static> {
    fn from(elf: Elf) -> Self {
        Source::Elf(elf)
    }
}

impl Debug for Elf {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Elf {
            path,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Elf)).field(path).finish()
    }
}


/// Linux Kernel's binary image and a copy of `/proc/kallsyms`.
///
/// This type is used in the [`Source::Kernel`] variant.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Kernel {
    /// The path of a kallsyms copy.
    ///
    /// For the running kernel on the device, it can be
    /// "/proc/kallsyms".  However, you can make a copy for later.
    /// In that situation, you should give the path of the
    /// copy.  Passing `None`, by default, will be
    /// `"/proc/kallsyms"`.
    pub kallsyms: Option<PathBuf>,
    /// The path of a kernel image.
    ///
    /// This should be the path of a kernel image.  For example,
    /// `"/boot/vmlinux-xxxx"`.  A `None` value will find the
    /// kernel image of the running kernel in `"/boot/"` or
    /// `"/usr/lib/debug/boot/"`.
    pub kernel_image: Option<PathBuf>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl From<Kernel> for Source<'static> {
    fn from(kernel: Kernel) -> Self {
        Source::Kernel(kernel)
    }
}


/// Configuration for process based address symbolization.
///
/// This type is used in the [`Source::Process`] variant.
///
/// The corresponding addresses supplied to [`Symbolizer::symbolize`] are
/// expected to be absolute addresses
/// ([`Input::AbsAddr`][crate::symbolize::Input::AbsAddr]) as valid within the
/// process identified by the [`pid`][Process::pid] member.
#[derive(Clone)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            _non_exhaustive: (),
        }
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Process {
            pid,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Process))
            // We use the `Display` representation here.
            .field(&format_args!("{pid}"))
            .finish()
    }
}

impl From<Process> for Source<'static> {
    fn from(process: Process) -> Self {
        Source::Process(process)
    }
}


/// Enumeration of supported Gsym sources.
///
/// This type is used in the [`Source::Gsym`] variant.
#[derive(Clone, Debug)]
pub enum Gsym<'dat> {
    /// "Raw" Gsym data.
    Data(GsymData<'dat>),
    /// A Gsym file.
    File(GsymFile),
}

/// Gsym data.
#[derive(Clone, Debug)]
pub struct GsymData<'dat> {
    /// The "raw" Gsym data.
    pub data: &'dat [u8],
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl<'dat> GsymData<'dat> {
    /// Create a new [`GsymData`] object, referencing the provided path.
    pub fn new(data: &'dat [u8]) -> Self {
        Self {
            data,
            _non_exhaustive: (),
        }
    }
}

impl<'dat> From<GsymData<'dat>> for Source<'dat> {
    fn from(gsym: GsymData<'dat>) -> Self {
        Source::Gsym(Gsym::Data(gsym))
    }
}


/// A Gsym file.
#[derive(Clone, Debug)]
pub struct GsymFile {
    /// The path to the Gsym file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl GsymFile {
    /// Create a new [`GsymFile`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<GsymFile> for Source<'static> {
    fn from(gsym: GsymFile) -> Self {
        Source::Gsym(Gsym::File(gsym))
    }
}


/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone)]
#[non_exhaustive]
pub enum Source<'dat> {
    /// A single APK file.
    Apk(Apk),
    /// A single ELF file.
    Elf(Elf),
    /// Information about the Linux kernel.
    Kernel(Kernel),
    /// Information about a process.
    Process(Process),
    /// A Gsym file.
    Gsym(Gsym<'dat>),
}

impl Debug for Source<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Apk(apk) => Debug::fmt(apk, f),
            Self::Elf(elf) => Debug::fmt(elf, f),
            Self::Kernel(kernel) => Debug::fmt(kernel, f),
            Self::Process(process) => Debug::fmt(process, f),
            Self::Gsym(gsym) => Debug::fmt(gsym, f),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let apk = Apk::new("/a-path/with/components.apk");
        assert_eq!(format!("{apk:?}"), "Apk(\"/a-path/with/components.apk\")");
        let src = Source::Apk(apk);
        assert_eq!(format!("{src:?}"), "Apk(\"/a-path/with/components.apk\")");

        let elf = Elf::new("/a-path/with/components.elf");
        assert_eq!(format!("{elf:?}"), "Elf(\"/a-path/with/components.elf\")");
        let src = Source::Elf(elf);
        assert_eq!(format!("{src:?}"), "Elf(\"/a-path/with/components.elf\")");

        let process = Process::new(Pid::Slf);
        assert_eq!(format!("{process:?}"), "Process(self)");
        let process = Process::new(Pid::from(1234));
        assert_eq!(format!("{process:?}"), "Process(1234)");
        let src = Source::Process(process);
        assert_eq!(format!("{src:?}"), "Process(1234)");
    }
}
