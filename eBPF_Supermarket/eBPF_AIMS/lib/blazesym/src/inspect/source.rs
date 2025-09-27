use std::path::Path;
use std::path::PathBuf;


/// An ELF file.
#[derive(Clone, Debug, PartialEq)]
pub struct Elf {
    /// The path to the ELF file.
    pub path: PathBuf,
    /// Whether or not to consult debug information to satisfy the request (if
    /// present).
    pub debug_info: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            debug_info: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Source {
    fn from(elf: Elf) -> Self {
        Source::Elf(elf)
    }
}


/// The source to use for the inspection request.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Source {
    /// The source is an ELF file.
    Elf(Elf),
}

impl Source {
    /// Retrieve the path to the source, if it has any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Elf(elf) => Some(&elf.path),
        }
    }
}
