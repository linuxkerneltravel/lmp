use std::path::PathBuf;


/// A GNU build ID, as raw bytes.
type BuildId = Vec<u8>;


/// Meta information about an APK.
///
/// This type is used in the [`UserMeta::Apk`] variant.
///
/// The corresponding file offset is normalized only to the APK container, not
/// any potential internal ELF files. Use the
/// [`Apk`][crate::symbolize::Source::Apk] symbolization source in order to
/// symbolize the offset:
/// ```no_run
/// # use std::path::Path;
/// # use blazesym::Pid;
/// # use blazesym::normalize;
/// # use blazesym::symbolize;
/// # let capture_addr_in_elf_in_apk = || 0xdeadbeef;
/// let addr_in_elf_in_apk = capture_addr_in_elf_in_apk();
/// let normalizer = normalize::Normalizer::new();
/// let normalized = normalizer
///     .normalize_user_addrs_sorted([addr_in_elf_in_apk].as_slice(), Pid::Slf)
///     .unwrap();
/// let (output, meta_idx) = normalized.outputs[0];
/// let meta = &normalized.meta[meta_idx];
/// let apk = meta.apk().unwrap();
///
/// // We assume that we have the APK lying around at the same path as on the
/// // "remote" system.
/// let src = symbolize::Source::from(symbolize::Apk::new(&apk.path));
/// let symbolizer = symbolize::Symbolizer::new();
/// let sym = symbolizer
///   .symbolize_single(&src, symbolize::Input::FileOffset(output))
///   .unwrap()
///   .into_sym()
///   .unwrap();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Apk {
    /// The canonical absolute path to the APK, including its name.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


/// Meta information about an ELF file (executable, shared object, ...).
///
/// This type is used in the [`UserMeta::Elf`] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct Elf {
    /// The canonical absolute path to the ELF file, including its name.
    pub path: PathBuf,
    /// The ELF file's build ID, if available.
    pub build_id: Option<BuildId>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


/// Meta information about an address that could not be determined to be
/// belonging to a specific component.
///
/// This type is used in the [`UserMeta::Unknown`] variant.
///
/// An unknown address will be reported in non-normalized form (i.e., as
/// provided as input by the user).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unknown {
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl From<Unknown> for UserMeta {
    fn from(unknown: Unknown) -> Self {
        Self::Unknown(unknown)
    }
}


/// Meta information for an address.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum UserMeta {
    /// The address belongs to an APK file.
    Apk(Apk),
    /// The address belongs to an ELF file.
    Elf(Elf),
    /// The address' origin is unknown.
    Unknown(Unknown),
}

impl UserMeta {
    /// Retrieve the [`Apk`] of this enum, if this variant is active.
    pub fn apk(&self) -> Option<&Apk> {
        match self {
            Self::Apk(entry) => Some(entry),
            _ => None,
        }
    }

    /// Retrieve the [`Elf`] of this enum, if this variant is active.
    pub fn elf(&self) -> Option<&Elf> {
        match self {
            Self::Elf(elf) => Some(elf),
            _ => None,
        }
    }

    /// Retrieve the [`Unknown`] of this enum, if this variant is active.
    pub fn unknown(&self) -> Option<&Unknown> {
        match self {
            Self::Unknown(unknown) => Some(unknown),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can access individual variants of a
    /// [`UserMeta`] via the accessor functions.
    #[test]
    fn user_addr_meta_accessors() {
        let meta = UserMeta::Apk(Apk {
            path: PathBuf::from("/tmp/archive.apk"),
            _non_exhaustive: (),
        });
        assert!(meta.apk().is_some());
        assert!(meta.elf().is_none());
        assert!(meta.unknown().is_none());

        let meta = UserMeta::Elf(Elf {
            path: PathBuf::from("/tmp/executable.bin"),
            build_id: None,
            _non_exhaustive: (),
        });
        assert!(meta.apk().is_none());
        assert!(meta.elf().is_some());
        assert!(meta.unknown().is_none());

        let meta = UserMeta::Unknown(Unknown {
            _non_exhaustive: (),
        });
        assert!(meta.apk().is_none());
        assert!(meta.elf().is_none());
        assert!(meta.unknown().is_some());
    }
}
