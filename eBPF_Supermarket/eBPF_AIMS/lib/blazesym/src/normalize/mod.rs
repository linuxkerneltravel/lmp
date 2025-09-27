//! Functionality for address normalization.
//!
//! Address normalization is one step of address symbolization. Typically only
//! used internally, it is also made accessible for users to enable remote
//! symbolization work flows. Remote symbolization refers to performing
//! symbolization on a system other than where the "raw" addresses were
//! originally captured. This is useful when working with embedded or locked
//! down systems, for example, where files necessary to perform the
//! symbolization are not available or not accessible.
//!
//! In such a setting address normalization would happen on the embedded device.
//! The result of this normalization would then be transferred to another one
//! that actually performs the symbolization.
//!
//! The [output][UserOutput] of address normalization is a set of file offsets
//! along with meta data. The meta data is expected to contain sufficient
//! information to identify the symbolization source to use (e.g., the ELF file
//! with symbols) on the symbolizing system.
//!
//! ```no_run
//! use blazesym::normalize::Normalizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! let normalizer = Normalizer::new();
//! let fopen_addr = libc::fopen as Addr;
//! let addrs = [fopen_addr];
//! let pid = Pid::Slf;
//! let normalized = normalizer.normalize_user_addrs(&addrs, pid).unwrap();
//! assert_eq!(normalized.outputs.len(), 1);
//!
//! let (file_offset, meta_idx) = normalized.outputs[0];
//! // fopen (0x7f5f8e23a790) corresponds to file offset 0x77790 within
//! // Elf(Elf { path: "/usr/lib64/libc.so.6", build_id: Some([...]), ... })
//! println!(
//!   "fopen ({fopen_addr:#x}) corresponds to file offset {file_offset:#x} within {:?}",
//!   normalized.meta[meta_idx]
//! );
//! ```

pub(crate) mod buildid;
mod meta;
mod normalizer;
mod user;

pub use meta::Apk;
pub use meta::Elf;
pub use meta::Unknown;
pub use meta::UserMeta;
pub use normalizer::Builder;
pub use normalizer::Normalizer;
// For reasons unknown, we need to `pub use` this type here or the documentation
// will not resolve links. See https://github.com/rust-lang/rust/issues/116854
#[doc(hidden)]
pub use normalizer::Output;
pub use user::UserOutput;

pub(crate) use user::create_apk_elf_path;
pub(crate) use user::normalize_sorted_user_addrs_with_entries;
pub(crate) use user::Handler;
