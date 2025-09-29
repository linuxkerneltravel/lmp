use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::ops::Range;
use std::path::PathBuf;

use crate::Addr;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Pid;
use crate::Result;


#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct EntryPath {
    /// The path of the file backing the maps entry via a
    /// `/proc/<xxx>/map_files/` component.
    ///
    /// This path should generally be used on the local system, unless perhaps
    /// for reporting purposes (for which `path` below may be more appropriate).
    pub maps_file: PathBuf,
    /// The path to the file backing the proc maps entry as found directly in
    /// the `/proc/<xxx>/maps` file. This path should generally only be used for
    /// reporting matters or outside of the system on which proc maps was
    /// parsed. This path has been sanitized and no longer contains any
    /// `(deleted)` suffixes.
    pub symbolic_path: PathBuf,
}


/// The "pathname" component in a proc maps entry. See `proc(5)` section
/// `/proc/[pid]/maps`.
#[derive(Debug, PartialEq)]
pub(crate) enum PathName {
    Path(EntryPath),
    Component(String),
}

impl PathName {
    #[cfg(test)]
    pub fn as_path(&self) -> Option<&EntryPath> {
        match self {
            Self::Path(path) => Some(path),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn as_component(&self) -> Option<&str> {
        match self {
            Self::Component(comp) => Some(comp),
            _ => None,
        }
    }
}


#[derive(Debug)]
pub(crate) struct MapsEntry {
    /// The virtual address range covered by this entry.
    pub range: Range<Addr>,
    pub mode: u8,
    pub offset: u64,
    pub path_name: Option<PathName>,
}


/// An already filtered `MapsEntry` that is guaranteed to contain a path.
pub(crate) struct PathMapsEntry {
    /// The virtual address range covered by this entry.
    pub range: Range<Addr>,
    pub mode: u8,
    pub offset: u64,
    pub path: EntryPath,
}

impl Debug for PathMapsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let PathMapsEntry {
            range,
            mode,
            offset,
            path,
        } = self;

        f.debug_struct(stringify!(PathMapsEntry))
            .field(stringify!(range), &format_args!("{range:#x?}"))
            .field(stringify!(mode), &format_args!("{mode:#06b}"))
            .field(stringify!(offset), &format_args!("{offset:#x}"))
            .field(stringify!(path), &path)
            .finish()
    }
}


/// Parse a line of a proc maps file.
fn parse_maps_line<'line>(line: &'line str, pid: Pid) -> Result<MapsEntry> {
    let full_line = line;

    let split_once = |line: &'line str, component| -> Result<(&'line str, &'line str)> {
        line.split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_invalid_data(|| {
                format!("failed to find {component} in proc maps line: {line}\n{full_line}")
            })
    };

    // Lines have the following format:
    // address           perms offset  dev   inode      pathname
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
    // a7cb1000-a7cb2000 ---p 00000000 00:00 0
    // a7ed5000-a8008000 r-xp 00000000 03:00 4222       /lib/libc.so.6
    let (address_str, line) = split_once(line, "address range")?;
    let (loaded_str, end_str) = address_str.split_once('-').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed address range in proc maps line: {full_line}"),
        )
    })?;
    let loaded_addr = Addr::from_str_radix(loaded_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed start address in proc maps line: {full_line}: {err}"),
        )
    })?;
    let end_addr = Addr::from_str_radix(end_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed end address in proc maps line: {full_line}: {err}"),
        )
    })?;

    let (mode_str, line) = split_once(line, "permissions component")?;
    let mode = mode_str
        .chars()
        .fold(0, |mode, c| (mode << 1) | u8::from(c != '-'));

    let (offset_str, line) = split_once(line, "offset component")?;
    let offset = u64::from_str_radix(offset_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed offset component in proc maps line: {full_line}: {err}"),
        )
    })?;

    let (_dev, line) = split_once(line, "device component")?;
    // Note that by design, a path may not be present and so we may not be able
    // to successfully split.
    let path_str = split_once(line, "inode component")
        .map(|(_inode, line)| line.trim())
        .unwrap_or("");

    let path_name = match path_str.as_bytes() {
        [] => None,
        [b'/', ..] => {
            let symbolic_path =
                PathBuf::from(path_str.strip_suffix(" (deleted)").unwrap_or(path_str));
            // TODO: May have to resolve the symbolic link in case of
            //       `Pid::Slf` here for remote symbolization use cases.
            let maps_file = PathBuf::from(format!(
                "/proc/{pid}/map_files/{loaded_addr:x}-{end_addr:x}"
            ));
            Some(PathName::Path(EntryPath {
                maps_file,
                symbolic_path,
            }))
        }
        // This variant would typically capture components such as `[vdso]` or
        // `[heap]`, but we can't rely on square brackets being present
        // unconditionally, as variants such as `anon_inode:bpf-map` are also
        // possible.
        [..] => Some(PathName::Component(path_str.to_string())),
    };

    let entry = MapsEntry {
        range: (loaded_addr..end_addr),
        mode,
        offset,
        path_name,
    };
    Ok(entry)
}


#[derive(Debug)]
struct MapsEntryIter<R> {
    reader: R,
    line: String,
    pid: Pid,
}

impl<R> Iterator for MapsEntryIter<R>
where
    R: BufRead,
{
    type Item = Result<MapsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let () = self.line.clear();
            match self.reader.read_line(&mut self.line) {
                Err(err) => return Some(Err(err.into())),
                Ok(0) => break None,
                Ok(_) => {
                    let line_str = self.line.trim();
                    // There shouldn't be any empty lines, but we'd just ignore them. We
                    // need to trim anyway.
                    if !line_str.is_empty() {
                        let result = parse_maps_line(line_str, self.pid);
                        break Some(result)
                    }
                }
            }
        }
    }
}


/// Parse a proc maps file from the provided reader.
///
/// `filter` is a filter function (similar to those usable on iterators)
/// that determines which entries we keep (those for which it returned
/// `true`) and which we discard (anything `false`).
pub(crate) fn parse_file<R>(reader: R, pid: Pid) -> impl Iterator<Item = Result<MapsEntry>>
where
    R: Read,
{
    MapsEntryIter {
        reader: BufReader::new(reader),
        line: String::new(),
        pid,
    }
}

/// Parse the maps file for the process with the given PID.
pub(crate) fn parse(pid: Pid) -> Result<impl Iterator<Item = Result<MapsEntry>>> {
    let path = format!("/proc/{pid}/maps");
    let file =
        File::open(&path).with_context(|| format!("failed to open proc maps file {path}"))?;
    let iter = parse_file(file, pid);
    Ok(iter)
}

/// A helper function checking whether a `MapsEntry` has relevance to
/// symbolization efforts and converting it accordingly.
pub(crate) fn filter_map_relevant(entry: MapsEntry) -> Option<PathMapsEntry> {
    let MapsEntry {
        range,
        mode,
        offset,
        path_name,
    } = entry;

    // Only entries that are executable (--x-) are of relevance.
    if (mode & 0b0010) != 0b0010 {
        return None
    }

    match path_name {
        Some(PathName::Path(path)) => Some(PathMapsEntry {
            range,
            mode,
            offset,
            path,
        }),
        _ => None,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use test_log::test;


    /// Check that the `Debug` representation of [`Entry`] is as expected.
    #[test]
    fn path_maps_entry_debug() {
        let entry = PathMapsEntry {
            range: 0x1000..0x1337,
            mode: 0b10,
            offset: 0x5000,
            path: EntryPath {
                maps_file: PathBuf::from("/proc/1234/maps_files/559cf1bdf000-559cf1be0000"),
                symbolic_path: PathBuf::from("/lib64/libc.so.6"),
            },
        };

        let dbg = format!("{entry:?}");
        assert!(
            dbg.starts_with(
                r#"PathMapsEntry { range: 0x1000..0x1337, mode: 0b0010, offset: 0x5000, "#
            ),
            "{dbg}"
        );
    }

    /// Check that we can parse `/proc/self/maps`.
    #[allow(clippy::suspicious_map)]
    #[test]
    fn self_map_parsing() {
        let maps = parse(Pid::Slf).unwrap();
        assert_ne!(maps.map(|entry| entry.unwrap()).count(), 0);
    }

    /// Make sure that we can parse proc maps lines correctly.
    #[test]
    fn map_line_parsing() {
        let lines = r#"
00400000-00401000 r--p 00000000 00:29 47459                              /tmp/test/test
00401000-00402000 r-xp 00001000 00:29 47459                              /tmp/test/test
00402000-00403000 r--p 00002000 00:29 47459                              /tmp/test/test
00403000-00404000 r--p 00002000 00:29 47459                              /tmp/test/test
00404000-00405000 rw-p 00003000 00:29 47459                              /tmp/test/test
55f4a95c9000-55f4a95cb000 r--p 00000000 00:20 41445                      /usr/bin/cat
55f4a95cb000-55f4a95cf000 r-xp 00002000 00:20 41445                      /usr/bin/cat
55f4a95cf000-55f4a95d1000 r--p 00006000 00:20 41445                      /usr/bin/cat
55f4a95d1000-55f4a95d2000 r--p 00007000 00:20 41445                      /usr/bin/cat
55f4a95d2000-55f4a95d3000 rw-p 00008000 00:20 41445                      /usr/bin/cat
55f4aa379000-55f4aa39a000 rw-p 00000000 00:00 0                          [heap]
7f1273b05000-7f1273b06000 r--s 00000000 00:13 19                         /sys/fs/selinux/status
7f2321e00000-7f2321e37000 r--p 00000000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321e37000-7f2321f6f000 r-xp 00037000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321f6f000-7f2322009000 r--p 0016f000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2322009000-7f232201b000 r--p 00208000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f232201b000-7f232201d000 rw-p 0021a000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7fa7ade00000-7fa7bb3b7000 r--p 00000000 00:20 12022451                   /usr/lib/locale/locale-archive
7fa7bb400000-7fa7bb428000 r--p 00000000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb428000-7fa7bb59c000 r-xp 00028000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb59c000-7fa7bb5f4000 r--p 0019c000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f4000-7fa7bb5f8000 r--p 001f3000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f8000-7fa7bb5fa000 rw-p 001f7000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5fa000-7fa7bb602000 rw-p 00000000 00:00 0
7fa7bb721000-7fa7bb746000 rw-p 00000000 00:00 0
7fa7bb758000-7fa7bb75a000 rw-p 00000000 00:00 0
7fa7bb75a000-7fa7bb75c000 r--p 00000000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb75c000-7fa7bb783000 r-xp 00002000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb783000-7fa7bb78e000 r--p 00029000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb78f000-7fa7bb791000 r--p 00034000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb791000-7fa7bb793000 rw-p 00036000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7ff8d9eab000-7ff8d9ecc000 rw-s 00000000 00:0e 2057                       anon_inode:[perf_event]
7ff8d9ecc000-7ff8d9eed000 rw-s 00000000 00:0e 2057                       anon_inode:[perf_event]
7ff8d9f2d000-7ff8d9f2e000 r--s 00000000 00:0e 2057                       anon_inode:bpf-map
7ff8d9f6f000-7ff8d9f70000 r--s 00000000 00:0e 2057                       anon_inode:bpf-map
7ffd03212000-7ffd03234000 rw-p 00000000 00:00 0                          [stack]
7ffd033a7000-7ffd033ab000 r--p 00000000 00:00 0                          [vvar]
7ffd033ab000-7ffd033ad000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
"#;

        let entries = parse_file(lines.as_bytes(), Pid::Slf);
        let () = entries.for_each(|entry| {
            let _entry = entry.unwrap();
        });

        // Parse the first (actual) line.
        let entry = parse_maps_line(lines.lines().nth(1).unwrap(), Pid::Slf).unwrap();
        assert_eq!(entry.range.start, 0x400000);
        assert_eq!(entry.range.end, 0x401000);
        assert_eq!(
            entry
                .path_name
                .as_ref()
                .unwrap()
                .as_path()
                .unwrap()
                .maps_file,
            Path::new("/proc/self/map_files/400000-401000")
        );

        let entry = parse_maps_line(lines.lines().nth(7).unwrap(), Pid::Slf).unwrap();
        assert_eq!(entry.range.start, 0x55f4a95cb000);
        assert_eq!(entry.range.end, 0x55f4a95cf000);
        assert_eq!(entry.mode, 0b1011);
        assert_eq!(
            entry
                .path_name
                .as_ref()
                .unwrap()
                .as_path()
                .unwrap()
                .maps_file,
            Path::new("/proc/self/map_files/55f4a95cb000-55f4a95cf000")
        );
        assert_eq!(entry.path_name.as_ref().unwrap().as_component(), None);

        let entry = parse_maps_line(lines.lines().nth(11).unwrap(), Pid::Slf).unwrap();
        assert_eq!(entry.range.start, 0x55f4aa379000);
        assert_eq!(entry.range.end, 0x55f4aa39a000);
        assert_eq!(entry.mode, 0b1101);
        assert_eq!(
            entry.path_name.as_ref().unwrap().as_component().unwrap(),
            "[heap]",
        );
        assert_eq!(entry.path_name.as_ref().unwrap().as_path(), None);

        let entry = parse_maps_line(lines.lines().nth(13).unwrap(), Pid::Slf).unwrap();
        assert_eq!(entry.mode, 0b1001);
        assert_eq!(
            entry
                .path_name
                .as_ref()
                .unwrap()
                .as_path()
                .unwrap()
                .maps_file,
            Path::new("/proc/self/map_files/7f2321e00000-7f2321e37000")
        );
    }

    /// Check that we error out as expected on malformed proc maps lines.
    #[test]
    fn malformed_proc_maps_lines() {
        let lines = [
            "7fa7bb75a000+7fa7bb75c000",
            "7fa7bb75a000-7fa7bb75c000",
            "7fa7b$#5a000-7fa7bb75c000",
            "7fa7bb75a000-7fa7@%@5c000",
            "7fa7bb75a000+7fa7bb75c000 r--p",
            "7fa7bb75a000-7fa7bb75c000 r--p",
            "7fa7b$#5a000-7fa7bb75c000 r--p",
            "7fa7bb75a000-7fa7@%@5c000 r--p",
            "7fa7bb75a000-7fa7bb75c000 r--p",
            "7fa7bb75a000-7fa7bb75c000 r--p 00000000",
            "7fa7bb75a000-7fa7bb75c000 r--p 000zz000 00:20",
        ];

        let () = lines.iter().for_each(|line| {
            let _err = parse_maps_line(line, Pid::Slf).unwrap_err();
        });
    }
}
