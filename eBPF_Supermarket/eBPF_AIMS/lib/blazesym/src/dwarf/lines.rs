// Based on gimli-rs/addr2line (https://github.com/gimli-rs/addr2line):
// > Copyright (c) 2016-2018 The gimli Developers
// >
// > Permission is hereby granted, free of charge, to any
// > person obtaining a copy of this software and associated
// > documentation files (the "Software"), to deal in the
// > Software without restriction, including without
// > limitation the rights to use, copy, modify, merge,
// > publish, distribute, sublicense, and/or sell copies of
// > the Software, and to permit persons to whom the Software
// > is furnished to do so, subject to the following
// > conditions:
// >
// > The above copyright notice and this permission notice
// > shall be included in all copies or substantial portions
// > of the Software.
// >
// > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// > ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// > TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// > PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// > SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// > CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// > OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// > IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// > DEALINGS IN THE SOFTWARE.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::mem;
use std::num::NonZeroU64;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use super::reader::R;


fn path_push<'p>(path: &'p Path, p: &'p Path) -> Cow<'p, Path> {
    if p.is_absolute() {
        Cow::Borrowed(p)
    } else {
        let mut path = Cow::Borrowed(path);
        let () = path.to_mut().push(p);
        path
    }
}

fn render_file<'dwarf>(
    dw_unit: &gimli::Unit<R<'dwarf>>,
    file: &gimli::FileEntry<R<'dwarf>, <R<'dwarf> as gimli::Reader>::Offset>,
    header: &gimli::LineProgramHeader<R<'dwarf>, <R<'dwarf> as gimli::Reader>::Offset>,
    sections: &gimli::Dwarf<R<'dwarf>>,
) -> Result<(Cow<'dwarf, Path>, &'dwarf OsStr), gimli::Error> {
    let dir = if let Some(ref comp_dir) = dw_unit.comp_dir {
        Path::new(OsStr::from_bytes(comp_dir.slice()))
    } else {
        Path::new("")
    };

    // The directory index 0 is defined to correspond to the compilation unit directory.
    let dir = if file.directory_index() != 0 {
        if let Some(directory) = file.directory(header) {
            let d = sections.attr_string(dw_unit, directory)?;
            path_push(dir, Path::new(OsStr::from_bytes(d.slice())))
        } else {
            Cow::default()
        }
    } else {
        Cow::default()
    };

    let f = sections.attr_string(dw_unit, file.path_name())?;
    let file = OsStr::from_bytes(f.slice());
    Ok((dir, file))
}


pub(crate) struct LineSequence {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) rows: Box<[LineRow]>,
}

pub(crate) struct LineRow {
    pub(crate) address: u64,
    pub(crate) file_index: u64,
    pub(crate) line: u32,
    pub(crate) column: u32,
}

pub(crate) struct Lines<'dwarf> {
    pub(crate) files: Box<[(Cow<'dwarf, Path>, &'dwarf OsStr)]>,
    pub(crate) sequences: Box<[LineSequence]>,
}

impl<'dwarf> Lines<'dwarf> {
    pub(crate) fn parse(
        dw_unit: &gimli::Unit<R<'dwarf>>,
        ilnp: gimli::IncompleteLineProgram<R<'dwarf>, <R<'dwarf> as gimli::Reader>::Offset>,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Self, gimli::Error> {
        let mut sequences = Vec::new();
        let mut sequence_rows = Vec::<LineRow>::new();
        let mut rows = ilnp.rows();
        while let Some((_, row)) = rows.next_row()? {
            if row.end_sequence() {
                if let Some(start) = sequence_rows.first().map(|x| x.address) {
                    let end = row.address();
                    let mut rows = Vec::new();
                    mem::swap(&mut rows, &mut sequence_rows);
                    sequences.push(LineSequence {
                        start,
                        end,
                        rows: rows.into_boxed_slice(),
                    });
                }
                continue
            }

            let address = row.address();
            let file_index = row.file_index();
            let line = row.line().map(NonZeroU64::get).unwrap_or(0) as u32;
            let column = match row.column() {
                gimli::ColumnType::LeftEdge => 0,
                gimli::ColumnType::Column(x) => x.get() as u32,
            };

            if let Some(last_row) = sequence_rows.last_mut() {
                if last_row.address == address {
                    last_row.file_index = file_index;
                    last_row.line = line;
                    last_row.column = column;
                    continue
                }
            }

            sequence_rows.push(LineRow {
                address,
                file_index,
                line,
                column,
            });
        }
        sequences.sort_by_key(|x| x.start);

        let mut files = Vec::new();
        let header = rows.header();
        match header.file(0) {
            Some(file) => files.push(render_file(dw_unit, file, header, sections)?),
            None => files.push(Default::default()), // DWARF version <= 4 may not have 0th index
        }
        let mut index = 1;
        while let Some(file) = header.file(index) {
            files.push(render_file(dw_unit, file, header, sections)?);
            index += 1;
        }

        Ok(Self {
            files: files.into_boxed_slice(),
            sequences: sequences.into_boxed_slice(),
        })
    }
}
