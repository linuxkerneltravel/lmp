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

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::path::Path;

use super::lines::LineSequence;
use super::lines::Lines;
use super::reader::R;
use super::unit::Unit;


/// A source location.
#[derive(Debug, PartialEq)]
pub struct Location<'dwarf> {
    /// The directory.
    pub dir: &'dwarf Path,
    /// The file name.
    pub file: &'dwarf OsStr,
    /// The line number.
    pub line: Option<u32>,
    /// The column number.
    pub column: Option<u32>,
}


pub(super) struct LocationRangeUnitIter<'unit, 'dwarf> {
    lines: &'unit Lines<'dwarf>,
    seqs: &'unit [LineSequence],
    seq_idx: usize,
    row_idx: usize,
    probe_high: u64,
}

impl<'unit, 'dwarf> LocationRangeUnitIter<'unit, 'dwarf> {
    pub(super) fn new(
        unit: &'unit Unit<'dwarf>,
        sections: &gimli::Dwarf<R<'dwarf>>,
        probe_low: u64,
        probe_high: u64,
    ) -> Result<Option<Self>, gimli::Error> {
        let lines = unit.parse_lines(sections)?;

        if let Some(lines) = lines {
            // Find index for probe_low.
            let seq_idx = lines.sequences.binary_search_by(|sequence| {
                if probe_low < sequence.start {
                    Ordering::Greater
                } else if probe_low >= sequence.end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            });
            let seq_idx = match seq_idx {
                Ok(x) => x,
                Err(0) => 0, // probe below sequence, but range could overlap
                Err(_) => lines.sequences.len(),
            };

            let row_idx = if let Some(seq) = lines.sequences.get(seq_idx) {
                let idx = seq.rows.binary_search_by(|row| row.address.cmp(&probe_low));
                match idx {
                    Ok(x) => x,
                    Err(0) => 0, // probe below sequence, but range could overlap
                    Err(x) => x - 1,
                }
            } else {
                0
            };

            Ok(Some(Self {
                lines,
                seqs: &*lines.sequences,
                seq_idx,
                row_idx,
                probe_high,
            }))
        } else {
            Ok(None)
        }
    }
}

impl<'unit, 'dwarf> Iterator for LocationRangeUnitIter<'unit, 'dwarf> {
    type Item = (u64, u64, Location<'unit>);

    fn next(&mut self) -> Option<(u64, u64, Location<'unit>)> {
        while let Some(seq) = self.seqs.get(self.seq_idx) {
            if seq.start >= self.probe_high {
                break
            }

            match seq.rows.get(self.row_idx) {
                Some(row) => {
                    if row.address >= self.probe_high {
                        break
                    }

                    // SANITY: We always have a file present for each
                    //         `file_index`.
                    let (dir, file) = self.lines.files.get(row.file_index as usize).unwrap();
                    let nextaddr = seq
                        .rows
                        .get(self.row_idx + 1)
                        .map(|row| row.address)
                        .unwrap_or(seq.end);

                    let item = (
                        row.address,
                        nextaddr - row.address,
                        Location {
                            dir,
                            file,
                            line: if row.line != 0 { Some(row.line) } else { None },
                            column: if row.column != 0 {
                                Some(row.column)
                            } else {
                                None
                            },
                        },
                    );
                    self.row_idx += 1;

                    return Some(item)
                }
                None => {
                    self.seq_idx += 1;
                    self.row_idx = 0;
                }
            }
        }
        None
    }
}
