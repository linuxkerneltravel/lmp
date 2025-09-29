//! Opcode runner of GSYM line table.

use crate::util::ReadRaw as _;
use crate::Addr;

/// End of the line table
const END_SEQUENCE: u8 = 0x00;
/// Set [`LineTableRow.file_idx`], don't push a row.
const SET_FILE: u8 = 0x01;
/// Increment [`LineTableRow.address`], and push a row.
const ADVANCE_PC: u8 = 0x02;
/// Set [`LineTableRow.file_line`], don't push a row.
const ADVANCE_LINE: u8 = 0x03;
/// All special opcodes push a row.
const FIRST_SPECIAL: u8 = 0x04;


#[derive(Debug)]
pub enum RunResult {
    /// Run the operator successfully.
    Ok,
    /// This operator creates a new row.
    NewRow,
    /// The end of the program (the operator stream.)
    End,
}

#[derive(Debug)]
pub struct LineTableHeader {
    /// `min_data` & `max_delta` together is used to set the range and encoding
    /// of line delta in special operator. Line delta is the number of lines
    /// that a line table row is different from the previous row.
    pub min_delta: i64,
    pub max_delta: i64,
    pub first_line: u32,
}

impl LineTableHeader {
    /// Parse [`AddrData`] of type [`INFO_TYPE_LINE_TABLE_INFO`].
    ///
    /// An `AddrData` of `INFO_TYPE_LINE_TABLE_INFO` type is a table of line numbers
    /// for a symbol. `AddrData` is the payload of `AddrInfo`. One `AddrInfo`
    /// may have several `AddrData` entries in its payload. Each `AddrData`
    /// entry stores a type of data related to the symbol the `AddrInfo`
    /// presents.
    ///
    /// # Arguments
    ///
    /// * `data` - is what [`AddrData::data`] is.
    pub(super) fn parse(data: &mut &[u8]) -> Option<Self> {
        let (min_delta, _bytes) = data.read_i64_leb128()?;
        let (max_delta, _bytes) = data.read_i64_leb128()?;
        let (first_line, _bytes) = data.read_u64_leb128()?;

        let header = Self {
            min_delta,
            max_delta,
            first_line: first_line as u32,
        };
        Some(header)
    }
}

#[derive(Clone, Debug)]
pub struct LineTableRow {
    pub address: Addr,
    pub file_idx: u32,
    pub file_line: u32,
}

impl LineTableRow {
    /// Create a `LineTableRow` to use as the states of a line table virtual
    /// machine.
    ///
    /// The returned `LineTableRow` can be passed to [`run_op`] as `ctx`.
    ///
    /// # Arguments
    ///
    /// * `header` - is a [`LineTableHeader`] returned by [`parse_line_table_header()`].
    /// * `symaddr` - the address of the symbol that `header` belongs to.
    pub fn from_header(header: &LineTableHeader, symaddr: Addr) -> Self {
        Self {
            address: symaddr,
            file_idx: 1,
            file_line: header.first_line,
        }
    }
}


/// Run a GSYM line table operator/instruction in the buffer.
///
/// # Arguments
///
/// * `ctx` - a line table row to present the current states of the virtual
///           machine. [`LineTableRow::from_header`] can create a `LineTableRow`
///           to keep the states of a virtual machine.
/// * `header` - is a `LineTableHeader`.
/// * `ops` - is the buffer of the operators following the `LineTableHeader` in
///           a GSYM file.
pub fn run_op(
    ctx: &mut LineTableRow,
    header: &LineTableHeader,
    ops: &mut &[u8],
) -> Option<RunResult> {
    let op = ops.read_u8()?;
    match op {
        END_SEQUENCE => Some(RunResult::End),
        SET_FILE => {
            let (f, _bytes) = ops.read_u64_leb128()?;
            ctx.file_idx = f as u32;
            Some(RunResult::Ok)
        }
        ADVANCE_PC => {
            let (adv, _bytes) = ops.read_u64_leb128()?;
            ctx.address += adv as Addr;
            Some(RunResult::NewRow)
        }
        ADVANCE_LINE => {
            let (adv, _bytes) = ops.read_i64_leb128()?;
            ctx.file_line = (ctx.file_line as i64 + adv) as u32;
            Some(RunResult::Ok)
        }
        // Special operators.
        //
        // All operators that have a value greater than or equal to
        // FIRST_SPECIAL are considered special operators. These operators
        // change both the line number and address of the virtual machine and
        // emit a new row.
        _ => {
            let adjusted = (op - FIRST_SPECIAL) as i64;
            // The range of line number delta is from min_delta to max_delta,
            // including max_delta.
            let range = header.max_delta - header.min_delta + 1;
            if range == 0 {
                return None
            }
            let line_delta = header.min_delta + (adjusted % range);
            let addr_delta = adjusted / range;

            let file_line = ctx.file_line as i32 + line_delta as i32;
            if file_line < 1 {
                return None
            }

            ctx.file_line = file_line as u32;
            ctx.address += addr_delta as Addr;
            Some(RunResult::NewRow)
        }
    }
}
