use std::ops::Range;

use crate::util::ReadRaw as _;
use crate::IntoError as _;
use crate::Result;


#[derive(Clone)]
pub(super) struct InlineInfo {
    pub name: u32,
    pub call_file: Option<u32>,
    pub call_line: Option<u32>,

    ranges: Vec<Range<u64>>,
    children: Vec<Self>,
}

impl InlineInfo {
    /// Parse Gsym `InlineInfo` from raw bytes.
    pub fn parse(
        data: &mut &[u8],
        base_addr: u64,
        lookup_addr: Option<u64>,
    ) -> Result<Option<InlineInfo>> {
        let range_cnt = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read range count from inline information")?
            .0;
        let range_cnt = usize::try_from(range_cnt)
            .ok()
            .ok_or_invalid_data(|| "range count ({}) is too big")?;
        if range_cnt == 0 {
            return Ok(None)
        }

        let mut ranges = Vec::new();
        let mut child_base_addr = 0u64;

        if let Some(lookup_addr) = lookup_addr {
            for i in 0..range_cnt {
                let offset = data
                    .read_u64_leb128()
                    .ok_or_invalid_data(|| "failed to read offset from inline information")?
                    .0;
                let size = data
                    .read_u64_leb128()
                    .ok_or_invalid_data(|| "failed to read size from inline information")?
                    .0;

                let start = base_addr + offset;
                let end = start + size;
                if i == 0 {
                    child_base_addr = start;
                }

                let range = start..end;
                if range.contains(&lookup_addr) {
                    let () = ranges.push(range);
                }
            }
        } else {
            for _ in 0..range_cnt {
                let _offset = data
                    .read_u64_leb128()
                    .ok_or_invalid_data(|| "failed to read offset from inline information")?;
                let _size = data
                    .read_u64_leb128()
                    .ok_or_invalid_data(|| "failed to read size from inline information")?;
            }
        }

        let child_cnt = data
            .read_u8()
            .ok_or_invalid_data(|| "failed to read child count from inline information")?;
        let has_children = child_cnt != 0;
        let name = data
            .read_u32()
            .ok_or_invalid_data(|| "failed to read name from inline information")?;

        let (call_file, call_line) = if lookup_addr.is_some() {
            let call_file = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read call file from inline information")?
                .0;
            let call_file = u32::try_from(call_file)
                .ok()
                .ok_or_invalid_data(|| "call file index ({}) is too big")?;
            let call_line = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read call line from inline information")?
                .0;
            let call_line = u32::try_from(call_line).unwrap_or(u32::MAX);
            (Some(call_file), Some(call_line))
        } else {
            let _call_file = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read call file from inline information")?;
            let _call_line = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read call line from inline information")?;
            (None, None)
        };

        let mut children = Vec::new();
        if has_children {
            if ranges.is_empty() {
                // This inlined function does not contain `lookup_addr`, no need
                // to decode ranges, just skip.
                while let Some(_child) = Self::parse(data, child_base_addr, None)? {
                    // Do nothing; we just skip the data.
                }
            } else {
                while let Some(child) = Self::parse(data, child_base_addr, lookup_addr)? {
                    let () = children.push(child);
                }
            }
        }

        let slf = Self {
            name,
            call_file,
            call_line,
            ranges,
            children,
        };
        Ok(Some(slf))
    }

    fn inline_stack_impl<'slf>(&'slf self, addr: u64, inlined: &mut Vec<&'slf Self>) -> bool {
        for range in &self.ranges {
            if range.contains(&addr) {
                if self.name > 0 {
                    let () = inlined.push(self);
                }

                for child in &self.children {
                    if child.inline_stack_impl(addr, inlined) {
                        break
                    }
                }
                return !inlined.is_empty()
            }
        }
        false
    }

    pub fn inline_stack(&self, addr: u64) -> Vec<&Self> {
        let mut inlined = Vec::new();
        let _done = self.inline_stack_impl(addr, &mut inlined);
        inlined
    }
}
