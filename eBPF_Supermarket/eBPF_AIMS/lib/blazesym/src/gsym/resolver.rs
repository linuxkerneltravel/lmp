use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::mem::swap;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::symbolize::AddrCodeInfo;
use crate::symbolize::FrameCodeInfo;
use crate::Addr;
use crate::IntSym;
use crate::IntoError as _;
use crate::Result;
use crate::SrcLang;
use crate::SymResolver;

use super::inline::InlineInfo;
use super::linetab::run_op;
use super::linetab::LineTableHeader;
use super::linetab::LineTableRow;
use super::linetab::RunResult;
use super::parser::parse_address_data;
use super::parser::GsymContext;
use super::types::INFO_TYPE_INLINE_INFO;
use super::types::INFO_TYPE_LINE_TABLE_INFO;
use crate::log::warn;


enum Data<'dat> {
    Mmap(Mmap),
    Slice(&'dat [u8]),
}

/// The symbol resolver for the GSYM format.
pub struct GsymResolver<'dat> {
    file_name: Option<PathBuf>,
    // SAFETY: This member should be listed before `ctx` to make sure we never
    //         end up with dangling references.
    _data: Data<'dat>,
    ctx: GsymContext<'dat>,
}

impl GsymResolver<'static> {
    /// Create a `GsymResolver` that load data from the provided file.
    pub fn new(file_name: PathBuf) -> Result<Self> {
        let mmap = Mmap::builder().open(&file_name)?;
        let ctx = GsymContext::parse_header(&mmap)?;
        let slf = Self {
            file_name: Some(file_name),
            // SAFETY: We own the underlying `Mmap` object and never hand out
            //         any 'static references to its data. So it is safe for us
            //         to transmute the lifetime.
            ctx: unsafe { mem::transmute(ctx) },
            _data: Data::Mmap(mmap),
        };

        Ok(slf)
    }
}

impl<'dat> GsymResolver<'dat> {
    /// Create a `GsymResolver` that works on the provided "raw" Gsym data.
    pub(crate) fn with_data(data: &'dat [u8]) -> Result<Self> {
        let ctx = GsymContext::parse_header(data)?;
        let slf = Self {
            file_name: None,
            ctx,
            _data: Data::Slice(data),
        };

        Ok(slf)
    }

    fn query_frame_code_info(&self, file_idx: u32, line: Option<u32>) -> Result<FrameCodeInfo<'_>> {
        let finfo = self
            .ctx
            .file_info(file_idx as usize)
            .ok_or_invalid_data(|| format!("failed to retrieve file info data @ {}", file_idx))?;
        let dir = self
            .ctx
            .get_str(finfo.directory as usize)
            .ok_or_invalid_data(|| {
                format!("failed to retrieve directory string @ {}", finfo.directory)
            })?;
        let file = self
            .ctx
            .get_str(finfo.filename as usize)
            .ok_or_invalid_data(|| {
                format!("failed to retrieve file name string @ {}", finfo.filename)
            })?;

        let info = FrameCodeInfo {
            dir: Path::new(dir),
            file,
            line,
            column: None,
        };
        Ok(info)
    }

    fn parse_line_tab_info(
        &self,
        mut data: &[u8],
        symaddr: Addr,
        addr: Addr,
    ) -> Result<Option<LineTableRow>> {
        // Continue to execute all GSYM line table operations
        // until the end of the buffer is reached or a row
        // containing addr is located.
        let lntab_hdr = LineTableHeader::parse(&mut data)
            .ok_or_invalid_data(|| "failed to parse line table header")?;
        let mut lntab_row = LineTableRow::from_header(&lntab_hdr, symaddr);
        let mut last_lntab_row = lntab_row.clone();
        let mut row_cnt = 0;
        while !data.is_empty() {
            match run_op(&mut lntab_row, &lntab_hdr, &mut data) {
                Some(RunResult::Ok) => {}
                Some(RunResult::NewRow) => {
                    row_cnt += 1;
                    if addr < lntab_row.address {
                        if row_cnt == 1 {
                            // The address is lower than the first row.
                            return Ok(None)
                        }
                        // Rollback to the last row.
                        lntab_row = last_lntab_row;
                        break
                    }
                    last_lntab_row = lntab_row.clone();
                }
                Some(RunResult::End) | None => break,
            }
        }

        if row_cnt == 0 {
            return Ok(None)
        }
        Ok(Some(lntab_row))
    }
}

impl SymResolver for GsymResolver<'_> {
    fn find_sym(&self, addr: Addr) -> Result<Option<IntSym<'_>>> {
        if let Some(idx) = self.ctx.find_addr(addr) {
            let found = self
                .ctx
                .addr_at(idx)
                .ok_or_invalid_data(|| format!("failed to read address table entry {idx}"))?;
            if addr < found {
                return Ok(None)
            }

            let info = self
                .ctx
                .addr_info(idx)
                .ok_or_invalid_data(|| format!("failed to read address information entry {idx}"))?;
            let name = self
                .ctx
                .get_str(info.name as usize)
                .and_then(|s| s.to_str())
                .ok_or_invalid_data(|| {
                    format!("failed to read string table entry at offset {}", info.name)
                })?;
            // Gsym does not carry any source code language information.
            let lang = SrcLang::Unknown;
            let sym = IntSym {
                name,
                addr: found,
                size: Some(usize::try_from(info.size).unwrap_or(usize::MAX)),
                lang,
            };

            Ok(Some(sym))
        } else {
            Ok(None)
        }
    }

    fn find_addr(&self, _name: &str, _opts: &FindAddrOpts) -> Result<Vec<SymInfo>> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        Ok(Vec::new())
    }

    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self), fields(file = debug(&self.file_name))))]
    fn find_code_info(&self, addr: Addr, inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>> {
        let idx = match self.ctx.find_addr(addr) {
            Some(idx) => idx,
            None => return Ok(None),
        };
        let symaddr = self
            .ctx
            .addr_at(idx)
            .ok_or_invalid_data(|| format!("failed to read address table entry {idx}"))?;
        if addr < symaddr {
            return Ok(None)
        }
        let addrinfo = self
            .ctx
            .addr_info(idx)
            .ok_or_invalid_data(|| format!("failed to read address info entry {idx}"))?;
        if addr >= (symaddr + addrinfo.size as Addr) {
            return Ok(None)
        }

        let mut line_tab_info = None;
        let mut inline_info = None;
        let addrdatas = parse_address_data(addrinfo.data);
        for addr_ent in addrdatas {
            match addr_ent.typ {
                INFO_TYPE_LINE_TABLE_INFO => {
                    if line_tab_info.is_none() {
                        line_tab_info = self.parse_line_tab_info(addr_ent.data, symaddr, addr)?;
                    }
                }
                INFO_TYPE_INLINE_INFO if inlined_fns => {
                    if inline_info.is_none() {
                        let mut data = addr_ent.data;
                        inline_info = InlineInfo::parse(&mut data, symaddr, Some(addr))?;
                    }
                }
                typ => {
                    warn!("encountered unknown info type: {typ}; ignoring...");
                    continue
                }
            }
        }

        if let Some(line_tab_row) = line_tab_info {
            let mut line_tab_info =
                self.query_frame_code_info(line_tab_row.file_idx, Some(line_tab_row.file_line))?;

            let mut direct_name = None;
            let mut inlined = Vec::new();

            if let Some(inline_info) = inline_info {
                let mut inline_stack = inline_info.inline_stack(addr).into_iter();
                // As per Gsym file format, the first "frame" only contains the
                // name and it effectively is meant to overwrite what is already
                // contained in the line table.
                if let Some(inline_info) = inline_stack.next() {
                    direct_name = Some(
                        self.ctx
                            .get_str(inline_info.name as usize)
                            .and_then(|s| s.to_str())
                            .ok_or_invalid_data(|| {
                                format!(
                                    "failed to read string table entry at offset {}",
                                    inline_info.name
                                )
                            })?,
                    );

                    let () = inlined.reserve(inline_stack.len());

                    for frame in inline_stack {
                        let name = self
                            .ctx
                            .get_str(frame.name as usize)
                            .and_then(|s| s.to_str())
                            .ok_or_invalid_data(|| {
                                format!(
                                    "failed to read string table entry at offset {}",
                                    frame.name
                                )
                            })?;

                        let mut code_info = if let Some(file) = frame.call_file {
                            let code_info = self.query_frame_code_info(file, frame.call_line)?;
                            Some(code_info)
                        } else {
                            None
                        };

                        // For each frame we need to move the code information
                        // up by one layer.
                        if let Some((_last_name, ref mut last_code_info)) = inlined.last_mut() {
                            let () = swap(&mut code_info, last_code_info);
                        } else if let Some(code_info) = &mut code_info {
                            let () = swap(code_info, &mut line_tab_info);
                        }
                        let () = inlined.push((name, code_info));
                    }
                }
            }

            let info = AddrCodeInfo {
                direct: (direct_name, line_tab_info),
                inlined,
            };
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        // Unavailable
        None
    }
}

impl Debug for GsymResolver<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let path = self
            .file_name
            .as_deref()
            .unwrap_or_else(|| Path::new("<unknown-file>"));
        write!(f, "GSYM {}", path.display())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::read as read_file;

    use test_log::test;


    /// Check that we can create a `GsymResolver` using a "raw" slice of data.
    #[test]
    fn creation_from_raw_data() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.gsym");
        let data = read_file(test_gsym).unwrap();

        let resolver = GsymResolver::with_data(&data).unwrap();
        assert_eq!(resolver.file_name, None);
    }

    /// Make sure that we can find file line information for a function, if available.
    #[test]
    fn find_line_info() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.gsym");
        let resolver = GsymResolver::new(test_gsym).unwrap();

        // `main` resides at address 0x2000000, and it's located at the given
        // line.
        let info = resolver.find_code_info(0x2000000, true).unwrap().unwrap();
        assert_eq!(info.direct.1.line, Some(50));
        assert_eq!(info.direct.1.file, "test-stable-addresses.c");
        assert_eq!(info.inlined, Vec::new());

        // `factorial` resides at address 0x2000100, and it's located at the
        // given line.
        let info = resolver.find_code_info(0x2000100, true).unwrap().unwrap();
        assert_eq!(info.direct.1.line, Some(8));
        assert_eq!(info.direct.1.file, "test-stable-addresses.c");
        assert_eq!(info.inlined, Vec::new());

        // Address is hopefully sufficiently far into `factorial_inline_test` to
        // always fall into the inlined region, no matter toolchain. If not, add
        // padding bytes/dummy instructions and adjust some more.
        let addr = 0x200020a;
        let sym = resolver.find_sym(addr).unwrap().unwrap();
        assert_eq!(sym.name, "factorial_inline_test");

        let info = resolver.find_code_info(addr, true).unwrap().unwrap();
        assert_eq!(info.direct.1.line, Some(32));
        assert_eq!(info.direct.1.file, "test-stable-addresses.c");
        assert_eq!(info.inlined.len(), 2);

        let name = &info.inlined[0].0;
        assert_eq!(*name, "factorial_inline_wrapper");
        let frame = info.inlined[0].1.as_ref().unwrap();
        assert_eq!(frame.file, "test-stable-addresses.c");
        assert_eq!(frame.line, Some(26));

        let name = &info.inlined[1].0;
        assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
        let frame = info.inlined[1].1.as_ref().unwrap();
        assert_eq!(frame.file, "test-stable-addresses.c");
        assert_eq!(frame.line, Some(21));

        let info = resolver.find_code_info(addr, false).unwrap().unwrap();
        // Note that the line number reported without inline information is
        // different to that when using inlined function information, because in
        // Gsym this additional data is used to "refine" the result.
        assert_eq!(info.direct.1.line, Some(21));
        assert_eq!(info.direct.1.file, "test-stable-addresses.c");
        assert_eq!(info.inlined, Vec::new());
    }
}
