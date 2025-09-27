use std::cell::RefCell;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem;
use std::ops::Deref as _;
use std::path::Path;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::mmap::Mmap;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;

use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::PT_LOAD;
use super::types::SHN_UNDEF;
#[cfg(test)]
use super::types::STT_FUNC;


fn symbol_name<'mmap>(strtab: &'mmap [u8], sym: &Elf64_Sym) -> Result<&'mmap str> {
    let name = strtab
        .get(sym.st_name as usize..)
        .ok_or_invalid_input(|| "string table index out of bounds")?
        .read_cstr()
        .ok_or_invalid_input(|| "no valid string found in string table")?
        .to_str()
        .map_err(Error::with_invalid_data)
        .context("invalid symbol name")?;

    Ok(name)
}

fn find_sym<'mmap>(
    symtab: &[&Elf64_Sym],
    strtab: &'mmap [u8],
    addr: Addr,
    st_type: u8,
) -> Result<Option<(&'mmap str, Addr, usize)>> {
    match find_match_or_lower_bound_by_key(symtab, addr, |sym| sym.st_value as Addr) {
        None => Ok(None),
        Some(idx) => {
            for sym in symtab[idx..].iter() {
                if sym.st_value as Addr > addr {
                    // Once we are seeing start addresses past the provided
                    // address, we can no longer be dealing with a match and
                    // stop the search.
                    break
                }

                // In ELF, a symbol size of 0 indicates "no size or an unknown
                // size" (see elf(5)). We take our changes and report these on a
                // best-effort basis.
                if sym.type_() == st_type
                    && sym.st_shndx != SHN_UNDEF
                    && (sym.st_size == 0 || addr < sym.st_value + sym.st_size)
                {
                    let name = symbol_name(strtab, sym)?;
                    let addr = sym.st_value as Addr;
                    let size = usize::try_from(sym.st_size).unwrap_or(usize::MAX);
                    return Ok(Some((name, addr, size)))
                }
            }
            Ok(None)
        }
    }
}


struct Cache<'mmap> {
    /// A slice of the raw ELF data that we are about to parse.
    elf_data: &'mmap [u8],
    /// The cached ELF header.
    ehdr: Option<&'mmap Elf64_Ehdr>,
    /// The cached ELF section headers.
    shdrs: Option<&'mmap [Elf64_Shdr]>,
    shstrtab: Option<&'mmap [u8]>,
    /// The cached ELF program headers.
    phdrs: Option<&'mmap [Elf64_Phdr]>,
    symtab: Option<Box<[&'mmap Elf64_Sym]>>, // in address order
    /// The cached ELF string table.
    strtab: Option<&'mmap [u8]>,
    str2symtab: Option<Box<[(&'mmap str, usize)]>>, // strtab offset to symtab in the dictionary order
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided raw ELF object data.
    fn new(elf_data: &'mmap [u8]) -> Self {
        Self {
            elf_data,
            ehdr: None,
            shdrs: None,
            shstrtab: None,
            phdrs: None,
            symtab: None,
            strtab: None,
            str2symtab: None,
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`.
    fn section_data(&mut self, idx: usize) -> Result<&'mmap [u8]> {
        let shdrs = self.ensure_shdrs()?;
        let section = shdrs
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?;

        let data = self
            .elf_data
            .get(section.sh_offset as usize..)
            .ok_or_invalid_data(|| "failed to read section data: invalid offset")?
            .read_slice(section.sh_size as usize)
            .ok_or_invalid_data(|| "failed to read section data: invalid size")?;
        Ok(data)
    }

    fn ensure_ehdr(&mut self) -> Result<&'mmap Elf64_Ehdr> {
        if let Some(ehdr) = self.ehdr {
            return Ok(ehdr)
        }

        let mut elf_data = self.elf_data;
        let ehdr = elf_data
            .read_pod_ref::<Elf64_Ehdr>()
            .ok_or_invalid_data(|| "failed to read Elf64_Ehdr")?;
        if !(ehdr.e_ident[0] == 0x7f
            && ehdr.e_ident[1] == b'E'
            && ehdr.e_ident[2] == b'L'
            && ehdr.e_ident[3] == b'F')
        {
            return Err(Error::with_invalid_data(format!(
                "encountered unexpected e_ident: {:x?}",
                &ehdr.e_ident[0..4]
            )))
        }
        self.ehdr = Some(ehdr);
        Ok(ehdr)
    }

    fn ensure_shdrs(&mut self) -> Result<&'mmap [Elf64_Shdr]> {
        if let Some(shdrs) = self.shdrs {
            return Ok(shdrs)
        }

        let ehdr = self.ensure_ehdr()?;
        let shdrs = self
            .elf_data
            .get(ehdr.e_shoff as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_shoff is invalid")?
            .read_pod_slice_ref::<Elf64_Shdr>(ehdr.e_shnum.into())
            .ok_or_invalid_data(|| "failed to read Elf64_Shdr")?;
        self.shdrs = Some(shdrs);
        Ok(shdrs)
    }

    fn ensure_phdrs(&mut self) -> Result<&'mmap [Elf64_Phdr]> {
        if let Some(phdrs) = self.phdrs {
            return Ok(phdrs)
        }

        let ehdr = self.ensure_ehdr()?;
        let phdrs = self
            .elf_data
            .get(ehdr.e_phoff as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_phoff is invalid")?
            .read_pod_slice_ref::<Elf64_Phdr>(ehdr.e_phnum.into())
            .ok_or_invalid_data(|| "failed to read Elf64_Phdr")?;
        self.phdrs = Some(phdrs);
        Ok(phdrs)
    }

    fn ensure_shstrtab(&mut self) -> Result<&'mmap [u8]> {
        if let Some(shstrtab) = self.shstrtab {
            return Ok(shstrtab)
        }

        let ehdr = self.ensure_ehdr()?;
        let shstrndx = ehdr.e_shstrndx;
        let shstrtab = self.section_data(shstrndx as usize)?;
        self.shstrtab = Some(shstrtab);
        Ok(shstrtab)
    }

    /// Get the name of the section at a given index.
    fn section_name(&mut self, idx: usize) -> Result<&'mmap str> {
        let shdrs = self.ensure_shdrs()?;
        let shstrtab = self.ensure_shstrtab()?;

        let sect = shdrs
            .get(idx)
            .ok_or_invalid_input(|| "ELF section index out of bounds")?;
        let name = shstrtab
            .get(sect.sh_name as usize..)
            .ok_or_invalid_input(|| "string table index out of bounds")?
            .read_cstr()
            .ok_or_invalid_input(|| "no valid string found in string table")?
            .to_str()
            .map_err(Error::with_invalid_data)
            .context("invalid section name")?;
        Ok(name)
    }

    #[cfg(test)]
    fn symbol(&mut self, idx: usize) -> Result<&'mmap Elf64_Sym> {
        let () = self.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();
        let symbol = symtab
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF symbol index ({idx}) out of bounds"))?;

        Ok(symbol)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    fn find_section(&mut self, name: &str) -> Result<Option<usize>> {
        let ehdr = self.ensure_ehdr()?;
        for i in 1..ehdr.e_shnum.into() {
            if self.section_name(i)? == name {
                return Ok(Some(i))
            }
        }
        Ok(None)
    }

    // Note: This function should really return a reference to
    //       `self.symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_symtab(&mut self) -> Result<()> {
        if self.symtab.is_some() {
            return Ok(())
        }

        let idx = if let Some(idx) = self.find_section(".symtab")? {
            idx
        } else if let Some(idx) = self.find_section(".dynsym")? {
            idx
        } else {
            // Neither symbol table exists. Fake an empty one.
            self.symtab = Some(Box::default());
            return Ok(())
        };
        let mut symtab = self.section_data(idx)?;

        if symtab.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::with_invalid_data(
                "size of symbol table section is invalid",
            ))
        }

        let count = symtab.len() / mem::size_of::<Elf64_Sym>();
        let mut symtab = symtab
            .read_pod_slice_ref::<Elf64_Sym>(count)
            .ok_or_invalid_data(|| "failed to read symbol table contents")?
            .iter()
            .collect::<Vec<&Elf64_Sym>>()
            .into_boxed_slice();
        // Order symbols by address and those with equal address descending by
        // size.
        let () = symtab.sort_by(|sym1, sym2| {
            sym1.st_value
                .cmp(&sym2.st_value)
                .then_with(|| sym1.st_size.cmp(&sym2.st_size).reverse())
        });

        self.symtab = Some(symtab);
        Ok(())
    }

    fn ensure_strtab(&mut self) -> Result<&'mmap [u8]> {
        if let Some(strtab) = self.strtab {
            return Ok(strtab)
        }

        let strtab = if let Some(idx) = self.find_section(".strtab")? {
            self.section_data(idx)?
        } else if let Some(idx) = self.find_section(".dynstr")? {
            self.section_data(idx)?
        } else {
            &[]
        };

        self.strtab = Some(strtab);
        Ok(strtab)
    }

    // Note: This function should really return a reference to
    //       `self.str2symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_str2symtab(&mut self) -> Result<()> {
        if self.str2symtab.is_some() {
            return Ok(())
        }

        let strtab = self.ensure_strtab()?;
        let () = self.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();

        let mut str2symtab = symtab
            .iter()
            .enumerate()
            .map(|(i, sym)| {
                let name = strtab
                    .get(sym.st_name as usize..)
                    .ok_or_invalid_input(|| "string table index out of bounds")?
                    .read_cstr()
                    .ok_or_invalid_input(|| "no valid string found in string table")?
                    .to_str()
                    .map_err(Error::with_invalid_data)
                    .context("invalid symbol name")?;
                Ok((name, i))
            })
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();

        let () = str2symtab.sort_by_key(|&(name, _i)| name);

        self.str2symtab = Some(str2symtab);
        Ok(())
    }
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}


/// A parser for ELF64 files.
#[derive(Debug)]
pub(crate) struct ElfParser {
    /// A cache for relevant parts of the ELF file.
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. Rather, they should never outlive `self`.
    ///         Furthermore, this member has to be listed before `mmap`
    ///         to make sure we never end up with a dangling reference.
    cache: RefCell<Cache<'static>>,
    /// The memory mapped file.
    _mmap: Mmap,
}

impl ElfParser {
    /// Create an `ElfParser` from an open file.
    pub fn open_file(file: File) -> Result<ElfParser> {
        Mmap::map(&file).map(Self::from_mmap)
    }

    /// Create an `ElfParser` from mmap'ed data.
    pub fn from_mmap(mmap: Mmap) -> ElfParser {
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let elf_data = unsafe { mem::transmute(mmap.deref()) };

        let parser = ElfParser {
            _mmap: mmap,
            cache: RefCell::new(Cache::new(elf_data)),
        };
        parser
    }

    /// Create an `ElfParser` for a path.
    pub fn open(filename: &Path) -> Result<ElfParser> {
        let file = File::open(filename)?;
        let parser = Self::open_file(file);
        if let Ok(parser) = parser {
            Ok(parser)
        } else {
            parser
        }
    }

    /// Retrieve the data corresponding to the ELF section at index `idx`.
    pub fn section_data(&self, idx: usize) -> Result<&[u8]> {
        let mut cache = self.cache.borrow_mut();
        cache.section_data(idx)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let mut cache = self.cache.borrow_mut();
        let index = cache.find_section(name)?;
        Ok(index)
    }

    pub fn find_sym(&self, addr: Addr, st_type: u8) -> Result<Option<(&str, Addr, usize)>> {
        let mut cache = self.cache.borrow_mut();
        let strtab = cache.ensure_strtab()?;
        let () = cache.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();

        find_sym(symtab, strtab, addr, st_type)
    }

    pub(crate) fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported("Not implemented"))
        }

        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab()?;
        let () = cache.ensure_str2symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();
        // SANITY: The above `ensure_str2symtab` ensures we have
        //         `str2symtab` available.
        let str2symtab = cache.str2symtab.as_ref().unwrap();

        let r = find_match_or_lower_bound_by_key(str2symtab, name, |&(name, _i)| name);
        match r {
            Some(idx) => {
                let mut found = vec![];
                for (name_visit, sym_i) in str2symtab.iter().skip(idx) {
                    if *name_visit != name {
                        break
                    }
                    let sym_ref = &symtab.get(*sym_i).ok_or_invalid_input(|| {
                        format!("symbol table index ({sym_i}) out of bounds")
                    })?;
                    if sym_ref.st_shndx != SHN_UNDEF {
                        found.push(SymInfo {
                            name: name.to_string(),
                            addr: sym_ref.st_value as Addr,
                            size: sym_ref.st_size as usize,
                            sym_type: SymType::Function,
                            file_offset: 0,
                            obj_file_name: None,
                        });
                    }
                }
                Ok(found)
            }
            None => Ok(vec![]),
        }
    }

    /// Find the file offset of the symbol at address `addr`.
    // TODO: See if we could make this a constant time calculation by supplying
    //       the ELF symbol index (and potentially an offset from it) [this will
    //       require a bit of a larger rework, including on call sites].
    pub(crate) fn find_file_offset(&self, addr: Addr) -> Option<u64> {
        let phdrs = self.program_headers().ok()?;
        let offset = phdrs.iter().find_map(|phdr| {
            if phdr.p_type == PT_LOAD {
                if (phdr.p_vaddr..phdr.p_vaddr + phdr.p_memsz).contains(&addr) {
                    return Some(addr - phdr.p_vaddr + phdr.p_offset)
                }
            }
            None
        })?;
        Some(offset)
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str> {
        let mut cache = self.cache.borrow_mut();
        let strtab = cache.ensure_strtab()?;
        let sym = cache.symbol(idx)?;
        let name = symbol_name(strtab, sym)?;
        Ok(name)
    }

    pub(crate) fn section_headers(&self) -> Result<&[Elf64_Shdr]> {
        let mut cache = self.cache.borrow_mut();
        let phdrs = cache.ensure_shdrs()?;
        Ok(phdrs)
    }

    pub(crate) fn program_headers(&self) -> Result<&[Elf64_Phdr]> {
        let mut cache = self.cache.borrow_mut();
        let phdrs = cache.ensure_phdrs()?;
        Ok(phdrs)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, Addr, usize) {
        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab().unwrap();
        let symtab = cache.symtab.as_ref().unwrap();

        let mut idx = symtab.len() / 2;
        while symtab[idx].type_() != STT_FUNC || symtab[idx].st_shndx == SHN_UNDEF {
            idx += 1;
        }
        let sym = &symtab[idx];
        let addr = sym.st_value;
        let size = sym.st_size;
        drop(cache);

        let sym_name = self.get_symbol_name(idx).unwrap();
        (
            sym_name,
            addr as Addr,
            usize::try_from(size).unwrap_or(usize::MAX),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use test_log::test;


    #[test]
    fn test_elf64_parser() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());
    }

    #[test]
    fn test_elf64_symtab() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        let sym = parser.find_sym(addr, STT_FUNC).unwrap().unwrap();
        let (name_ret, addr_ret, size_ret) = sym;
        assert_eq!(addr_ret, addr);
        assert_eq!(name_ret, name);
        assert_eq!(size_ret, size);
    }

    #[test]
    fn elf64_lookup_symbol_random() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        println!("{name}");
        let opts = FindAddrOpts::default();
        let addr_r = parser.find_addr(name, &opts).unwrap();
        assert_eq!(addr_r.len(), 1);
        assert!(addr_r.iter().any(|x| x.addr == addr && x.size == size));
    }

    /// Make sure that we can look up a symbol in an ELF file.
    #[test]
    fn lookup_symbol() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let opts = FindAddrOpts::default();
        let syms = parser.find_addr("factorial", &opts).unwrap();
        assert_eq!(syms.len(), 1);
        let sym = &syms[0];
        assert_eq!(sym.name, "factorial");
        assert_eq!(sym.addr, 0x2000100);

        let syms = parser.find_addr("factorial_wrapper", &opts).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "factorial_wrapper");
        assert_eq!(syms[1].name, "factorial_wrapper");
        assert_ne!(syms[0].addr, syms[1].addr);
    }

    /// Make sure that we do not report a symbol if there is no conceivable
    /// match.
    #[test]
    fn lookup_symbol_without_match() {
        let strtab = b"\x00_glapi_tls_Context\x00_glapi_get_dispatch_table_size\x00";
        let symtab = [
            &Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            &Elf64_Sym {
                st_name: 0x1,
                // Note: the type is *not* `STT_FUNC`.
                st_info: 0x16,
                st_other: 0x0,
                st_shndx: 0x14,
                st_value: 0x8,
                st_size: 0x8,
            },
            &Elf64_Sym {
                st_name: 0x21,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xe,
                st_value: 0x1a4a0,
                st_size: 0xa,
            },
        ];

        let result = find_sym(&symtab, strtab, 0x10d20, STT_FUNC).unwrap();
        assert_eq!(result, None);
    }

    /// Check that we report a symbol with an unknown `st_size` value is
    /// reported, if it is the only conceivable match.
    #[test]
    fn lookup_symbol_with_unknown_size() {
        fn test(symtab: &[&Elf64_Sym]) {
            let strtab = b"\x00__libc_init_first\x00versionsort64\x00";
            let result = find_sym(symtab, strtab, 0x29d00, STT_FUNC)
                .unwrap()
                .unwrap();
            assert_eq!(result, ("__libc_init_first", 0x29d00, 0x0));

            // Because the symbol has a size of 0 and is the only conceivable
            // match, we report it on the basis that ELF reserves these for "no
            // size or an unknown size" cases.
            let result = find_sym(symtab, strtab, 0x29d90, STT_FUNC)
                .unwrap()
                .unwrap();
            assert_eq!(result, ("__libc_init_first", 0x29d00, 0x0));

            // Note that despite of the first symbol (the invalid one; present
            // by default and reserved by ELF), is not being reported here
            // because it has an `st_shndx` value of `SHN_UNDEF`.
            let result = find_sym(symtab, strtab, 0x1, STT_FUNC).unwrap();
            assert_eq!(result, None);
        }

        let symtab = [
            &Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            &Elf64_Sym {
                st_name: 0x1,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29d00,
                st_size: 0x0,
            },
            &Elf64_Sym {
                st_name: 0xdeadbeef,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29dc0,
                st_size: 0x148,
            },
        ];

        test(&symtab);
        test(&symtab[0..2]);
    }
}
