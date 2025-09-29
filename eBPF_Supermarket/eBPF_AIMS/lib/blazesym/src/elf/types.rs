const EI_NIDENT: usize = 16;

type Elf64_Addr = u64;
type Elf64_Half = u16;
type Elf64_Off = u64;
type Elf64_Word = u32;
type Elf64_Xword = u64;

pub(crate) const ET_EXEC: u16 = 2;
pub(crate) const ET_DYN: u16 = 3;

#[repr(C)]
pub(crate) struct Elf64_Ehdr {
    pub e_ident: [u8; EI_NIDENT], /* ELF "magic number" */
    pub e_type: Elf64_Half,
    pub e_machine: Elf64_Half,
    pub e_version: Elf64_Word,
    pub e_entry: Elf64_Addr, /* Entry point virtual address */
    pub e_phoff: Elf64_Off,  /* Program header table file offset */
    pub e_shoff: Elf64_Off,  /* Section header table file offset */
    pub e_flags: Elf64_Word,
    pub e_ehsize: Elf64_Half,
    pub e_phentsize: Elf64_Half,
    pub e_phnum: Elf64_Half,
    pub e_shentsize: Elf64_Half,
    pub e_shnum: Elf64_Half,
    pub e_shstrndx: Elf64_Half,
}

// SAFETY: `Elf64_Ehdr` is valid for any bit pattern.
unsafe impl crate::util::Pod for Elf64_Ehdr {}

pub(crate) const PT_LOAD: u32 = 1;

#[repr(C)]
pub(crate) struct Elf64_Phdr {
    pub p_type: Elf64_Word,
    pub p_flags: Elf64_Word,
    pub p_offset: Elf64_Off,   /* Segment file offset */
    pub p_vaddr: Elf64_Addr,   /* Segment virtual address */
    pub p_paddr: Elf64_Addr,   /* Segment physical address */
    pub p_filesz: Elf64_Xword, /* Segment size in file */
    pub p_memsz: Elf64_Xword,  /* Segment size in memory */
    pub p_align: Elf64_Xword,  /* Segment alignment, file & memory */
}

// SAFETY: `Elf64_Phdr` is valid for any bit pattern.
unsafe impl crate::util::Pod for Elf64_Phdr {}

pub(crate) const PF_X: Elf64_Word = 1;

#[repr(C)]
pub(crate) struct Elf64_Shdr {
    pub sh_name: Elf64_Word,       /* Section name, index in string tbl */
    pub sh_type: Elf64_Word,       /* Type of section */
    pub sh_flags: Elf64_Xword,     /* Miscellaneous section attributes */
    pub sh_addr: Elf64_Addr,       /* Section virtual addr at execution */
    pub sh_offset: Elf64_Off,      /* Section file offset */
    pub sh_size: Elf64_Xword,      /* Size of section in bytes */
    pub sh_link: Elf64_Word,       /* Index of another section */
    pub sh_info: Elf64_Word,       /* Additional section information */
    pub sh_addralign: Elf64_Xword, /* Section alignment */
    pub sh_entsize: Elf64_Xword,   /* Entry size if section holds table */
}

// SAFETY: `Elf64_Shdr` is valid for any bit pattern.
unsafe impl crate::util::Pod for Elf64_Shdr {}

pub(crate) const SHN_UNDEF: u16 = 0;

pub(crate) const SHT_NOTE: Elf64_Word = 7;

pub(crate) const STT_FUNC: u8 = 2;

#[derive(Clone)]
#[repr(C)]
pub(crate) struct Elf64_Sym {
    pub st_name: Elf64_Word,  /* Symbol name, index in string tbl */
    pub st_info: u8,          /* Type and binding attributes */
    pub st_other: u8,         /* No defined meaning, 0 */
    pub st_shndx: Elf64_Half, /* Associated section index */
    pub st_value: Elf64_Addr, /* Value of the symbol */
    pub st_size: Elf64_Xword, /* Associated symbol size */
}

impl Elf64_Sym {
    /// Extract the symbols type, typically represented by a STT_* constant.
    pub fn type_(&self) -> u8 {
        self.st_info & 0xf
    }
}

// SAFETY: `Elf64_Sym` is valid for any bit pattern.
unsafe impl crate::util::Pod for Elf64_Sym {}

pub(crate) const NT_GNU_BUILD_ID: Elf64_Word = 3;

#[repr(C)]
pub(crate) struct Elf64_Nhdr {
    pub n_namesz: Elf64_Word,
    pub n_descsz: Elf64_Word,
    pub n_type: Elf64_Word,
}

// SAFETY: `Elf64_Nhdr` is valid for any bit pattern.
unsafe impl crate::util::Pod for Elf64_Nhdr {}
