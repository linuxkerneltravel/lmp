/*
 * Linux内核诊断工具--elf相关公共函数
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdio.h>

#include "stack_analyzer/include/elf.h"

#define NOTE_ALIGN(n) (((n) + 3) & -4U)

struct sym_section_ctx {
    Elf_Data *syms;
    Elf_Data *symstrs;
    Elf_Data *rel_data;
    int is_reloc;
    int is_plt;
    int sym_count;
    int plt_rel_type;
    unsigned long plt_offset;
    unsigned long plt_entsize;
};

struct symbol_sections_ctx {
    sym_section_ctx symtab;
    sym_section_ctx symtab_in_dynsym;
    sym_section_ctx dynsymtab;
};

struct section_info {
    Elf_Scn *sec;
    GElf_Shdr *hdr;
};

struct plt_ctx {
    section_info dynsym;
    section_info plt_rel;
    section_info plt;
};

__attribute__((unused)) static Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
                                    GElf_Shdr *shp, const char *name,
                                    size_t *idx) {
    Elf_Scn *sec = NULL;
    size_t cnt = 1;

    /* Elf is corrupted/truncated, avoid calling elf_strptr. */
    if (!elf_rawdata(elf_getscn(elf, ep->e_shstrndx), NULL))
        return NULL;

    while ((sec = elf_nextscn(elf, sec)) != NULL) {
        char *str;

        gelf_getshdr(sec, shp);
        str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);

        if (!strcmp(name, str)) {
            if (idx)
                *idx = cnt;

            break;
        }

        ++cnt;
    }

    return sec;
}

__attribute__((unused)) static int elf_read_build_id(Elf *elf, char *bf, size_t size) {
    int err = -1;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Data *data;
    Elf_Scn *sec;
    Elf_Kind ek;
    char *ptr;

    if (size < BUILD_ID_SIZE)
        goto out;

    ek = elf_kind(elf);

    if (ek != ELF_K_ELF)
        goto out;

    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "%s: cannot get elf header.\n", __func__);
        goto out;
    }

    /*
     * Check following sections for notes:
     *   '.note.gnu.build-id'
     *   '.notes'
     *   '.note' (VDSO specific)
     */
    do {
        sec = elf_section_by_name(elf, &ehdr, &shdr,
                                  ".note.gnu.build-id", NULL);

        if (sec)
            break;

        sec = elf_section_by_name(elf, &ehdr, &shdr,
                                  ".notes", NULL);

        if (sec)
            break;

        sec = elf_section_by_name(elf, &ehdr, &shdr,
                                  ".note", NULL);

        if (sec)
            break;

        return err;

    } while (0);

    data = elf_getdata(sec, NULL);

    if (data == NULL)
        goto out;

    ptr = (char *)data->d_buf;

    while ((intptr_t)ptr < (intptr_t)((char *)data->d_buf + data->d_size)) {
        GElf_Nhdr *nhdr = (GElf_Nhdr *)ptr;
        size_t namesz = NOTE_ALIGN(nhdr->n_namesz),
               descsz = NOTE_ALIGN(nhdr->n_descsz);
        const char *name;

        ptr += sizeof(*nhdr);
        name = (const char *)ptr;
        ptr += namesz;

        if (nhdr->n_type == NT_GNU_BUILD_ID &&
                nhdr->n_namesz == sizeof("GNU")) {
            if (memcmp(name, "GNU", sizeof("GNU")) == 0) {
                size_t sz = size < descsz ? size : descsz;
                memcpy(bf, ptr, sz);
                memset(bf + sz, 0, size - sz);
                err = descsz;
                break;
            }
        }

        ptr += descsz;
    }

out:
    return err;
}

extern int calc_sha1_1M(const char *filename, unsigned char *buf);

int filename__read_build_id(int pid, const char *mnt_ns_name, const char *filename, char *bf, size_t size) {
    int fd, err = -1;
    struct stat sb;

    if (size < BUILD_ID_SIZE)
        goto out;

    fd = open(filename, O_RDONLY);

    if (fd < 0)
        goto out;

    if (fstat(fd, &sb) == 0) {
        snprintf(bf, size, "%s[%lu]", filename, sb.st_size);
        err = 0;
    }

    close(fd);
out:
    return err;
}

static int is_function(const GElf_Sym *sym)
{
    return GELF_ST_TYPE(sym->st_info) == STT_FUNC &&
        sym->st_name != 0 &&
        sym->st_shndx != SHN_UNDEF;
}

static int get_symbols_in_section(sym_section_ctx *sym, Elf *elf, Elf_Scn *sec, GElf_Shdr *shdr, int is_reloc)
{
    sym->syms = elf_getdata(sec, NULL);
    if (!sym->syms) {
        return -1;
    }

    Elf_Scn *symstrs_sec = elf_getscn(elf, shdr->sh_link);
    if (!sec) {
        return -1;
    }

    sym->symstrs = elf_getdata(symstrs_sec, NULL);
    if (!sym->symstrs) {
        return -1;
    }

    sym->sym_count = shdr->sh_size / shdr->sh_entsize;
    sym->is_plt = 0;
    sym->is_reloc = is_reloc;

    return 0;
}

static int get_plt_symbols_in_section(sym_section_ctx *sym, Elf *elf, plt_ctx *plt)
{
    sym->syms = elf_getdata(plt->dynsym.sec, NULL);
    if (!sym->syms) {
        return -1;
    }
   
    sym->rel_data = elf_getdata(plt->plt_rel.sec, NULL);       
    if (!sym->rel_data) {
        return -1;
    }
   
    Elf_Scn *symstrs_sec = elf_getscn(elf, plt->dynsym.hdr->sh_link);
    if (!symstrs_sec) {
        return -1;
    }
    
    sym->symstrs = elf_getdata(symstrs_sec, NULL);
    if (!sym->symstrs) {
        return -1;
    }

    sym->is_plt = 1;
    sym->plt_entsize = plt->plt.hdr->sh_type;
    sym->plt_offset = plt->plt.hdr->sh_offset;
    sym->sym_count = plt->plt_rel.hdr->sh_size / plt->plt_rel.hdr->sh_entsize;
    sym->plt_rel_type = plt->plt_rel.hdr->sh_type;

    return 0;
}

static void __get_plt_symbol(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    symbol s;
    GElf_Sym sym;
    int symidx;
    int index = 0;
    const char *sym_name = NULL;

    s.end = 0;
    s.start = 0;

    if (!si->dynsymtab.syms) {
        return;
    }

    while (index < si->dynsymtab.sym_count) {
        if (si->dynsymtab.plt_rel_type == SHT_RELA) {
            GElf_Rela pos_mem, *pos;
            pos = gelf_getrela(si->dynsymtab.rel_data, index, &pos_mem);
            symidx = GELF_R_SYM(pos->r_info);
        }
        else if (si->dynsymtab.plt_rel_type == SHT_REL) {
            GElf_Rel pos_mem, *pos;
            pos = gelf_getrel(si->dynsymtab.rel_data, index, &pos_mem);
            symidx = GELF_R_SYM(pos->r_info);
        }
        else {
            return;
        }
        index++;
        si->dynsymtab.plt_offset += si->dynsymtab.plt_entsize;
        gelf_getsym(si->dynsymtab.syms, symidx, &sym);

        sym_name = (const char *)si->dynsymtab.symstrs->d_buf + sym.st_name;
        s.start = si->dynsymtab.plt_offset;
        s.end = s.start + si->dynsymtab.plt_entsize;
        s.ip = s.start;
        s.name = sym_name;
        ss.insert(s);
    }
}

static void __get_symbol_without_plt(std::set<symbol> &ss, sym_section_ctx *tab, Elf *elf)
{
    GElf_Sym sym;
    int index = 0;
    const char *sym_name;
    symbol s;
    s.end = 0;
    s.start = 0;

    while (index < tab->sym_count) {
        gelf_getsym(tab->syms, index, &sym);
        index++;
        if (sym.st_shndx == SHN_ABS) {
            continue;
        }
        if (!is_function(&sym)) {
            continue;
        } 
        sym_name = (const char *)tab->symstrs->d_buf + sym.st_name;
        if (tab->is_reloc) {
            Elf_Scn *sec = elf_getscn(elf, sym.st_shndx);
            if (!sec) {
                continue;
            }
            GElf_Shdr shdr;
            gelf_getshdr(sec, &shdr);
            sym.st_value -= shdr.sh_addr - shdr.sh_offset;
        }
        s.start = sym.st_value & 0xffffffff; 
        s.end = s.start + sym.st_size;
        s.ip = s.start;
        s.name = sym_name;
        ss.insert(s);
    }
}

static void __get_symbol(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    symbol s;
    s.end = 0;
    s.start = 0;

    if (!si->symtab.syms && !si->dynsymtab.syms) {
        return;
    }

    sym_section_ctx *tab = &si->symtab;
    __get_symbol_without_plt(ss, tab, elf);
    tab = &si->symtab_in_dynsym;
    __get_symbol_without_plt(ss, tab, elf);
}

static void get_all_symbols(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    __get_symbol(ss, si, elf);
    __get_plt_symbol(ss, si, elf);
}

bool search_symbol(const std::set<symbol> &ss, symbol &sym)
{
    std::set<symbol>::const_iterator it = ss.find(sym);

    if (it != ss.end()) {
        sym.end = it->end;
        sym.start = it->start;
        sym.name = it->name;

        return true;
    }

    return false;
}

bool get_symbol_from_elf(std::set<symbol> &ss, const char *path)
{
    // static int first_init = 0;

    // if (!first_init) {
    //     first_init = true;
    //     init_global_env();
    // }

    int is_reloc = 0;
    elf_version(EV_CURRENT);
    int fd = open(path, O_RDONLY);

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        close(fd);
        return false;
    }

    Elf_Kind ek = elf_kind(elf);
    if (ek != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return false;
    }
    GElf_Ehdr hdr;
    if (gelf_getehdr(elf, &hdr) == NULL) {
        elf_end(elf);
        close(fd);
        return false;
    }

    if (hdr.e_type == ET_EXEC) {
        is_reloc = 1;
    }

    if (!elf_rawdata(elf_getscn(elf, hdr.e_shstrndx), NULL)) {
        elf_end(elf);
        close(fd);
        return false;
    }

    GElf_Shdr shdr;
    GElf_Shdr symtab_shdr;
    GElf_Shdr dynsym_shdr;
    GElf_Shdr plt_shdr;
    GElf_Shdr plt_rel_shdr;
    memset(&shdr, 0, sizeof(shdr));
    memset(&symtab_shdr, 0, sizeof(symtab_shdr));
    memset(&dynsym_shdr, 0, sizeof(dynsym_shdr));
    memset(&plt_shdr, 0, sizeof(plt_shdr));
    memset(&plt_rel_shdr, 0, sizeof(plt_rel_shdr));

    Elf_Scn *sec = NULL;
    Elf_Scn *dynsym_sec = NULL;
    Elf_Scn *symtab_sec = NULL;
    Elf_Scn *plt_sec = NULL;
    Elf_Scn *plt_rel_sec = NULL;

    while ((sec = elf_nextscn(elf, sec)) != NULL) {
        char *str;
        gelf_getshdr(sec, &shdr);
        str = elf_strptr(elf, hdr.e_shstrndx, shdr.sh_name);

        if (str && strcmp(".symtab", str) == 0) {
            symtab_sec = sec;
            memcpy(&symtab_shdr, &shdr, sizeof(dynsym_shdr));
        }
        if (str && strcmp(".dynsym", str) == 0) {
            dynsym_sec = sec;
            memcpy(&dynsym_shdr, &shdr, sizeof(dynsym_shdr));
        }
        if (str && strcmp(".rela.plt", str) == 0) {
            plt_rel_sec = sec;
            memcpy(&plt_rel_shdr, &shdr, sizeof(plt_rel_shdr));
        }
        if (str && strcmp(".plt", str) == 0) {
            plt_sec = sec;
            memcpy(&plt_shdr, &shdr, sizeof(plt_shdr));
        }
        if (str && strcmp(".gnu.prelink_undo", str) == 0) {
            is_reloc = 1;
        }
    }

    plt_ctx plt;  
    plt.dynsym.hdr = &dynsym_shdr;
    plt.dynsym.sec = dynsym_sec;
    plt.plt.hdr = &plt_shdr;
    plt.plt.sec = plt_sec;
    plt.plt_rel.hdr = &plt_rel_shdr;
    plt.plt_rel.sec = plt_rel_sec;

    symbol_sections_ctx si;
    memset(&si, 0, sizeof(si));
    if (symtab_sec) {
        get_symbols_in_section(&si.symtab, elf, symtab_sec, &symtab_shdr, is_reloc);
    }
    if (dynsym_sec) {
        get_symbols_in_section(&si.symtab_in_dynsym, elf, dynsym_sec, &dynsym_shdr, is_reloc);
    }
    if (dynsym_sec && plt_sec) {
        get_plt_symbols_in_section(&si.dynsymtab, elf, &plt);
    }

    get_all_symbols(ss, &si, elf);
    elf_end(elf);
    close(fd);
    return true;
}

struct symbol_cache_item {
    int start;
    int size;
    char name[0];
};

bool save_symbol_cache(std::set<symbol> &ss, const char *path)
{
    char buf[2048];
    int len = 0;
    bool status = true;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        status = false;
        return status;
    }
    int ret;
    ret = read(fd, &len, 4);
    if (ret <= 0) {
        close(fd);
        status = false;
        return status;
    }
    ret = read(fd, buf, len);
    if (ret <= 0) {
        close(fd);
        status = false;
        return status;
    }

    while (1) {
        struct symbol_cache_item *sym;
        symbol s;
        ret = read(fd, &len, 4);
        if (ret <= 0) {
            status = false;
            break;
        }
        ret = read(fd, buf, len);
        if (ret < len) {
            status = false;
            break;
        }
        sym = (struct symbol_cache_item *)buf;
        s.start = sym->start;
        s.end = sym->start + sym->size;
        s.ip = sym->start;
        s.name = sym->name;
        ss.insert(s);
    }
    close(fd);
    return status;
}

bool load_symbol_cache(std::set<symbol> &ss, const char *path, const char *filename)
{
    int fd = open(path, O_RDWR | O_EXCL);
    if (fd < 0) {
        return false;
    }
    int len = strlen(filename);
    int ret = write(fd, &len, 4);
    if (ret < 0) {
        close(fd);
        return false;
    }
    ret = write(fd, filename, len);
    if (ret < 0) {
        close(fd);
        return false;
    }

    std::set<symbol>::iterator it;
    int v;
    for (it = ss.begin(); it != ss.end(); ++it) {
        v = it->start;
        ret = write(fd, &v, 4);
        v = it->end - it->start;
        ret = write(fd, &v, 4);
        ret = write(fd, it->name.c_str(), it->name.length());
    }
    return true;
}
