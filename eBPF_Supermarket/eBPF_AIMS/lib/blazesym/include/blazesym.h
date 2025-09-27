#ifndef __blazesym_h_
#define __blazesym_h_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The type of a symbol.
 */
typedef enum blaze_sym_type {
  /**
   * That type could not be determined (possibly because the source does not
   * contains information about the type).
   */
  BLAZE_SYM_UNKNOWN,
  /**
   * The symbol is a function.
   */
  BLAZE_SYM_FUNC,
  /**
   * The symbol is a variable.
   */
  BLAZE_SYM_VAR,
} blaze_sym_type;

/**
 * The valid variant kind in [`blaze_user_meta`].
 */
typedef enum blaze_user_meta_kind {
  /**
   * [`blaze_user_meta_variant::unknown`] is valid.
   */
  BLAZE_USER_META_UNKNOWN,
  /**
   * [`blaze_user_meta_variant::apk`] is valid.
   */
  BLAZE_USER_META_APK,
  /**
   * [`blaze_user_meta_variant::elf`] is valid.
   */
  BLAZE_USER_META_ELF,
} blaze_user_meta_kind;

/**
 * An inspector of various "sources".
 *
 * Object of this type can be used to perform inspections of supported sources.
 * E.g., using an ELF file as a source, information about a symbol can be
 * inquired based on its name.
 */
typedef struct blaze_inspector blaze_inspector;

/**
 * A normalizer for addresses.
 *
 * Address normalization is the process of taking virtual absolute
 * addresses as they are seen by, say, a process (which include
 * relocation and process specific layout randomizations, among other
 * things) and converting them to "normalized" virtual addresses as
 * they are present in, say, an ELF binary or a DWARF debug info file,
 * and one would be able to see them using tools such as readelf(1).
 */
typedef struct blaze_normalizer blaze_normalizer;

/**
 * Symbolizer provides an interface to symbolize addresses.
 *
 * An instance of this type is the unit at which symbolization inputs are
 * cached. That is to say, source files (DWARF, ELF, ...) and the parsed data
 * structures may be kept around in memory for the lifetime of this object to
 * speed up future symbolization requests. If you are working with large input
 * sources and/or do not intend to perform multiple symbolization requests
 * (i.e., [`symbolize`][Symbolizer::symbolize] or
 * [`symbolize_single`][Symbolizer::symbolize_single] calls) for the same
 * symbolization source, you may want to consider creating a new `Symbolizer`
 * instance regularly.
 */
typedef struct blaze_symbolizer blaze_symbolizer;

/**
 * Information about a looked up symbol.
 */
typedef struct blaze_sym_info {
  /**
   * See [`inspect::SymInfo::name`].
   */
  const char *name;
  /**
   * See [`inspect::SymInfo::addr`].
   */
  uintptr_t addr;
  /**
   * See [`inspect::SymInfo::size`].
   */
  size_t size;
  /**
   * See [`inspect::SymInfo::file_offset`].
   */
  uint64_t file_offset;
  /**
   * See [`inspect::SymInfo::obj_file_name`].
   */
  const char *obj_file_name;
  /**
   * See [`inspect::SymInfo::sym_type`].
   */
  enum blaze_sym_type sym_type;
} blaze_sym_info;

/**
 * An object representing an ELF inspection source.
 *
 * C ABI compatible version of [`inspect::Elf`].
 */
typedef struct blaze_inspect_elf_src {
  /**
   * The path to the ELF file. This member is always present.
   */
  const char *path;
  /**
   * Whether or not to consult debug information to satisfy the request (if
   * present).
   */
  bool debug_info;
} blaze_inspect_elf_src;

/**
 * C compatible version of [`Apk`].
 */
typedef struct blaze_user_meta_apk {
  /**
   * The canonical absolute path to the APK, including its name.
   * This member is always present.
   */
  char *path;
} blaze_user_meta_apk;

/**
 * C compatible version of [`Elf`].
 */
typedef struct blaze_user_meta_elf {
  /**
   * The path to the ELF file. This member is always present.
   */
  char *path;
  /**
   * The length of the build ID, in bytes.
   */
  size_t build_id_len;
  /**
   * The optional build ID of the ELF file, if found.
   */
  uint8_t *build_id;
} blaze_user_meta_elf;

/**
 * C compatible version of [`Unknown`].
 */
typedef struct blaze_user_meta_unknown {
  /**
   * This member is unused.
   */
  uint8_t _unused;
} blaze_user_meta_unknown;

/**
 * The actual variant data in [`blaze_user_meta`].
 */
typedef union blaze_user_meta_variant {
  /**
   * Valid on [`blaze_user_meta_kind::BLAZE_USER_META_APK`].
   */
  struct blaze_user_meta_apk apk;
  /**
   * Valid on [`blaze_user_meta_kind::BLAZE_USER_META_ELF`].
   */
  struct blaze_user_meta_elf elf;
  /**
   * Valid on [`blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN`].
   */
  struct blaze_user_meta_unknown unknown;
} blaze_user_meta_variant;

/**
 * C ABI compatible version of [`UserMeta`].
 */
typedef struct blaze_user_meta {
  /**
   * The variant kind that is present.
   */
  enum blaze_user_meta_kind kind;
  /**
   * The actual variant with its data.
   */
  union blaze_user_meta_variant variant;
} blaze_user_meta;

/**
 * A file offset or non-normalized address along with an index into the
 * associated [`blaze_user_meta`] array (such as
 * [`blaze_normalized_user_output::metas`]).
 */
typedef struct blaze_normalized_output {
  /**
   * The file offset or non-normalized address.
   */
  uint64_t output;
  /**
   * The index into the associated [`blaze_user_meta`] array.
   */
  size_t meta_idx;
} blaze_normalized_output;

/**
 * An object representing normalized user addresses.
 *
 * C ABI compatible version of [`UserOutput`].
 */
typedef struct blaze_normalized_user_output {
  /**
   * The number of [`blaze_user_meta`] objects present in `metas`.
   */
  size_t meta_cnt;
  /**
   * An array of `meta_cnt` objects.
   */
  struct blaze_user_meta *metas;
  /**
   * The number of [`blaze_normalized_output`] objects present in `outputs`.
   */
  size_t output_cnt;
  /**
   * An array of `output_cnt` objects.
   */
  struct blaze_normalized_output *outputs;
} blaze_normalized_user_output;

/**
 * A placeholder symbolizer for C API.
 *
 * It is returned by [`blaze_symbolizer_new`] and should be free by
 * [`blaze_symbolizer_free`].
 */
typedef struct blaze_symbolizer blaze_symbolizer;

/**
 * Options for configuring `blaze_symbolizer` objects.
 */
typedef struct blaze_symbolizer_opts {
  /**
   * Whether to enable usage of debug symbols.
   */
  bool debug_syms;
  /**
   * Whether to attempt to gather source code location information.
   *
   * This setting implies `debug_syms` (and forces it to `true`).
   */
  bool code_info;
  /**
   * Whether to report inlined functions as part of symbolization.
   */
  bool inlined_fns;
  /**
   * Whether or not to transparently demangle symbols.
   *
   * Demangling happens on a best-effort basis. Currently supported
   * languages are Rust and C++ and the flag will have no effect if
   * the underlying language does not mangle symbols (such as C).
   */
  bool demangle;
} blaze_symbolizer_opts;

/**
 * Source code location information for a symbol or inlined function.
 */
typedef struct blaze_symbolize_code_info {
  /**
   * The directory in which the source file resides.
   *
   * This attribute is optional and may be NULL.
   */
  const char *dir;
  /**
   * The file that defines the symbol.
   *
   * This attribute is optional and may be NULL.
   */
  const char *file;
  /**
   * The line number on which the symbol is located in the source
   * code.
   */
  uint32_t line;
  /**
   * The column number of the symbolized instruction in the source
   * code.
   */
  uint16_t column;
} blaze_symbolize_code_info;

/**
 * Data about an inlined function call.
 */
typedef struct blaze_symbolize_inlined_fn {
  /**
   * The symbol name of the inlined function.
   */
  const char *name;
  /**
   * Source code location information for the inlined function.
   */
  struct blaze_symbolize_code_info code_info;
} blaze_symbolize_inlined_fn;

/**
 * The result of symbolization of an address.
 *
 * A `blaze_sym` is the information of a symbol found for an
 * address.
 */
typedef struct blaze_sym {
  /**
   * The symbol name is where the given address should belong to.
   *
   * If an address could not be symbolized, this member will be NULL.
   */
  const char *name;
  /**
   * The address at which the symbol is located (i.e., its "start").
   *
   * This is the "normalized" address of the symbol, as present in
   * the file (and reported by tools such as `readelf(1)`,
   * `llvm-gsymutil`, or similar).
   */
  uintptr_t addr;
  /**
   * The byte offset of the address that got symbolized from the
   * start of the symbol (i.e., from `addr`).
   *
   * E.g., when normalizing address 0x1337 of a function that starts at
   * 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
   * member is especially useful in contexts when input addresses are not
   * already normalized, such as when normalizing an address in a process
   * context (which may have been relocated and/or have layout randomizations
   * applied).
   */
  size_t offset;
  /**
   * Source code location information for the symbol.
   */
  struct blaze_symbolize_code_info code_info;
  /**
   * The number of symbolized inlined function calls present.
   */
  size_t inlined_cnt;
  /**
   * An array of `inlined_cnt` symbolized inlined function calls.
   */
  const struct blaze_symbolize_inlined_fn *inlined;
} blaze_sym;

/**
 * `blaze_result` is the result of symbolization for C API.
 *
 * Instances of [`blaze_result`] are returned by any of the `blaze_symbolize_*`
 * variants. They should be freed by calling [`blaze_result_free`].
 */
typedef struct blaze_result {
  /**
   * The number of symbols being reported.
   */
  size_t cnt;
  /**
   * The symbols corresponding to input addresses.
   *
   * Symbolization happens based on the ordering of (input) addresses.
   * Therefore, every input address has an associated symbol.
   */
  struct blaze_sym syms[0];
} blaze_result;

/**
 * The parameters to load symbols and debug information from a process.
 *
 * Load all ELF files in a process as the sources of symbols and debug
 * information.
 */
typedef struct blaze_symbolize_src_process {
  /**
   * It is the PID of a process to symbolize.
   *
   * blazesym will parse `/proc/<pid>/maps` and load all the object
   * files.
   */
  uint32_t pid;
} blaze_symbolize_src_process;

/**
 * The parameters to load symbols and debug information from a kernel.
 *
 * Use a kernel image and a snapshot of its kallsyms as a source of symbols and
 * debug information.
 */
typedef struct blaze_symbolize_src_kernel {
  /**
   * The path of a copy of kallsyms.
   *
   * It can be `"/proc/kallsyms"` for the running kernel on the
   * device.  However, you can make copies for later.  In that situation,
   * you should give the path of a copy.
   * Passing a `NULL`, by default, will result in `"/proc/kallsyms"`.
   */
  const char *kallsyms;
  /**
   * The path of a kernel image.
   *
   * The path of a kernel image should be, for instance,
   * `"/boot/vmlinux-xxxx"`.  For a `NULL` value, it will locate the
   * kernel image of the running kernel in `"/boot/"` or
   * `"/usr/lib/debug/boot/"`.
   */
  const char *kernel_image;
} blaze_symbolize_src_kernel;

/**
 * The parameters to load symbols and debug information from an ELF.
 *
 * Describes the path and address of an ELF file loaded in a
 * process.
 */
typedef struct blaze_symbolize_src_elf {
  /**
   * The path to the ELF file.
   *
   * The referenced file may be an executable or shared object. For example,
   * passing "/bin/sh" will load symbols and debug information from `sh` and
   * passing "/lib/libc.so.xxx" will load symbols and debug information from
   * libc.
   */
  const char *path;
} blaze_symbolize_src_elf;

/**
 * The parameters to load symbols and debug information from "raw" Gsym data.
 */
typedef struct blaze_symbolize_src_gsym_data {
  /**
   * The Gsym data.
   */
  const uint8_t *data;
  /**
   * The size of the Gsym data.
   */
  size_t data_len;
} blaze_symbolize_src_gsym_data;

/**
 * The parameters to load symbols and debug information from a Gsym file.
 */
typedef struct blaze_symbolize_src_gsym_file {
  /**
   * The path to a gsym file.
   */
  const char *path;
} blaze_symbolize_src_gsym_file;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Lookup symbol information in an ELF file.
 *
 * Return an array with the same size as the input names. The caller should
 * free the returned array by calling [`blaze_inspect_syms_free`].
 *
 * Every name in the input name list may have more than one address.
 * The respective entry in the returned array is an array containing
 * all addresses and ended with a null (0x0).
 *
 * The returned pointer should be freed by [`blaze_inspect_syms_free`].
 *
 * # Safety
 * The `inspector` object should have been created using
 * [`blaze_inspector_new`], `src` needs to point to a valid object, and `names`
 * needs to be a valid pointer to `name_cnt` strings.
 */
const struct blaze_sym_info *const *blaze_inspect_syms_elf(const struct blaze_inspector *inspector,
                                                           const struct blaze_inspect_elf_src *src,
                                                           const char *const *names,
                                                           size_t name_cnt);

/**
 * Free an array returned by [`blaze_inspect_syms_elf`].
 *
 * # Safety
 *
 * The pointer must be returned by [`blaze_inspect_syms_elf`].
 *
 */
void blaze_inspect_syms_free(const struct blaze_sym_info *const *syms);

/**
 * Create an instance of a blazesym inspector.
 *
 * The returned pointer should be released using
 * [`blaze_inspector_free`] once it is no longer needed.
 */
struct blaze_inspector *blaze_inspector_new(void);

/**
 * Free a blazesym inspector.
 *
 * Release resources associated with a inspector as created by
 * [`blaze_inspector_new`], for example.
 *
 * # Safety
 * The provided inspector should have been created by
 * [`blaze_inspector_new`].
 */
void blaze_inspector_free(struct blaze_inspector *inspector);

/**
 * Create an instance of a blazesym normalizer.
 *
 * The returned pointer should be released using
 * [`blaze_normalizer_free`] once it is no longer needed.
 */
struct blaze_normalizer *blaze_normalizer_new(void);

/**
 * Free a blazesym normalizer.
 *
 * Release resources associated with a normalizer as created by
 * [`blaze_normalizer_new`], for example.
 *
 * # Safety
 * The provided normalizer should have been created by
 * [`blaze_normalizer_new`].
 */
void blaze_normalizer_free(struct blaze_normalizer *normalizer);

/**
 * Normalize a list of user space addresses.
 *
 * Contrary to [`blaze_normalize_user_addrs_sorted`] the provided
 * `addrs` array does not have to be sorted, but otherwise the
 * functions behave identically. If you happen to know that `addrs` is
 * sorted, using [`blaze_normalize_user_addrs_sorted`] instead will
 * result in slightly faster normalization.
 *
 * C ABI compatible version of [`Normalizer::normalize_user_addrs`].
 * Returns `NULL` on error. The resulting object should be freed using
 * [`blaze_user_output_free`].
 *
 * # Safety
 * Callers need to pass in a valid `addrs` pointer, pointing to memory of
 * `addr_cnt` addresses.
 */
struct blaze_normalized_user_output *blaze_normalize_user_addrs(const struct blaze_normalizer *normalizer,
                                                                const uintptr_t *addrs,
                                                                size_t addr_cnt,
                                                                uint32_t pid);

/**
 * Normalize a list of user space addresses.
 *
 * The `addrs` array has to be sorted in ascending order. By providing
 * a pre-sorted array the library does not have to sort internally,
 * which will result in quicker normalization. If you don't have sorted
 * addresses, use [`blaze_normalize_user_addrs`] instead.
 *
 * `pid` should describe the PID of the process to which the addresses
 * belongs. It may be `0` if they belong to the calling process.
 *
 * C ABI compatible version of [`Normalizer::normalize_user_addrs_sorted`].
 * Returns `NULL` on error. The resulting object should be freed using
 * [`blaze_user_output_free`].
 *
 * # Safety
 * Callers need to pass in a valid `addrs` pointer, pointing to memory of
 * `addr_cnt` addresses.
 */
struct blaze_normalized_user_output *blaze_normalize_user_addrs_sorted(const struct blaze_normalizer *normalizer,
                                                                       const uintptr_t *addrs,
                                                                       size_t addr_cnt,
                                                                       uint32_t pid);

/**
 * Free an object as returned by [`blaze_normalize_user_addrs`] or
 * [`blaze_normalize_user_addrs_sorted`].
 *
 * # Safety
 * The provided object should have been created by
 * [`blaze_normalize_user_addrs`] or [`blaze_normalize_user_addrs_sorted`].
 */
void blaze_user_output_free(struct blaze_normalized_user_output *output);

/**
 * Create an instance of a symbolizer.
 */
blaze_symbolizer *blaze_symbolizer_new(void);

/**
 * Create an instance of a symbolizer with configurable options.
 *
 * # Safety
 * `opts` needs to be a valid pointer.
 */
blaze_symbolizer *blaze_symbolizer_new_opts(const struct blaze_symbolizer_opts *opts);

/**
 * Free an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * The pointer must have been returned by [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`].
 */
void blaze_symbolizer_free(blaze_symbolizer *symbolizer);

/**
 * Symbolize a list of process virtual addresses.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_process`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_process_virt_addrs(blaze_symbolizer *symbolizer,
                                                              const struct blaze_symbolize_src_process *src,
                                                              const uintptr_t *addrs,
                                                              size_t addr_cnt);

/**
 * Symbolize a list of kernel virtual addresses.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_kernel`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_kernel_virt_addrs(blaze_symbolizer *symbolizer,
                                                             const struct blaze_symbolize_src_kernel *src,
                                                             const uintptr_t *addrs,
                                                             size_t addr_cnt);

/**
 * Symbolize file addresses in an ELF file.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_elf`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_elf_file_addrs(blaze_symbolizer *symbolizer,
                                                          const struct blaze_symbolize_src_elf *src,
                                                          const uintptr_t *addrs,
                                                          size_t addr_cnt);

/**
 * Symbolize file addresses using "raw" Gsym data.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_gsym_data`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_gsym_data_file_addrs(blaze_symbolizer *symbolizer,
                                                                const struct blaze_symbolize_src_gsym_data *src,
                                                                const uintptr_t *addrs,
                                                                size_t addr_cnt);

/**
 * Symbolize file addresses in a Gsym file.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_gsym_file`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_gsym_file_file_addrs(blaze_symbolizer *symbolizer,
                                                                const struct blaze_symbolize_src_gsym_file *src,
                                                                const uintptr_t *addrs,
                                                                size_t addr_cnt);

/**
 * Free an array returned by any of the `blaze_symbolize_*` variants.
 *
 * # Safety
 * The pointer must have been returned by any of the `blaze_symbolize_*`
 * variants.
 */
void blaze_result_free(const struct blaze_result *results);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* __blazesym_h_ */
