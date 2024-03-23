/*
 * stdio.h
 *
 * Definitions of types and prototypes of functions for operations on
 * standard input and standard output streams.
 *
 * $Id: stdio.h,v 0fe8afb3a429 2019/10/26 09:33:12 keith $
 *
 * Written by Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
 * Copyright (C) 1997-2005, 2007-2010, 2014-2019, MinGW.org Project.
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice, and the following
 * disclaimer shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OF OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * NOTE: The file manipulation functions provided by Microsoft seem to
 * work with either slash (/) or backslash (\) as the directory separator;
 * (this is consistent with Microsoft's own documentation, on MSDN).
 *
 */
#ifndef _STDIO_H
#pragma GCC system_header
 
/* When including <wchar.h>, some of the definitions and declarations
 * which are nominally provided in <stdio.h> must be duplicated.  Rather
 * than require duplicated maintenance effort, we provide for partial
 * inclusion of <stdio.h> by <wchar.h>; only when not included in
 * this partial fashion...
 */
#ifndef __WCHAR_H_SOURCED__
 /* ...which is exclusive to <wchar.h>, do we assert the multiple
  * inclusion guard for <stdio.h> itself.
  */
#define _STDIO_H
#endif
 
/* All the headers include this file.
 */
#include <_mingw.h>
 
#ifndef RC_INVOKED
/* POSIX stipulates that the following set of types, (as identified by
 * __need_TYPENAME macros), shall be defined consistently with <stddef.h>;
 * by defining the appropriate __need_TYPENAME macros, we may selectively
 * obtain the required definitions by inclusion of <stddef.h>, WITHOUT
 * automatic exposure of any of its additional content.
 */
#define __need_NULL
#define __need_size_t
#define __need_wchar_t
#define __need_wint_t
#include <stddef.h>
 
#if _POSIX_C_SOURCE >= 200809L
 /* Similarly, for types defined in <sys/types.h>, (which are explicitly
  * dependent on the POSIX.1-2008 feature test)...
  */
# define __need_off_t
# define __need_ssize_t
#endif
 
/* Although non-standard themselves, we also need either one or other
 * of the following pair of data types, from <sys/types.h>, because our
 * standard fpos_t is opaquely defined in terms of...
 */
#ifdef __MSVCRT__
 /* ...an explicitly 64-bit file offset type, for MSVCRT.DLL users...
  */
# define __need___off64_t
#else
 /* ...or a 32-bit equivalent, for pre-MSVCRT.DLL users.
  */
# define __need___off32_t
#endif
 
/* Note the use of the #include "..." form here, to ensure that we get
 * the correct header file, relative to the location of this <stdio.h>
 */
#include "sys/types.h"
 
#ifndef __VALIST
 /* Also similarly, for the va_list type, defined in "stdarg.h"
  */
# if defined __GNUC__ && __GNUC__ >= 3
#  define __need___va_list
#  include "stdarg.h"
#  define __VALIST __builtin_va_list
# else
#  define __VALIST char *
# endif
#endif
#endif	/* ! RC_INVOKED */
 
#ifdef _STDIO_H
/* Flags for the iobuf structure
 */
#define _IOREAD 	1	/* currently reading */
#define _IOWRT		2	/* currently writing */
#define _IORW	   0x0080	/* opened as "r+w" */
 
/* The three standard file pointers provided by the run time library.
 * NOTE: These will go to the bit-bucket silently in GUI applications!
 */
#define STDIN_FILENO	0
#define STDOUT_FILENO	1
#define STDERR_FILENO	2
 
/* Returned by various functions on end of file condition or error.
 */
#define EOF	      (-1)
 
#endif	/* _STDIO_H */
 
/* The maximum length of a file name.  It may be better to use the Windows'
 * GetVolumeInformation() function in preference to this constant, but hey,
 * this works!  Note that <io.h> also defines it, but we don't guard it, so
 * that the compiler has a chance to catch inconsistencies.
 *
 * FIXME: Right now, we define this unconditionally for both full <stdio.h>
 * inclusion, and for partial inclusion on behalf of <wchar.h>, (which needs
 * it for some non-ANSI structure declarations).  The conditions under which
 * <wchar.h> needs this require review, because defining it as a consequence
 * of including <wchar.h> alone may violate strict ANSI conformity.
 */
#define FILENAME_MAX  (260)
 
#ifdef _STDIO_H
/* The maximum number of files that may be open at once. I have set this to
 * a conservative number. The actual value may be higher.
 */
#define FOPEN_MAX      (20)
 
/* After creating this many names, tmpnam and tmpfile return NULL
 */
#define TMP_MAX      32767
 
/* Tmpnam, tmpfile and, sometimes, _tempnam try to create
 * temp files in the root directory of the current drive
 * (not in pwd, as suggested by some older MS doc's).
 * Redefining these macros does not effect the CRT functions.
 */
#define _P_tmpdir   "\\"
#ifndef __STRICT_ANSI__
#define P_tmpdir _P_tmpdir
#endif
#define _wP_tmpdir  L"\\"
 
/* The maximum size of name (including NUL) that will be put in the user
 * supplied buffer caName for tmpnam.
 * Inferred from the size of the static buffer returned by tmpnam
 * when passed a NULL argument. May actually be smaller.
 */
#define L_tmpnam (16)
 
#define _IOFBF		0x0000	/* full buffered */
#define _IOLBF		0x0040	/* line buffered */
#define _IONBF		0x0004	/* not buffered */
 
#define _IOMYBUF	0x0008	/* stdio malloc()'d buffer */
#define _IOEOF		0x0010	/* EOF reached on read */
#define _IOERR		0x0020	/* I/O error from system */
#define _IOSTRG 	0x0040	/* Strange or no file descriptor */
#ifdef _POSIX_SOURCE
# define _IOAPPEND	0x0200
#endif
 
/* The buffer size as used by setbuf such that it is equivalent to
 * (void) setvbuf(fileSetBuffer, caBuffer, _IOFBF, BUFSIZ).
 */
#define BUFSIZ		   512
 
/* Constants for nOrigin indicating the position relative to which fseek
 * sets the file position.  Defined unconditionally since ISO and POSIX
 * say they are defined here.
 */
#define SEEK_SET	     0
#define SEEK_CUR	     1
#define SEEK_END	     2
 
#endif	/* _STDIO_H */
 
#ifndef RC_INVOKED
#if ! (defined _STDIO_H && defined _WCHAR_H)
/* The structure underlying the FILE type; this should be defined when
 * including either <stdio.h> or <wchar.h>.  If both header include guards
 * are now in place, then we must currently be including <stdio.h> in its
 * own right, having already processed this block during a prior partial
 * inclusion by <wchar.h>; there is no need to process it a second time.
 *
 * Some believe that nobody in their right mind should make use of the
 * internals of this structure. Provided by Pedro A. Aranda Gutiirrez
 * <paag@tid.es>.
 */
typedef struct _iobuf
{
  char	*_ptr;
  int	 _cnt;
  char	*_base;
  int	 _flag;
  int	 _file;
  int	 _charbuf;
  int	 _bufsiz;
  char	*_tmpfname;
} FILE;
 
#endif  /* ! (_STDIO_H && _WCHAR_H) */
#ifdef _STDIO_H
/* Content to be exposed only when including <stdio.h> in its own right;
 * these will not be exposed when __WCHAR_H_SOURCE__ is defined, as will
 * be the case when <stdio.h> is included indirectly, by <wchar.h>
 *
 *
 * The standard file handles
 */
#ifndef __DECLSPEC_SUPPORTED
 
extern FILE (*_imp___iob)[];	/* A pointer to an array of FILE */
 
#define _iob (*_imp___iob)	/* An array of FILE */
 
#else /* __DECLSPEC_SUPPORTED */
 
__MINGW_IMPORT FILE _iob[];	/* An array of FILE imported from DLL. */
 
#endif /* __DECLSPEC_SUPPORTED */
 
#define stdin	(&_iob[STDIN_FILENO])
#define stdout	(&_iob[STDOUT_FILENO])
#define stderr	(&_iob[STDERR_FILENO])
 
/* Need to close the current _STDIO_H specific block here...
 */
#endif
/* ...because, we need this regardless of the inclusion mode...
 */
_BEGIN_C_DECLS
 
#ifdef _STDIO_H
/* ...then revert to _STDIO_H specific mode, to declare...
 *
 *
 * File Operations
 */
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * fopen (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * freopen (const char *, const char *, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fflush (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fclose (FILE *);
 
/* Note: Microsoft also declares remove & rename (but not their wide char
 * variants) in <io.h>; since duplicate prototypes are acceptable, provided
 * they are consistent, we simply declare them here anyway, while allowing
 * the compiler to check consistency as appropriate.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int    remove (const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    rename (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * tmpfile (void);
_CRTIMP __cdecl __MINGW_NOTHROW  char * tmpnam (char *);
 
#ifndef __STRICT_ANSI__
_CRTIMP __cdecl __MINGW_NOTHROW  char *_tempnam (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int   _rmtmp (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int   _unlink (const char *);
 
#if __MSVCRT_VERSION__>=__MSVCR80_DLL
/* The following pair of non-ANSI functions require a non-free version of
 * the Microsoft runtime; neither is provided by any MSVCRT.DLL variant.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  void  _lock_file(FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  void  _unlock_file(FILE *);
#endif
 
#ifndef NO_OLDNAMES
_CRTIMP __cdecl __MINGW_NOTHROW  char * tempnam (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    rmtmp (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    unlink (const char *);
#endif
#endif /* __STRICT_ANSI__ */
 
_CRTIMP __cdecl __MINGW_NOTHROW  int    setvbuf (FILE *, char *, int, size_t);
_CRTIMP __cdecl __MINGW_NOTHROW  void   setbuf (FILE *, char *);
 
/* Formatted Output
 *
 * MSVCRT implementations are not ANSI C99 conformant...
 * we offer conforming alternatives from libmingwex.a
 */
#undef  __mingw_stdio_redirect__
#define __mingw_stdio_redirect__(F) __cdecl __MINGW_NOTHROW __Wformat(F)
#define __Wformat_mingw_printf(F,A) __attribute__((__format__(__mingw_printf__,F,A)))
 
#if __GNUC__ >= 6
/* From GCC-6 onwards, we will provide customized -Wformat
 * handling, via our own mingw_printf format category...
 */
#define __Wformat(F)		__Wformat_##F __mingw_##F
 
#else	/* __GNUC__ < 6 */
/* ...whereas, for earlier GCC, we preserve the status quo,
 * offering no -Wformat checking for those functions which
 * replace the MSVCRT.DLL versions...
 */
#define __Wformat(F)		__mingw_##F
 
/* ...while degrading to gnu_printf checking for snprintf()
 * and vsnprintf(), (which are ALWAYS MinGW.org variants).
 */
#define __mingw_printf__	__gnu_printf__
#endif
 
/* The following convenience macros specify the appropriate
 * -Wformat checking for MSVCRT.DLL replacement functions...
 */
#define __Wformat_printf	__Wformat_mingw_printf(1,2)
#define __Wformat_fprintf	__Wformat_mingw_printf(2,3)
#define __Wformat_sprintf	__Wformat_mingw_printf(2,3)
#define __Wformat_vprintf	__Wformat_mingw_printf(1,0)
#define __Wformat_vfprintf	__Wformat_mingw_printf(2,0)
#define __Wformat_vsprintf	__Wformat_mingw_printf(2,0)
 
/* ...while this pair are specific to the two MinGW.org
 * only functions.
 */
#define __Wformat_snprintf	__Wformat_mingw_printf(3,4)
#define __Wformat_vsnprintf	__Wformat_mingw_printf(3,0)
 
extern int __mingw_stdio_redirect__(fprintf)(FILE*, const char*, ...);
extern int __mingw_stdio_redirect__(printf)(const char*, ...);
extern int __mingw_stdio_redirect__(sprintf)(char*, const char*, ...);
extern int __mingw_stdio_redirect__(snprintf)(char*, size_t, const char*, ...);
extern int __mingw_stdio_redirect__(vfprintf)(FILE*, const char*, __VALIST);
extern int __mingw_stdio_redirect__(vprintf)(const char*, __VALIST);
extern int __mingw_stdio_redirect__(vsprintf)(char*, const char*, __VALIST);
extern int __mingw_stdio_redirect__(vsnprintf)(char*, size_t, const char*, __VALIST);
 
/* When using these C99 conforming alternatives, we may wish to support
 * some of Microsoft's quirky formatting options, even when they violate
 * strict C99 conformance.
 */
#define _MSVC_PRINTF_QUIRKS		0x0100U
#define _QUERY_MSVC_PRINTF_QUIRKS	~0U, 0U
#define _DISABLE_MSVC_PRINTF_QUIRKS	~_MSVC_PRINTF_QUIRKS, 0U
#define _ENABLE_MSVC_PRINTF_QUIRKS	~0U, _MSVC_PRINTF_QUIRKS
 
/* Those quirks which conflict with ANSI C99 specified behaviour are
 * disabled by default; use the following function, like this:
 *
 *   _mingw_output_format_control( _ENABLE_MSVC_PRINTF_QUIRKS );
 *
 * to enable them, like this:
 *
 *   state = _mingw_output_format_control( _QUERY_MSVC_PRINTF_QUIRKS )
 *		& _MSVC_PRINTF_QUIRKS;
 *
 * to ascertain the currently active enabled state, or like this:
 *
 *   _mingw_output_format_control( _DISABLE_MSVC_PRINTF_QUIRKS );
 *
 * to disable them again.
 */
extern unsigned int _mingw_output_format_control( unsigned int, unsigned int );
 
#if __USE_MINGW_ANSI_STDIO || defined _ISOC99_SOURCE
/* User has expressed a preference for C99 conformance...
 */
# undef __mingw_stdio_redirect__
# if defined __GNUC__
/* FIXME: Is there any GCC version prerequisite here?
 *
 * We prefer inline implementations for both C and C++, when we can be
 * confident that the GNU specific __inline__ mechanism is supported.
 */
#  define __mingw_stdio_redirect__  static __inline__ __cdecl __MINGW_NOTHROW
 
# elif defined __cplusplus
/* For non-GNU C++ we use inline implementations, to avoid interference
 * with namespace qualification, which may result from using #defines.
 */
#  define __mingw_stdio_redirect__  inline __cdecl __MINGW_NOTHROW
 
# else	/* Neither GCC, nor non-GNU C++ */
/* Can't use inlines; fall back on module local static stubs.
 */
#  define __mingw_stdio_redirect__  static __cdecl __MINGW_NOTHROW
 
# endif	/* Neither GCC, nor non-GNU C++ */
#endif	/* __USE_MINGW_ANSI_STDIO || defined _ISOC99_SOURCE */
 
#if __USE_MINGW_ANSI_STDIO
/* The MinGW ISO-C conforming implementations of the printf() family
 * of functions are to be used, in place of non-conforming Microsoft
 * implementations; force call redirection, via the following set of
 * in-line functions.
 */
__mingw_stdio_redirect__
int fprintf (FILE *__stream, const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vfprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}
 
__mingw_stdio_redirect__
int printf (const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vprintf( __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}
 
__mingw_stdio_redirect__
int sprintf (char *__stream, const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vsprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}
 
__mingw_stdio_redirect__
int vfprintf (FILE *__stream, const char *__format, __VALIST __local_argv)
{
  return __mingw_vfprintf( __stream, __format, __local_argv );
}
 
__mingw_stdio_redirect__
int vprintf (const char *__format, __VALIST __local_argv)
{
  return __mingw_vprintf( __format, __local_argv );
}
 
__mingw_stdio_redirect__
int vsprintf (char *__stream, const char *__format, __VALIST __local_argv)
{
  return __mingw_vsprintf( __stream, __format, __local_argv );
}
 
#else	/* !__USE_MINGW_ANSI_STDIO */
/* Default configuration: simply direct all calls to MSVCRT...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int fprintf (FILE *, const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int printf (const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int sprintf (char *, const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int vfprintf (FILE *, const char *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int vprintf (const char *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int vsprintf (char *, const char *, __VALIST);
 
#endif	/* !__USE_MINGW_ANSI_STDIO */
 
#if __GNUC__ && defined _ISOC99_SOURCE
/* Although MinGW implementations of the ISO-C99 snprintf() and
 * vsnprintf() functions do not conflict with any implementation
 * in MSVCRT.DLL, (because MSVCRT.DLL does not implement either),
 * there are -Wformat attribute conflicts with the GCC built-in
 * prototypes associated with each; by providing the following
 * in-line function implementations, which will override GCC's
 * built-in prototypes, we may avoid these conflicts.
 */
__mingw_stdio_redirect__
int snprintf (char *__buf, size_t __len, const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vsnprintf( __buf, __len, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}
 
__mingw_stdio_redirect__
int vsnprintf (char *__buf, size_t __len, const char *__format, __VALIST __local_argv)
{
  return __mingw_vsnprintf( __buf, __len, __format, __local_argv );
}
#endif	/* __GNUC__ && defined _ISOC99_SOURCE */
 
/* Regardless of user preference, always offer these alternative
 * entry points, for direct access to the MSVCRT implementations,
 * with ms_printf -Wformat checking in each case.
 */
#undef  __Wformat
#undef  __mingw_stdio_redirect__
#define __mingw_stdio_redirect__(F) __cdecl __MINGW_NOTHROW __Wformat(F)
#define __Wformat_msvcrt_printf(F,A) __attribute__((__format__(__ms_printf__,F,A)))
#define __Wformat(F) __Wformat_ms_##F __msvcrt_##F
 
#define __Wformat_ms_printf	__Wformat_msvcrt_printf(1,2)
#define __Wformat_ms_fprintf	__Wformat_msvcrt_printf(2,3)
#define __Wformat_ms_sprintf	__Wformat_msvcrt_printf(2,3)
#define __Wformat_ms_vprintf	__Wformat_msvcrt_printf(1,0)
#define __Wformat_ms_vfprintf	__Wformat_msvcrt_printf(2,0)
#define __Wformat_ms_vsprintf	__Wformat_msvcrt_printf(2,0)
 
_CRTIMP int __mingw_stdio_redirect__(fprintf)(FILE *, const char *, ...);
_CRTIMP int __mingw_stdio_redirect__(printf)(const char *, ...);
_CRTIMP int __mingw_stdio_redirect__(sprintf)(char *, const char *, ...);
_CRTIMP int __mingw_stdio_redirect__(vfprintf)(FILE *, const char *, __VALIST);
_CRTIMP int __mingw_stdio_redirect__(vprintf)(const char *, __VALIST);
_CRTIMP int __mingw_stdio_redirect__(vsprintf)(char *, const char *, __VALIST);
 
#undef  __mingw_stdio_redirect__
#undef  __Wformat
 
/* The following three ALWAYS refer to the MSVCRT implementations...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int _snprintf (char *, size_t, const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int _vsnprintf (char *, size_t, const char *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int _vscprintf (const char *, __VALIST);
 
#ifdef _ISOC99_SOURCE
/* Microsoft does not provide implementations for the following,
 * which are required by C99.  Note in particular that Microsoft's
 * corresponding implementations of _snprintf() and _vsnprintf() are
 * NOT compatible with C99, but the following are; if you want the
 * MSVCRT behaviour, you MUST use the Microsoft "uglified" names.
 */
__cdecl __MINGW_NOTHROW __Wformat_snprintf
int snprintf (char *, size_t, const char *, ...);
 
__cdecl __MINGW_NOTHROW __Wformat_vsnprintf
int vsnprintf (char *, size_t, const char *, __VALIST);
 
__cdecl __MINGW_NOTHROW
int vscanf (const char * __restrict__, __VALIST);
 
__cdecl __MINGW_NOTHROW
int vfscanf (FILE * __restrict__, const char * __restrict__, __VALIST);
 
__cdecl __MINGW_NOTHROW
int vsscanf (const char * __restrict__, const char * __restrict__, __VALIST);
 
#endif  /* _ISOC99_SOURCE */
#endif	/* <stdio.h> included in its own right */
 
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL || _WIN32_WINNT >= _WIN32_WINNT_VISTA
/* In MSVCR80.DLL, (and its descendants), Microsoft introduced variants
 * of the printf() functions, with names qualified by an underscore prefix
 * and "_p" or "_p_l" suffixes; implemented in Microsoft's typically crass,
 * non-standard, and non-portable fashion, these provide support for access
 * to printf() arguments in random order, as was standardised by POSIX as a
 * feature of the optional Extended Systems Interface (XSI) specification,
 * and is now required for conformity with the POSIX.1-2008 base standard.
 * Although these additional Microsoft functions were subsequently added
 * to MSVCRT.DLL, from Windows-Vista onward, and they are prototyped here,
 * MinGW applications are strenuously encouraged to avoid using them; a
 * much better alternative is to "#define _XOPEN_SOURCE 700" before any
 * system header is included, then use POSIX standard printf() functions
 * instead; this is both portable to many non-Windows platforms, and it
 * offers better compatibility with earlier Windows versions.
 */
#ifndef __have_typedef_locale_t
/* Note that some of the following require the opaque locale_t data type,
 * which we may obtain, by selective inclusion, from <locale.h>
 */
#define __need_locale_t
#include <locale.h>
#endif
 
#ifdef _STDIO_H
/* The following are to be declared only when <stdio.h> is explicitly
 * included; the first six are NOT dependent on locale_t...
 */
_CRTIMP __cdecl __MINGW_NOTHROW
int _printf_p (const char *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _fprintf_p (FILE *, const char *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _sprintf_p (char *, size_t, const char *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vprintf_p (const char *, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vfprintf_p (FILE *, const char *, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vsprintf_p (char *, size_t, const char *, __VALIST);
 
/* ...whereas the following six DO depend on locale_t.
 *
 * CAVEAT: unless you are linking with non-free MSVCR80.DLL, or one
 * of its later derivatives, good luck trying to use these; see the
 * explanation in <locale.t>, as to why you may be unable to create,
 * or otherwise acquire a reference to, a locale_t object.
 */
_CRTIMP __cdecl __MINGW_NOTHROW
int _printf_p_l (const char *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _fprintf_p_l (FILE *, const char *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _sprintf_p_l (char *, size_t, const char *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vprintf_p_l (const char *, locale_t, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vfprintf_p_l (FILE *, const char *, locale_t, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vsprintf_p_l (char *, size_t, const char *, locale_t, __VALIST);
 
#endif	/* <stdio.h> included in its own right */
#endif	/* MSVCR80.DLL and descendants, or MSVCRT.DLL since Vista */
 
#if ! (defined _STDIO_H && defined _WCHAR_H)
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL || _WIN32_WINNT >= _WIN32_WINNT_VISTA
/* Wide character variants of the foregoing "positional parameter" printf()
 * functions; MSDN says that these should be declared when either <stdio.h>, or
 * <wchar.h> is included, so we make them selectively available to <wchar.h>,
 * but, just as in the foregoing, we advise against their use.
 */
_CRTIMP __cdecl __MINGW_NOTHROW
int _wprintf_p (const wchar_t *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _fwprintf_p (FILE *, const wchar_t *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _swprintf_p (wchar_t *, size_t, const wchar_t *, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vwprintf_p (const wchar_t *, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vfwprintf_p (FILE *, const wchar_t *, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vswprintf_p (wchar_t *, size_t, const wchar_t *, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _wprintf_p_l (const wchar_t *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _fwprintf_p_l (FILE *, const wchar_t *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _swprintf_p_l (wchar_t *, size_t, const wchar_t *, locale_t, ...);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vwprintf_p_l (const wchar_t *, locale_t, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vfwprintf_p_l (FILE *, const wchar_t *, locale_t, __VALIST);
 
_CRTIMP __cdecl __MINGW_NOTHROW
int _vswprintf_p_l (wchar_t *, size_t, const wchar_t *, locale_t, __VALIST);
 
#endif	/* MSVCR80.DLL and descendants, or MSVCRT.DLL since Vista */
#endif	/* ! (defined _STDIO_H && defined _WCHAR_H) */
#ifdef _STDIO_H
/* Once again, back to <stdio.h> specific declarations.
 */
#if _POSIX_C_SOURCE >= 200809L
/* POSIX standard IEEE 1003.1-2008 added getdelim() and getline()
 */
__cdecl __MINGW_NOTHROW ssize_t
getdelim (char ** __restrict__, size_t * __restrict__, int, FILE * __restrict__);
 
__cdecl __MINGW_NOTHROW ssize_t
getline (char ** __restrict__, size_t * __restrict__, FILE * __restrict__);
 
#ifndef __NO_INLINE__
/* getline() is a trivial specialization of getdelim(), which may
 * be readily expressed by inline expansion.
 */
__CRT_ALIAS __LIBIMPL__(( FUNCTION = getline ))
__cdecl __MINGW_NOTHROW ssize_t getline
( char **__restrict__ __l, size_t *__restrict__ __n, FILE *__restrict__ __s )
{ return getdelim( __l, __n, '\n', __s ); }
 
#endif  /* !__NO_INLINE__ */
#endif  /* POSIX.1-2008 */
 
/* Formatted Input
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int    fscanf (FILE *, const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int    scanf (const char *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int    sscanf (const char *, const char *, ...);
 
/* Character Input and Output Functions
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int    fgetc (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  char * fgets (char *, int, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fputc (int, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fputs (const char *, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  char * gets (char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    puts (const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    ungetc (int, FILE *);
 
/* Traditionally, getc and putc are defined as macros. but the
 * standard doesn't say that they must be macros.  We use inline
 * functions here to allow the fast versions to be used in C++
 * with namespace qualification, eg., ::getc.
 *
 * NOTE: _filbuf and _flsbuf  are not thread-safe.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int   _filbuf (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int   _flsbuf (int, FILE *);
 
#if !defined _MT
 
__CRT_INLINE __cdecl __MINGW_NOTHROW  int getc (FILE *);
__CRT_INLINE __cdecl __MINGW_NOTHROW  int getc (FILE * __F)
{
  return (--__F->_cnt >= 0)
    ?  (int) (unsigned char) *__F->_ptr++
    : _filbuf (__F);
}
 
__CRT_INLINE __cdecl __MINGW_NOTHROW  int putc (int, FILE *);
__CRT_INLINE __cdecl __MINGW_NOTHROW  int putc (int __c, FILE * __F)
{
  return (--__F->_cnt >= 0)
    ?  (int) (unsigned char) (*__F->_ptr++ = (char)__c)
    :  _flsbuf (__c, __F);
}
 
__CRT_INLINE __cdecl __MINGW_NOTHROW  int getchar (void);
__CRT_INLINE __cdecl __MINGW_NOTHROW  int getchar (void)
{
  return (--stdin->_cnt >= 0)
    ?  (int) (unsigned char) *stdin->_ptr++
    : _filbuf (stdin);
}
 
__CRT_INLINE __cdecl __MINGW_NOTHROW  int putchar(int);
__CRT_INLINE __cdecl __MINGW_NOTHROW  int putchar(int __c)
{
  return (--stdout->_cnt >= 0)
    ?  (int) (unsigned char) (*stdout->_ptr++ = (char)__c)
    :  _flsbuf (__c, stdout);}
 
#else  /* Use library functions.  */
 
_CRTIMP __cdecl __MINGW_NOTHROW  int    getc (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    putc (int, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    getchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    putchar (int);
 
#endif
 
/* Direct Input and Output Functions
 */
_CRTIMP __cdecl __MINGW_NOTHROW  size_t fread (void *, size_t, size_t, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  size_t fwrite (const void *, size_t, size_t, FILE *);
 
/* File Positioning Functions
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int    fseek (FILE *, long, int);
_CRTIMP __cdecl __MINGW_NOTHROW  long   ftell (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  void   rewind (FILE *);
 
#ifdef __USE_MINGW_FSEEK
/* Workaround for a limitation on Win9x where a file is not zero padded
 * on write, following a seek beyond the original end of file; supporting
 * redirector functions are implemented in libmingwex.a
 *
 * Note: this is improper usage.  __USE_MINGW_FSEEK exhibits the form of a
 * private (system reserved) feature test macro; as such, users should not
 * define it directly, and thus, it really should not have been defined at
 * this point; discourage this practice.
 */
#warning "The __USE_MINGW_FSEEK feature test is deprecated"
#pragma info "Define _WIN32_WINDOWS, instead of __USE_MINGW_FSEEK"
 
#elif _WIN32_WINDOWS >= _WIN32_WINDOWS_95 && _WIN32_WINDOWS < _WIN32_WINNT_WIN2K
/* This is correct usage; the private __USE_MINGW_FSEEK feature affects only
 * Win9x, so enable it implicitly when the _WIN32_WINDOWS feature is specified,
 * thus indicating the user's intent to target a Win9x platform.
 */
#define __USE_MINGW_FSEEK
#endif
 
#ifdef __USE_MINGW_FSEEK
/* Regardless of how it may have become defined, when __USE_MINGW_FSEEK has
 * been defined, we must redirect calls to fseek() and fwrite(), so that the
 * Win9x zero padding limitation can be mitigated.
 */
__cdecl __MINGW_NOTHROW  int __mingw_fseek (FILE *, __off64_t, int);
__CRT_ALIAS int fseek( FILE *__fp, long __offset, int __whence )
{ return __mingw_fseek( __fp, (__off64_t)(__offset), __whence ); }
 
__cdecl __MINGW_NOTHROW  size_t __mingw_fwrite (const void *, size_t, size_t, FILE *);
__CRT_ALIAS size_t fwrite( const void *__buf, size_t __len, size_t __cnt, FILE *__fp )
{ return __mingw_fwrite( __buf, __len, __cnt, __fp ); }
#endif /* __USE_MINGW_FSEEK */
 
/* An opaque data type used for storing file positions...  The contents
 * of this type are unknown, but we (the compiler) need to know the size
 * because the programmer using fgetpos and fsetpos will be setting aside
 * storage for fpos_t aggregates.  Actually I tested using a byte array and
 * it is fairly evident that fpos_t is a 32-bit type in CRTDLL.DLL, but in
 * MSVCRT.DLL, it is a 64-bit type.  Define it in terms of an int type of
 * the appropriate size, encapsulated within an aggregate type, to make
 * it opaque to casting, and so discourage abuse.
 */
#ifdef __MSVCRT__
typedef union { __int64 __value; __off64_t __offset; } fpos_t;
#else
typedef union { __int32 __value; __off32_t __offset; } fpos_t;
#endif
 
_CRTIMP __cdecl __MINGW_NOTHROW  int fgetpos (FILE *, fpos_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  int fsetpos (FILE *, const fpos_t *);
 
#if _WIN32_WINNT >= _WIN32_WINNT_VISTA || __MSVCRT_VERSION__ >= __MSVCR80_DLL
 /* Microsoft introduced a number of variations on fseek() and ftell(),
  * beginning with MSVCR80.DLL; the bare _fseeki64() and _ftelli64() were
  * subsequently integrated into MSVCRT.DLL, from Vista onward...
  */
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fseeki64 (FILE *, __int64, int);
_CRTIMP __cdecl __MINGW_NOTHROW __int64 _ftelli64 (FILE *);
 
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL
 /* ...while the "nolock" variants remain exclusive to MSVCR80.DLL, and
  * its later MSVC specific derivatives.
  */
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fseek_nolock (FILE *, long, int);
_CRTIMP __cdecl __MINGW_NOTHROW  long   _ftell_nolock (FILE *);
 
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fseeki64_nolock (FILE *, __int64, int);
_CRTIMP __cdecl __MINGW_NOTHROW __int64 _ftelli64_nolock (FILE *);
 
#endif  /* MSVCR80.DLL and later derivatives ONLY */
 
#else	/* pre-MSVCR80.DLL or MSVCRT.DLL pre-Vista */
/* The Microsoft DLLs don't provide either _fseeki64() or _ftelli64(), but
 * they DO provide fgetpos(), fsetpos(), and _lseeki64(), which may be used
 * to emulate the two missing functions.  (Note that we choose to provide
 * these emulations in the form of MinGW external helper functions, rather
 * than pollute the <stdio.h> namespace with declarations, such as that
 * for _lseeki64(), which properly belongs in <io.h>).
 */
#ifndef __USE_MINGW_FSEEK
/* If this option has been selected, an alternative emulation for _fseeki64()
 * is provided later, to ensure that the call is wrapped in a MinGW specific
 * fseek() handling API.
 */
int __cdecl __MINGW_NOTHROW __mingw_fseeki64 (FILE *, __int64, int);
__CRT_ALIAS __cdecl __MINGW_NOTHROW  int _fseeki64 (FILE *__f, __int64 __o, int __w)
{ return __mingw_fseeki64 (__f, __o, __w); }
#endif
 
__int64 __cdecl __MINGW_NOTHROW __mingw_ftelli64 (FILE *);
__CRT_ALIAS __cdecl  __int64 __MINGW_NOTHROW _ftelli64 (FILE *__file )
{ return __mingw_ftelli64 (__file); }
 
#endif	/* pre-MSVCR80.DLL or MSVCRT.DLL pre-Vista */
 
/* Error Functions
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int feof (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int ferror (FILE *);
 
#ifdef __cplusplus
inline __cdecl __MINGW_NOTHROW  int feof (FILE * __F){ return __F->_flag & _IOEOF; }
inline __cdecl __MINGW_NOTHROW  int ferror (FILE * __F){ return __F->_flag & _IOERR; }
#else
#define feof(__F)     ((__F)->_flag & _IOEOF)
#define ferror(__F)   ((__F)->_flag & _IOERR)
#endif
 
_CRTIMP __cdecl __MINGW_NOTHROW  void clearerr (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  void perror (const char *);
 
#ifndef __STRICT_ANSI__
/*
 * Pipes
 */
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * _popen (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _pclose (FILE *);
 
#ifndef NO_OLDNAMES
_CRTIMP __cdecl __MINGW_NOTHROW  FILE *  popen (const char *, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int     pclose (FILE *);
#endif
 
/* Other Non ANSI functions
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int    _flushall (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fgetchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fputchar (int);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * _fdopen (int, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fileno (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _fcloseall (void);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * _fsopen (const char *, const char *, int);
#ifdef __MSVCRT__
_CRTIMP __cdecl __MINGW_NOTHROW  int    _getmaxstdio (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _setmaxstdio (int);
#endif
 
/* Microsoft introduced a capability in MSVCR80.DLL and later, to
 * set the minimum number of digits to be displayed in a printf()
 * floating point exponent; they retro-fitted this in MSVCRT.DLL,
 * from Windows-Vista onwards, but we provide our own wrappers in
 * libmingwex.a, which make it possible for us to emulate the API
 * for any version of MSVCRT.DLL (including WinXP and earlier).
 */
#define _TWO_DIGIT_EXPONENT    1
 
/* While Microsoft define the preceding manifest constant, they
 * appear to neglect to define its complement, (for restoration
 * of their default exponent display format); for orthogonality,
 * we will provide this regardless of Microsoft's negligence.
 */
#define _THREE_DIGIT_EXPONENT  0
 
/* Once again, unspecified by Microsoft, (and mostly redundant),
 * it is convenient to specify a combining mask for these.
 */
#define _EXPONENT_DIGIT_MASK  (_TWO_DIGIT_EXPONENT | _THREE_DIGIT_EXPONENT)
 
unsigned int __cdecl __mingw_get_output_format (void);
unsigned int __cdecl __mingw_set_output_format (unsigned int);
 
/* Also appearing for the first time in MSVCR80.DLL, and then also
 * retro-fitted to MSVCRT.DLL from Windows-Vista onwards, was this
 * pair of functions to control availability of "%n" formatting in
 * the MSVCRT.DLL printf() family of functions, for which we also
 * provide our own DLL version agnostic wrappers:
 */
int __cdecl __mingw_get_printf_count_output (void);
int __cdecl __mingw_set_printf_count_output (int);
 
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL
/* When the user declares that MSVCR80.DLL features are supported,
 * we simply expose the corresponding APIs...
 */
_CRTIMP unsigned int __cdecl __MINGW_NOTHROW _get_output_format (void);
_CRTIMP unsigned int __cdecl __MINGW_NOTHROW _set_output_format (unsigned int);
 
_CRTIMP __cdecl __MINGW_NOTHROW  int _get_printf_count_output (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int _set_printf_count_output (int);
 
#else
/* ...otherwise, we emulate the APIs, in a DLL version agnostic
 * manner, using our own implementation wrappers.
 */
__CRT_ALIAS unsigned int __cdecl _get_output_format (void)
{ return __mingw_get_output_format (); }
 
__CRT_ALIAS unsigned int __cdecl _set_output_format (unsigned int __style)
{ return __mingw_set_output_format (__style); }
 
/* When using our own printf() implementation, "%n" format is ALWAYS
 * supported, so we make this API a no-op, reporting it to be so; for
 * the alternative case, when using MSVCRT.DLL's printf(), we delegate
 * to our wrapper API implementation, which will invoke the API function
 * calls within the DLL, if they are available, or persistently report
 * the state of "%n" formatting as DISABLED if they are not.
 */
#if __USE_MINGW_ANSI_STDIO
/* Note that __USE_MINGW_ANSI_STDIO is not guaranteed to resolve to any
 * symbol which will represent a compilable logic state; map it to this
 * alternative which will, for the true state...
 */
# define __USE_MINGW_PRINTF  1
#else
/* ...and for the false.
 */
# define __USE_MINGW_PRINTF  0
#endif
 
__CRT_ALIAS int __cdecl _get_printf_count_output (void)
{ return __USE_MINGW_PRINTF ? 1 : __mingw_get_printf_count_output (); }
 
__CRT_ALIAS int __cdecl _set_printf_count_output (int __mode)
{ return __USE_MINGW_PRINTF ? 1 : __mingw_set_printf_count_output (__mode); }
#endif
 
#ifndef _NO_OLDNAMES
_CRTIMP __cdecl __MINGW_NOTHROW  int    fgetchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fputchar (int);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * fdopen (int, const char *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    fileno (FILE *);
#endif	/* !_NO_OLDNAMES */
 
#define _fileno(__F) ((__F)->_file)
#ifndef _NO_OLDNAMES
#define fileno(__F) ((__F)->_file)
#endif
 
#if defined (__MSVCRT__) && ! defined (__NO_MINGW_LFS)
__CRT_ALIAS FILE * __cdecl __MINGW_NOTHROW  fopen64 (const char *, const char *);
__CRT_ALIAS __JMPSTUB__(( FUNCTION = fopen64, REMAPPED = fopen ))
FILE * __cdecl __MINGW_NOTHROW  fopen64 (const char * filename, const char * mode)
{ return fopen (filename, mode); }
 
int __cdecl __MINGW_NOTHROW  fseeko64 (FILE *, __off64_t, int);
 
#ifdef __USE_MINGW_FSEEK
/* When this option is selected, we need to redirect calls to _fseeki64()
 * and fseeko64() through a MinGW specific wrapper.  Since the two functions
 * are fundamentally identical, differing only in the type of the "offset"
 * argument, (and both types are effectively 64-bit signed ints anyway),
 * the same wrapper will suffice for both.
 */
__CRT_ALIAS int _fseeki64( FILE *__fp, __int64 __offset, int __whence )
{ return __mingw_fseek( __fp, (__off64_t)(__offset), __whence ); }
 
__CRT_ALIAS int fseeko64( FILE *__fp, __off64_t __offset, int __whence )
{ return __mingw_fseek( __fp, __offset, __whence ); }
#endif
 
__off64_t __cdecl __MINGW_NOTHROW ftello64 (FILE *);
 
#endif	/* __MSVCRT__ && !__NO_MINGW_LFS */
#endif	/* !__STRICT_ANSI__ */
#endif	/* _STDIO_H */
 
#if ! (defined _STDIO_H && defined _WCHAR_H)
/* The following are declared when including either <stdio.h> or <wchar.h>.
 * If both header include guards are now in place, then we must currently be
 * including <stdio.h> in its own right, having already processed this block
 * during prior partial inclusion by <wchar.h>; there is no need to process
 * it a second time.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int     fwprintf (FILE *, const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int     wprintf (const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int     vfwprintf (FILE *, const wchar_t *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int     vwprintf (const wchar_t *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _snwprintf (wchar_t *, size_t, const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _vscwprintf (const wchar_t *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _vsnwprintf (wchar_t *, size_t, const wchar_t *, __VALIST);
_CRTIMP __cdecl __MINGW_NOTHROW  int     fwscanf (FILE *, const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int     wscanf (const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int     swscanf (const wchar_t *, const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t  fgetwc (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t  fputwc (wchar_t, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t  ungetwc (wchar_t, FILE *);
 
#ifndef __STRICT_ANSI__
/* These differ from the ISO C prototypes, which have a maxlen parameter (like snprintf).
 */
_CRTIMP __cdecl __MINGW_NOTHROW  int  swprintf (wchar_t *, const wchar_t *, ...);
_CRTIMP __cdecl __MINGW_NOTHROW  int  vswprintf (wchar_t *, const wchar_t *, __VALIST);
#endif
 
#ifdef __MSVCRT__
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t * fgetws (wchar_t *, int, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int       fputws (const wchar_t *, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t    getwc (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t    getwchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t    putwc (wint_t, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t    putwchar (wint_t);
 
#ifndef __STRICT_ANSI__
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t * _getws (wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  int       _putws (const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE    * _wfdopen(int, const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE    * _wfopen (const wchar_t *, const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE    * _wfreopen (const wchar_t *, const wchar_t *, FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE    * _wfsopen (const wchar_t *, const wchar_t *, int);
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t * _wtmpnam (wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t * _wtempnam (const wchar_t *, const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  int       _wrename (const wchar_t *, const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  int       _wremove (const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  void      _wperror (const wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  FILE    * _wpopen (const wchar_t *, const wchar_t *);
 
#endif  /* !__STRICT_ANSI__ */
#endif	/* __MSVCRT__ */
 
#ifdef _ISOC99_SOURCE
__JMPSTUB__(( FUNCTION = snwprintf, DLLENTRY = _snwprintf ))
__cdecl __MINGW_NOTHROW  int snwprintf (wchar_t *, size_t, const wchar_t *, ...);
__cdecl __MINGW_NOTHROW  int vsnwprintf (wchar_t *, size_t, const wchar_t *, __VALIST);
 
#ifndef __NO_INLINE__
__CRT_INLINE __cdecl __MINGW_NOTHROW
__JMPSTUB__(( FUNCTION = vsnwprintf, DLLENTRY = _vsnwprintf ))
int vsnwprintf (wchar_t *__s, size_t __n, const wchar_t *__fmt, __VALIST __arg)
{ return _vsnwprintf ( __s, __n, __fmt, __arg); }
#endif
 
__cdecl __MINGW_NOTHROW  int  vwscanf (const wchar_t *__restrict__, __VALIST);
__cdecl __MINGW_NOTHROW
int  vfwscanf (FILE *__restrict__, const wchar_t *__restrict__, __VALIST);
__cdecl __MINGW_NOTHROW
int  vswscanf (const wchar_t *__restrict__, const wchar_t * __restrict__, __VALIST);
 
#endif  /* _ISOC99_SOURCE */
#endif  /* ! (_STDIO_H && _WCHAR_H) */
 
#if defined _STDIO_H && ! defined __STRICT_ANSI__
#if defined __MSVCRT__ && ! defined _NO_OLDNAMES
_CRTIMP __cdecl __MINGW_NOTHROW  FILE * wpopen (const wchar_t *, const wchar_t *);
#endif
 
/* Other non-ANSI wide character functions...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t _fgetwchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t _fputwchar (wint_t);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _getw (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int    _putw (int, FILE *);
 
#ifndef _NO_OLDNAMES
/* ...and their original names, before Microsoft uglification...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t  fgetwchar (void);
_CRTIMP __cdecl __MINGW_NOTHROW  wint_t  fputwchar (wint_t);
_CRTIMP __cdecl __MINGW_NOTHROW  int     getw (FILE *);
_CRTIMP __cdecl __MINGW_NOTHROW  int     putw (int, FILE *);
 
#endif  /* !_NO_OLDNAMES */
#endif  /* !__STRICT_ANSI__ */
 
_END_C_DECLS
 
#endif	/* ! RC_INVOKED */
#endif  /* !_STDIO_H: $RCSfile: stdio.h,v $: end of file */