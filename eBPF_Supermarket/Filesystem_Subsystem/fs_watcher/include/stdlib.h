/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifndef _INC_STDLIB
#define _INC_STDLIB
 
#include <crtdefs.h>
#include <limits.h>
 
#if defined (__USE_MINGW_ANSI_STDIO) && ((__USE_MINGW_ANSI_STDIO + 0) != 0) && !defined (__USE_MINGW_STRTOX)
#define __USE_MINGW_STRTOX 1
#endif
 
#pragma pack(push,_CRT_PACKING)
 
#ifdef __cplusplus
extern "C" {
#endif
 
#ifndef NULL
#ifdef __cplusplus
#ifndef _WIN64
#define NULL 0
#else
#define NULL 0LL
#endif  /* W64 */
#else
#define NULL ((void *)0)
#endif
#endif
 
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
 
#ifndef _ONEXIT_T_DEFINED
#define _ONEXIT_T_DEFINED
 
  typedef int (__cdecl *_onexit_t)(void);
 
#ifndef	NO_OLDNAMES
#define onexit_t _onexit_t
#endif
#endif
 
#ifndef _DIV_T_DEFINED
#define _DIV_T_DEFINED
 
  typedef struct _div_t {
    int quot;
    int rem;
  } div_t;
 
  typedef struct _ldiv_t {
    long quot;
    long rem;
  } ldiv_t;
#endif
 
#ifndef _CRT_DOUBLE_DEC
#define _CRT_DOUBLE_DEC
 
#pragma pack(4)
  typedef struct {
    unsigned char ld[10];
  } _LDOUBLE;
#pragma pack()
 
#define _PTR_LD(x) ((unsigned char *)(&(x)->ld))
 
  typedef struct {
    double x;
  } _CRT_DOUBLE;
 
  typedef struct {
    float f;
  } _CRT_FLOAT;
 
#pragma push_macro("long")
#undef long
 
  typedef struct {
    long double x;
  } _LONGDOUBLE;
 
#pragma pop_macro("long")
 
#pragma pack(4)
  typedef struct {
    unsigned char ld12[12];
  } _LDBL12;
#pragma pack()
#endif
 
#define RAND_MAX 0x7fff
 
#ifndef MB_CUR_MAX
#define MB_CUR_MAX ___mb_cur_max_func()
#ifndef __mb_cur_max
#ifdef _MSVCRT_
  extern int __mb_cur_max;
#define __mb_cur_max	__mb_cur_max
#else
  extern int * __MINGW_IMP_SYMBOL(__mb_cur_max);
#define __mb_cur_max	(* __MINGW_IMP_SYMBOL(__mb_cur_max))
#endif
#endif
#define ___mb_cur_max_func() (__mb_cur_max)
#endif
 
#define __max(a,b) (((a) > (b)) ? (a) : (b))
#define __min(a,b) (((a) < (b)) ? (a) : (b))
 
#define _MAX_PATH 260
#define _MAX_DRIVE 3
#define _MAX_DIR 256
#define _MAX_FNAME 256
#define _MAX_EXT 256
 
#define _OUT_TO_DEFAULT 0
#define _OUT_TO_STDERR 1
#define _OUT_TO_MSGBOX 2
#define _REPORT_ERRMODE 3
 
#define _WRITE_ABORT_MSG 0x1
#define _CALL_REPORTFAULT 0x2
 
#define _MAX_ENV 32767
 
  typedef void (__cdecl *_purecall_handler)(void);
 
  _CRTIMP _purecall_handler __cdecl _set_purecall_handler(_purecall_handler _Handler);
  _CRTIMP _purecall_handler __cdecl _get_purecall_handler(void);
 
  typedef void (__cdecl *_invalid_parameter_handler)(const wchar_t *,const wchar_t *,const wchar_t *,unsigned int,uintptr_t);
  _CRTIMP _invalid_parameter_handler __cdecl _set_invalid_parameter_handler(_invalid_parameter_handler _Handler);
  _CRTIMP _invalid_parameter_handler __cdecl _get_invalid_parameter_handler(void);
 
#ifndef _CRT_ERRNO_DEFINED
#define _CRT_ERRNO_DEFINED
  _CRTIMP extern int *__cdecl _errno(void);
#define errno (*_errno())
  errno_t __cdecl _set_errno(int _Value);
  errno_t __cdecl _get_errno(int *_Value);
#endif
  _CRTIMP unsigned long *__cdecl __doserrno(void);
#define _doserrno (*__doserrno())
  errno_t __cdecl _set_doserrno(unsigned long _Value);
  errno_t __cdecl _get_doserrno(unsigned long *_Value);
#ifdef _MSVCRT_
  extern char *_sys_errlist[];
  extern int _sys_nerr;
#else
  extern _CRTIMP char *_sys_errlist[1];
  extern _CRTIMP int _sys_nerr;
#endif
#if (defined(_X86_) && !defined(__x86_64))
  _CRTIMP int *__cdecl __p___argc(void);
  _CRTIMP char ***__cdecl __p___argv(void);
  _CRTIMP wchar_t ***__cdecl __p___wargv(void);
  _CRTIMP char ***__cdecl __p__environ(void);
  _CRTIMP wchar_t ***__cdecl __p__wenviron(void);
  _CRTIMP char **__cdecl __p__pgmptr(void);
  _CRTIMP wchar_t **__cdecl __p__wpgmptr(void);
#endif
#ifndef __argc
#ifdef _MSVCRT_
  extern int __argc;
#else
  extern int * __MINGW_IMP_SYMBOL(__argc);
#define __argc (* __MINGW_IMP_SYMBOL(__argc))
#endif
#endif
#ifndef __argv
#ifdef _MSVCRT_
  extern char **__argv;
#else
  extern char *** __MINGW_IMP_SYMBOL(__argv);
#define __argv	(* __MINGW_IMP_SYMBOL(__argv))
#endif
#endif
#ifndef __wargv
#ifdef _MSVCRT_
  extern wchar_t **__wargv;
#else
  extern wchar_t *** __MINGW_IMP_SYMBOL(__wargv);
#define __wargv (* __MINGW_IMP_SYMBOL(__wargv))
#endif
#endif
 
#ifdef _POSIX_
  extern char **environ;
#else
#ifndef _environ
#ifdef _MSVCRT_
  extern char **_environ;
#else
  extern char *** __MINGW_IMP_SYMBOL(_environ);
#define _environ (* __MINGW_IMP_SYMBOL(_environ))
#endif
#endif
 
#ifndef _wenviron
#ifdef _MSVCRT_
  extern wchar_t **_wenviron;
#else
  extern wchar_t *** __MINGW_IMP_SYMBOL(_wenviron);
#define _wenviron (* __MINGW_IMP_SYMBOL(_wenviron))
#endif
#endif
#endif
#ifndef _pgmptr
#ifdef _MSVCRT_
  extern char *_pgmptr;
#else
  extern char ** __MINGW_IMP_SYMBOL(_pgmptr);
#define _pgmptr	(* __MINGW_IMP_SYMBOL(_pgmptr))
#endif
#endif
 
#ifndef _wpgmptr
#ifdef _MSVCRT_
  extern wchar_t *_wpgmptr;
#else
  extern wchar_t ** __MINGW_IMP_SYMBOL(_wpgmptr);
#define _wpgmptr (* __MINGW_IMP_SYMBOL(_wpgmptr))
#endif
#endif
  errno_t __cdecl _get_pgmptr(char **_Value);
  errno_t __cdecl _get_wpgmptr(wchar_t **_Value);
#ifndef _fmode
#ifdef _MSVCRT_
  extern int _fmode;
#else
  extern int * __MINGW_IMP_SYMBOL(_fmode);
#define _fmode	(* __MINGW_IMP_SYMBOL(_fmode))
#endif
#endif
  _CRTIMP errno_t __cdecl _set_fmode(int _Mode);
  _CRTIMP