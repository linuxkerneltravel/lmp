/*
 * time.h
 *
 * Type definitions and function declarations relating to date and time.
 *
 * $Id: time.h,v c10027655651 2018/10/18 08:50:58 keith $
 *
 * Written by Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
 * Copyright (C) 1997-2007, 2011, 2015-2018, MinGW.org Project.
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
 */
#if ! defined _TIME_H || defined __need_time_t
#pragma GCC system_header
 
/* Irrespective of whether this is normal or selective inclusion of
 * <time.h>, we ALWAYS require the definition for time_t; get it by
 * selective inclusion from its primary source, in <sys/types.h>;
 * note that we must ALWAYS delegate this, when __need_time_t is
 * defined, even when _TIME_H had been defined previously, to ensure
 * that __need_time_t is properly reset, and thus cannot compromise
 * a later inclusion of <sys/types.h>
 */
#undef __need_time_h
#define __need_time_t  1
#include <sys/types.h>
 
#ifndef _TIME_H
/* To support selective partial inclusion, we do not immediately define
 * the normal _TIME_H guard macro; initially, we also clear all of those
 * declaraction subset selection macros which are applicable herein.
 */
#undef __need_struct_timespec
#undef __need_wchar_decls
 
#if defined __SCHED_H_SOURCED__
/* This is selective inclusion by <sched.h>; although not a standard
 * MinGW.org header, we provide this hook to grant access from third
 * party implementations, (e.g. pthreads-win32), to get a definition
 * for struct timespec, which POSIX requires it to provide.
 *
 * Note that, in common with all selective inclusion strategies, we
 * do not define the _TIME_H guard macro in this case, and we select
 * only the minimally required subset of declarations to be exposed
 * from within <time.h>, as required by <sched.h>
 */
# define __need_struct_timespec  1
 
#elif defined __WCHAR_H_SOURCED__
/* This is selective inclusion by <wchar.h>; thus, we do not define the
 * _TIME_H guard macro, and we select only the minimally required subset
 * of declarations to be exposed from within <time.h>
 */
# define __need_wchar_decls  1
 
/* Both ISO-C and POSIX stipulate that <wchar.h> shall declare "struct tm"
 * as an incomplete structure, with its complete declaration to be provided
 * by <time.h>; provide an incomplete forward declaration, to satisfy this
 * minimal requirement for selective inclusion by <wchar.h>
 */
struct tm;
 
#else
#define _TIME_H
/* This is normal inclusion of <time.h>, in its own right.  All our system
 * headers are required to include <_mingw.h>, but in the case of selective
 * inclusion, we delegate that responsibility to the including header; when
 * including <time.h> directly, we must fulfil this requirement now.
 */
#include <_mingw.h>
 
/* Number of clock ticks per second. A clock tick is the unit by which
 * processor time is measured and is returned by 'clock'.
 */
#define CLOCKS_PER_SEC	((clock_t)(1000))
#define CLK_TCK 	CLOCKS_PER_SEC
 
#define __need_struct_timespec  1
#define __need_wchar_decls  1
#endif
 
#ifndef RC_INVOKED
#if defined __need_struct_timespec && ! __struct_timespec_defined
/* Structure timespec is mandated by POSIX, for specification of
 * intervals with the greatest precision supported by the OS kernel.
 * Although this allows for specification to nanosecond precision, do
 * not be deluded into any false expectation that such short intervals
 * can be realized on Windows; on Win9x derivatives, the metronome used
 * by the process scheduler has a period of ~55 milliseconds, while for
 * WinNT derivatives, the corresponding period is ~15 milliseconds; thus,
 * the shortest intervals which can be realistically timed will range
 * from 0..55 milliseconds on Win9x hosts, and from 0..15 ms on WinNT,
 * with period values normally distributed around means of ~27.5 ms
 * and ~7.5 ms, for the two system types respectively.
 */
struct timespec
{ /* Period is sum of tv_sec + tv_nsec; while 32-bits is sufficient
   * to accommodate tv_nsec, we use 64-bit __time64_t for tv_sec, to
   * ensure that we have a sufficiently large field to accommodate
   * Microsoft's ambiguous __time32_t vs. __time64_t representation
   * of time_t; we may resolve this ambiguity locally, by casting a
   * pointer to a struct timespec to point to an identically sized
   * struct __mingw32_timespec, which is defined below.
   */
  __time64_t	  tv_sec;	/* seconds; accept 32 or 64 bits */
  __int32  	  tv_nsec;	/* nanoseconds */
};
 
# ifdef _MINGW32_SOURCE_EXTENDED
struct __mingw32_expanded_timespec
{
  /* Equivalent of struct timespec, with disambiguation for the
   * 32-bit vs. 64-bit tv_sec field declaration.  Period is the
   * sum of tv_sec + tv_nsec; we use explicitly sized types to
   * avoid 32-bit vs. 64-bit time_t ambiguity...
   */
  union
  { /* ...within this anonymous union, allowing tv_sec to accommodate
     * seconds expressed in either of Microsoft's (ambiguously sized)
     * time_t representations.
     */
    __time64_t	__tv64_sec;	/* unambiguously 64 bits */
    __time32_t	__tv32_sec;	/* unambiguously 32 bits */
    time_t	  tv_sec;	/* ambiguously 32 or 64 bits */
  };
  __int32  	  tv_nsec;	/* nanoseconds */
};
# endif /* _MINGW32_SOURCE_EXTENDED */
 
# define __struct_timespec_defined  1
#endif
 
#ifdef _TIME_H
#ifdef _MINGW32_SOURCE_EXTENDED
 
_BEGIN_C_DECLS
 
__CRT_ALIAS __LIBIMPL__(( FUNCTION = mingw_timespec ))
/* This non-ANSI convenience function facilitates access to entities
 * defined as struct timespec, while exposing the broken down form of
 * the tv_sec field, as declared within struct __mingw32_timespec.  It
 * is exposed only when _MINGW32_SOURCE_EXTENDED is defined, which is
 * normally implicitly the case, except when in __STRICT_ANSI__ mode
 * unless the user defines it explicitly.
 */
struct __mingw32_expanded_timespec *mingw_timespec( struct timespec *__tv )
{ return (struct __mingw32_expanded_timespec *)(__tv); }
 
_END_C_DECLS
 
#endif	/* _MINGW32_SOURCE_EXTENDED */
 
/* <time.h> is also required to duplicate the following type definitions,
 * which are nominally defined in <stddef.h>
 */
#define __need_NULL
#define __need_wchar_t
#define __need_size_t
#include <stddef.h>
 
/* A type for measuring processor time in clock ticks; (no need to
 * guard this, since it isn't defined elsewhere).
 */
typedef long clock_t;
 
struct tm
{ /* A structure for storing the attributes of a broken-down time; (once
   * again, it isn't defined elsewhere, so no guard is necessary).  Note
   * that we are within the scope of <time.h> itself, so we must provide
   * the complete structure declaration here.
   */
  int  tm_sec;  	/* Seconds: 0-60 (to accommodate leap seconds) */
  int  tm_min;  	/* Minutes: 0-59 */
  int  tm_hour; 	/* Hours since midnight: 0-23 */
  int  tm_mday; 	/* Day of the month: 1-31 */
  int  tm_mon;  	/* Months *since* January: 0-11 */
  int  tm_year; 	/* Years since 1900 */
  int  tm_wday; 	/* Days since Sunday (0-6) */
  int  tm_yday; 	/* Days since Jan. 1: 0-365 */
  int  tm_isdst;	/* +1=Daylight Savings Time, 0=No DST, -1=unknown */
};
 
_BEGIN_C_DECLS
_CRTIMP __cdecl __MINGW_NOTHROW  clock_t  clock (void);
 
#if __MSVCRT_VERSION__ < __MSVCR80_DLL
 /* Although specified as ISO-C functions, Microsoft withdrew direct
  * support for these, with their ISO-C names, from MSVCR80.DLL onwards,
  * preferring to map them via header file macros, to alternatively named
  * DLL functions with ambiguous time_t representations; they remain in
  * MSVCRT.DLL, however, with their original ISO-C names, and time_t
  * unambiguously represented as a 32-bit data type.
  */
_CRTIMP __cdecl __MINGW_NOTHROW  time_t time (time_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  double difftime (time_t, time_t);
_CRTIMP __cdecl __MINGW_NOTHROW  time_t mktime (struct tm *);
#endif
 
/* These functions write to and return pointers to static buffers that may
 * be overwritten by other function calls. Yikes!
 *
 * NOTE: localtime, and perhaps the others of the four functions grouped
 * below may return NULL if their argument is not 'acceptable'. Also note
 * that calling asctime with a NULL pointer will produce an Invalid Page
 * Fault and crap out your program. Guess how I know. Hint: stat called on
 * a directory gives 'invalid' times in st_atime etc...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  char *asctime (const struct tm *);
 
#if __MSVCRT_VERSION__ < __MSVCR80_DLL
 /* Once again, these have been withdrawn from MSVCR80.DLL, (and later),
  * but remain in MSVCRT.DLL, with unambiguously 32-bit time_t.
  */
_CRTIMP __cdecl __MINGW_NOTHROW  char *ctime (const time_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  struct tm *gmtime (const time_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  struct tm *localtime (const time_t *);
#endif
 
_CRTIMP __cdecl __MINGW_NOTHROW
size_t strftime (char *, size_t, const char *, const struct tm *);
 
#ifndef __STRICT_ANSI__
extern _CRTIMP __cdecl __MINGW_NOTHROW  void _tzset (void);
 
#ifndef _NO_OLDNAMES
extern _CRTIMP __cdecl __MINGW_NOTHROW  void tzset (void);
#endif
 
_CRTIMP __cdecl __MINGW_NOTHROW  char *_strdate (char *);
_CRTIMP __cdecl __MINGW_NOTHROW  char *_strtime (char *);
 
#if __MSVCRT_VERSION__ >= __MSVCR61_DLL || _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* These 64-bit time_t variant functions first became available in
 * MSVCR61.DLL, and its descendants; they were subsequently included
 * in MSVCRT.DLL, from its Win2K release onwards.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  __time64_t _time64( __time64_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  __time64_t _mktime64 (struct tm *);
_CRTIMP __cdecl __MINGW_NOTHROW    char *_ctime64 (const __time64_t *);
_CRTIMP __cdecl __MINGW_NOTHROW    struct tm *_gmtime64 (const __time64_t *);
_CRTIMP __cdecl __MINGW_NOTHROW    struct tm *_localtime64 (const __time64_t *);
 
#endif	/* __MSVCR61_DLL, _WIN32_WINNT_WIN2K, and descendants. */
 
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL || _WIN32_WINNT >= _WIN32_WINNT_VISTA
 /* The following were introduced in MSVCR80.DLL, and they subsequently
  * appeared in MSVCRT.DLL, from Windows-Vista onwards.
  */
_CRTIMP __cdecl __MINGW_NOTHROW    char *_ctime32 (const __time32_t *);
_CRTIMP __cdecl __MINGW_NOTHROW    double _difftime32 (__time32_t, __time32_t);
_CRTIMP __cdecl __MINGW_NOTHROW    double _difftime64 (__time64_t, __time64_t);
_CRTIMP __cdecl __MINGW_NOTHROW    struct tm *_gmtime32 (const __time32_t *);
_CRTIMP __cdecl __MINGW_NOTHROW    struct tm *_localtime32 (const __time32_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  __time32_t _mktime32 (struct tm *);
_CRTIMP __cdecl __MINGW_NOTHROW  __time32_t _mkgmtime32 (struct tm *);
_CRTIMP __cdecl __MINGW_NOTHROW  __time64_t _mkgmtime64 (struct tm *);
_CRTIMP __cdecl __MINGW_NOTHROW  __time32_t _time32 (__time32_t *);
 
# if __MSVCRT_VERSION__ >= __MSVCR80_DLL && defined _USE_32BIT_TIME_T
  /* Users of MSVCR80.DLL and later, (but not users of MSVCRT.DLL, even
   * for _WIN32_WINNT_VISTA and later), must contend with the omission of
   * the following functions from their DLL of choice, thus requiring these
   * brain damaged mappings, in terms of an ambiguously defined 'time_t';
   * thus, when 'time_t' is declared to be equivalent to '__time32_t':
   */
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t time (time_t *__v)
 { return _time32 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  double difftime (time_t __v1, time_t __v2)
 { return _difftime32 (__v1, __v2); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t mktime (struct tm *__v)
 { return _mktime32 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t _mkgmtime (struct tm *__v)
 { return _mkgmtime32 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  char *ctime (const time_t *__v)
 { return _ctime32 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  struct tm *gmtime (const time_t *__v)
 { return _gmtime32 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  struct tm *localtime (const time_t *__v)
 { return _localtime32 (__v); }
 
# elif __MSVCRT_VERSION__ >= __MSVCR80_DLL
  /* Correspondingly, for users of MSVCR80.DLL and later only, when there
   * is no explicit declaration to direct the specification of 'time_t', and
   * thus 'time_t' is assumed to be equivalent to '__time64_t':
   */
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t time (time_t *__v)
 { return _time64 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  double difftime (time_t __v1, time_t __v2)
 { return _difftime64 (__v1, __v2); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t mktime (struct tm *__v)
 { return _mktime64 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  time_t _mkgmtime (struct tm *__v)
 { return _mkgmtime64 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  char *ctime (const time_t *__v)
 { return _ctime64 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  struct tm *gmtime (const time_t *__v)
 { return _gmtime64 (__v); }
 
__CRT_ALIAS __cdecl __MINGW_NOTHROW  struct tm *localtime (const time_t *__v)
 { return _localtime64 (__v); }
 
# endif /* _USE_32BIT_TIME_T brain damage */
#endif	/* >=__MSVCR80.DLL || >=_WIN32_WINNT_VISTA */
 
/* _daylight: non zero if daylight savings time is used.
 * _timezone: difference in seconds between GMT and local time.
 * _tzname: standard/daylight savings time zone names (an array with two
 *          elements).
 */
#ifdef __MSVCRT__
/* These are for compatibility with pre-VC 5.0 supplied MSVCRT.DLL
 */
extern _CRTIMP __cdecl __MINGW_NOTHROW  int   *__p__daylight (void);
extern _CRTIMP __cdecl __MINGW_NOTHROW  long  *__p__timezone (void);
extern _CRTIMP __cdecl __MINGW_NOTHROW  char **__p__tzname (void);
 
__MINGW_IMPORT int   _daylight;
__MINGW_IMPORT long  _timezone;
__MINGW_IMPORT char *_tzname[2];
 
#else /* !__MSVCRT__ (i.e. using CRTDLL.DLL) */
#ifndef __DECLSPEC_SUPPORTED
 
extern int   *_imp___daylight_dll;
extern long  *_imp___timezone_dll;
extern char **_imp___tzname;
 
#define _daylight  (*_imp___daylight_dll)
#define _timezone  (*_imp___timezone_dll)
#define _tzname	   (*_imp___tzname)
 
#else /* __DECLSPEC_SUPPORTED */
 
__MINGW_IMPORT int   _daylight_dll;
__MINGW_IMPORT long  _timezone_dll;
__MINGW_IMPORT char *_tzname[2];
 
#define _daylight  _daylight_dll
#define _timezone  _timezone_dll
 
#endif /* __DECLSPEC_SUPPORTED */
#endif /* ! __MSVCRT__ */
#endif /* ! __STRICT_ANSI__ */
 
#ifndef _NO_OLDNAMES
#ifdef __MSVCRT__
 
/* These go in the oldnames import library for MSVCRT.
 */
__MINGW_IMPORT int   daylight;
__MINGW_IMPORT long  timezone;
__MINGW_IMPORT char *tzname[2];
 
#else /* ! __MSVCRT__ */
/* CRTDLL is royally messed up when it comes to these macros.
 * TODO: import and alias these via oldnames import library instead
 * of macros.
 */
#define daylight  _daylight
 
/* NOTE: timezone not defined as a macro because it would conflict with
 * struct timezone in sys/time.h.  Also, tzname used to a be macro, but
 * now it's in moldname.
 */
__MINGW_IMPORT char 	*tzname[2];
 
#endif	/* ! __MSVCRT__ */
#endif	/* ! _NO_OLDNAMES */
 
#if _POSIX_C_SOURCE
/* The nanosleep() function provides the most general purpose API for
 * process/thread suspension; it provides for specification of periods
 * ranging from ~7.5 ms mean, (on WinNT derivatives; ~27.5 ms on Win9x),
 * extending up to ~136 years, (effectively eternity).
 */
__cdecl __MINGW_NOTHROW
int nanosleep( const struct timespec *, struct timespec * );
 
#ifndef __NO_INLINE__
/* We may conveniently provide an in-line implementation here,
 * in terms of the __mingw_sleep() helper function.
 */
__cdecl __MINGW_NOTHROW
int __mingw_sleep( unsigned long, unsigned long );
 
__CRT_INLINE __LIBIMPL__(( FUNCTION = nanosleep ))
int nanosleep( const struct timespec *period, struct timespec *residual )
{
  if( residual != (void *)(0) )
    residual->tv_sec = (__time64_t)(residual->tv_nsec = 0);
  return __mingw_sleep((unsigned)(period->tv_sec), (period->tv_sec < 0LL)
    ? (unsigned)(-1) : (unsigned)(period->tv_nsec));
}
#endif	/* !__NO_INLINE__ */
 
#if _POSIX_C_SOURCE >= 199309L
/* POSIX.1b-1993 introduced the optional POSIX clocks API; it
 * was subsequently moved to "base", as of POSIX.1-2008, to the
 * extent required to support the CLOCK_REALTIME feature, with
 * the remainder of its features remaining optional.  We choose
 * to provide a subset, supporting CLOCK_MONOTONIC in addition
 * to the aforementioned CLOCK_REALTIME feature.
 *
 * We define the POSIX clockid_t type as a pointer to an opaque
 * structure; user code should never need to know details of the
 * internal layout of this structure.
 */
typedef struct __clockid__ *clockid_t;
 
/* POSIX prefers to have the standard clockid_t entities defined
 * as macros, each of which represents an entity of type clockid_t.
 * Since this is not an integer data type, POSIX does not strictly
 * require such macros to expand to constant expressions; however,
 * some ill-behaved applications, (GCC's Ada implementation is one
 * such), depend on such expansions.  Thus, although it will incur
 * a small additional run-time overhead to interpret them, we map
 * such entities in terms of pseudo-pointer references, (which we
 * discriminate from real pointer references, which we assume to
 * be always to even valued addresses, by forcing odd values for
 * the pseudo-pointer references).
 */
#define __MINGW_POSIX_CLOCKAPI(ID)  ((clockid_t)(1 + ((ID) << 1)))
 
/* The standard clockid_t entities which we choose to support.
 */
#define CLOCK_REALTIME  __MINGW_POSIX_CLOCKAPI (0)
#define CLOCK_MONOTONIC __MINGW_POSIX_CLOCKAPI (1)
 
/* Prototypes for the standard POSIX functions which provide the
 * API to these standard clockid_t entities.
 */
int clock_getres (clockid_t, struct timespec *);
int clock_gettime (clockid_t, struct timespec *);
int clock_settime (clockid_t, const struct timespec *);
 
#endif	/* _POSIX_C_SOURCE >= 199309L */
#endif	/* _POSIX_C_SOURCE */
 
_END_C_DECLS
 
#endif	/* _TIME_H included in its own right */
 
#if __need_wchar_decls && ! (defined _TIME_H && defined _WCHAR_H)
/* Wide character time function prototypes.  These are nominally declared
 * both here, in <time.h>, and also in <wchar.h>; we declare them here, and
 * make them available for selective inclusion by <wchar.h>, but such that
 * the declarations, and in particular any in-line implementation of the
 * _wctime() function, are visible only on the first time parse, when
 * one of either _TIME_H, or _WCHAR_H, but not both, is defined.
 */
_BEGIN_C_DECLS
 
#if defined __MSVCRT__ && ! defined __STRICT_ANSI__
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wasctime (const struct tm *);
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wstrdate (wchar_t *);
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wstrtime (wchar_t *);
 
#if __MSVCRT_VERSION__ >= __MSVCR61_DLL || _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* A __time64_t specific variant of _wctime(), identified as _wctime64(),
 * first appeared in the non-free MSVC specific MSVCR61.DLL, and was added
 * to the freely available platform MSVCRT.DLL from Win2K onwards...
 */
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wctime64 (const __time64_t *);
#endif
#if __MSVCRT_VERSION__ >= __MSVCR80_DLL || _WIN32_WINNT >= _WIN32_WINNT_VISTA
/* ...whereas its __time32_t specific counterpart, _wctime32(), did not
 * make an appearance until MSVCR80.DLL, and was not added to MSVCRT.DLL
 * until the release of Vista.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wctime32 (const __time32_t *);
#endif
#if __MSVCRT_VERSION__ < __MSVCR80_DLL
/* Present in all versions of MSVCRT.DLL, but withdrawn from non-free
 * MSVC specific releases from MSVCR80.DLL onwards; in all versions of
 * MSVCRT.DLL, _wctime() accepts a 32-bit time_t argument pointer.
 */
_CRTIMP __cdecl __MINGW_NOTHROW  wchar_t *_wctime (const time_t *);
 
#else /* __MSVCRT_VERSION__ >= __MSVCR80_DLL */
/* For users of the non-free MSVC libraries, we must deal with both the
 * absence of _wctime(), and with Microsoft's attendant _USE_32BIT_TIME_T
 * brain damage, as we map an inline replacement...
 */
__CRT_ALIAS __cdecl __MINGW_NOTHROW  wchar_t *_wctime (const time_t *__v)
{
  /* ...in terms of an appropriately selected time_t size specific
   * alternative function, which should be available...
   */
# ifdef _USE_32BIT_TIME_T
  /* ...i.e. the __time32_t specific _wctime32(), when the user has
   * enabled this choice; (the only sane choice, if compatibility with
   * MSVCRT.DLL is desired)...
   */
  return _wctime32 (__v);
 
# else	/* !_USE_32BIT_TIME_T */
  /* ...or otherwise, the __time64_t specific _wctime64(), (in which
   * case, compatibility with MSVCRT.DLL must be sacrificed).
   */
  return _wctime64 (__v);
# endif	/* !_USE_32BIT_TIME_T */
}
#endif	/* __MSVCRT_VERSION__ >= __MSVCR80_DLL */
#endif	/* __MSVCRT__ && !__STRICT_ANSI__ */
 
_CRTIMP __cdecl __MINGW_NOTHROW
size_t wcsftime (wchar_t *, size_t, const wchar_t *, const struct tm *);
 
_END_C_DECLS
 
#endif	/* ! (defined _TIME_H && defined _WCHAR_H) */
 
/* We're done with all <time.h> specific content selectors; clear them.
 */
#undef __need_time_t
#undef __need_struct_timespec
#undef __need_wchar_decls
 
#endif /* ! RC_INVOKED */
#endif /* !_TIME_H after __need_time_t processing */
#endif /* !_TIME_H: $RCSfile: time.h,v $: end of file */