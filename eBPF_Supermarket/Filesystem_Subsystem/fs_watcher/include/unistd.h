/* unistd.h - unix standard library header file */

/* Copyright 1984-1994 Wind River Systems, Inc. */

/*
modification history
--------------------
02h,20jul00,jgn  add POSIX version information + removed old style prototypes
02g,24sep01,jkf  added const to rmdir()
02f,19aug94,ism  added getcwd() prototypes (SPR #3536)
02e,12nov93,dvs  added prototype for ftruncate.
02d,08feb93,smb  changed int to size_t in protype for read() and write()
02c,22sep92,rrr  added support for c++
02b,18sep92,smb  added the rmdir prototype.
02a,04jul92,jcf  cleaned up.
01c,26may92,rrr  the tree shuffle
01b,05dec91,rrr  added SEEK_ macros (was in ioLib.h)
01a,19nov91,rrr  written.
*/

#ifndef __INCunistdh
#define __INCunistdh

#ifdef __cplusplus
extern "C" {
#endif

#include "vxWorks.h"

#ifndef SEEK_SET
#define SEEK_SET           0       /* absolute offset, was L_SET */
#define SEEK_CUR           1       /* relative to current offset, was L_INCR */
#define SEEK_END           2       /* relative to end of file, was L_XTND */
#endif

/* POSIX defines */

#ifndef _POSIX_VERSION
#define _POSIX_VERSION 199506L
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE	199506L
#endif

/* function declarations */

#if defined(__STDC__) || defined(__cplusplus)

extern STATUS 		unlink (char *name);
extern STATUS 		close (int fd);
extern int 		read (int fd, char *buffer, size_t maxbytes);
extern int 		write (int fd, char *buffer, size_t nbytes);
extern int 		lseek (int fd, long offset, int whence);
extern STATUS 		chdir (char *pathname);
extern STATUS 		pause (void);
extern BOOL 		isatty (int fd);
extern STATUS 		rmdir (const char *dirName);
extern char *		getcwd (char *buffer, int size);
extern int    		ftruncate (int fildes, off_t length);
extern unsigned int	sleep (unsigned int);
extern unsigned int	alarm (unsigned int);

#else	/* __STDC__ */

extern STATUS 	unlink ();
extern STATUS 	close ();
extern int 	read ();
extern int 	write ();
extern int 	lseek ();
extern STATUS 	chdir ();
extern STATUS 	pause ();
extern BOOL 	isatty ();
extern STATUS 	rmdir ();
extern char	*getcwd();
extern int    	ftruncate ();

#endif	/* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* __INCunistdh */

