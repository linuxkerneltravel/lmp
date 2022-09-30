#ifndef XARRAY_H
#define XARRAY_H

#include "lib.h"

extern struct xarray  *xa;

extern int alloc_xarray(void);
extern void destroy_xarray(void);
#endif