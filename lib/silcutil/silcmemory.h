/*

  silcmemory.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Memory Interface
 *
 * DESCRIPTION
 *
 * Basic utility functions for allocating memory. All SILC routines, and
 * applications use these functions when they need to allocate, manipulate
 * and free memory.
 *
 * Currently all allocation routines assert() that the memory was allocated
 * successfully. Hence, if memory allocation fails it is fatal error.
 *
 ***/

#ifndef SILCMEMORY_H
#define SILCMEMORY_H

/* Prototypes */

#ifndef SILC_STACKTRACE

/****f* silcutil/SilcMemoryAPI/silc_malloc
 *
 * SYNOPSIS
 *
 *    void *silc_malloc(size_t size);
 *
 * DESCRIPTION
 *
 *    Allocates memory of `size' bytes and returns pointer to the allocated
 *    memory area.  Free the memory by calling silc_free.
 *
 ***/
void *silc_malloc(size_t size);

/****f* silcutil/SilcMemoryAPI/silc_calloc
 *
 * SYNOPSIS
 *
 *    void *silc_calloc(size_t items, size_t size);
 *
 * DESCRIPTION
 *
 *    Allocates memory of for an array of `items' elements of `size' bytes
 *    and returns pointer to the allocated memory area.  The memory area is
 *    also zeroed.  Free the memory by calling silc_free.
 *
 ***/
void *silc_calloc(size_t items, size_t size);

/****f* silcutil/SilcMemoryAPI/silc_realloc
 *
 * SYNOPSIS
 *
 *    void *silc_realloc(void *ptr, size_t size);
 *
 * DESCRIPTION
 *
 *    Change the size of the memory block indicated by `ptr' to the new
 *    size of `size' bytes.  The contents of `ptr' will not be changed.
 *    If `ptr' is NULL the call is equivalent to silc_malloc.  If the
 *    `size' is zero (0) the call is equivalent to silc_free.  Free the
 *    memory by calling silc_free.
 *
 * NOTES
 *
 *    The pointer returned to the reallocated memory area might not be
 *    same as `ptr'.
 *
 ***/
void *silc_realloc(void *ptr, size_t size);

/****f* silcutil/SilcMemoryAPI/silc_free
 *
 * SYNOPSIS
 *
 *    void silc_free(void *ptr);
 *
 * DESCRIPTION
 *
 *    Frees the memory area indicated by the `ptr'. If `ptr' is NULL no
 *    operation is performed.
 *
 ***/
void silc_free(void *ptr);

/****f* silcutil/SilcMemoryAPI/silc_memdup
 *
 * SYNOPSIS
 *
 *    void *silc_memdup(const void *ptr, size_t size);
 *
 * DESCRIPTION
 *
 *    Duplicates the memory area indicated by `ptr' which is of size
 *    of `size' bytes. Returns pointer to the duplicated memory area.
 *    This NULL terminates the dupped memory area by allocating `size' + 1
 *    bytes, so this function can be used to duplicate strings that does
 *    not have NULL termination.
 *
 ***/
void *silc_memdup(const void *ptr, size_t size);

#else
#include "stacktrace.h"
#endif /* SILC_STACKTRACE */

#endif /* SILCMEMORY_H */
