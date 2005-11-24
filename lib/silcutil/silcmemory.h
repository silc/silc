/*

  silcmemory.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2005 Pekka Riikonen

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
#ifndef SILC_DIST_TOOLKIT
#error "The stack trace is not supported in this distribution"
#endif

#include "stacktrace.h"
#endif /* SILC_STACKTRACE */


/* Following functions that use SilcStack as memory source. */

/****f* silcutil/SilcMemoryAPI/silc_smalloc
 *
 * SYNOPSIS
 *
 *    void *silc_smalloc(SilcStack stack, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Allocate memory block of size of `size' from the stack indicated by
 *    `stack' and return pointer to it.  Returns NULL on error.  This
 *    function allocates aligned memory so it can be used to allocate
 *    memory for structures, for example.  If you allocate strings or
 *    data buffers using silc_smalloc_ua is recommended instead of this
 *    function.
 *
 * NOTES
 *
 *    Be careful with this function:  do not free the returned pointer
 *    explicitly and do not save the returned pointer to a permanent
 *    location.
 *
 *    If `stack' is NULL this function calls silc_malloc.
 *
 ***/
void *silc_smalloc(SilcStack stack, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_smalloc_ua
 *
 * SYNOPSIS
 *
 *    void *silc_smalloc_ua(SilcStack stack, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Allocate unaligned memory block of size of `size' from the stack
 *    indicated by `stack' and return pointer to it.  Returns NULL on error.
 *
 * NOTES
 *
 *    This function must not be used to allocate memory for structures.
 *    Use this function only for strings and data buffers.
 *
 *    Be careful with this function:  do not free the returned pointer
 *    explicitly and do not save the returned pointer to a permanent
 *    location.
 *
 *    If `stack' is NULL this function calls silc_malloc.
 *
 ***/
void *silc_smalloc_ua(SilcStack stack, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_scalloc
 *
 * SYNOPSIS
 *
 *    void *silc_scalloc(SilcStack stack, SilcUInt32 items, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Allocate memory block of size of `size' from the stack indicated by
 *    `stack', zero the memory area and return pointer to it.  This
 *    function allocates aligned memory.  Returns NULL on error.
 *
 * NOTES
 *
 *    Be careful with this function:  do not free the returned pointer
 *    explicitly and do not save the returned pointer to a permanent
 *    location.
 *
 *    If `stack' is NULL this function calls silc_calloc.
 *
 ***/
void *silc_scalloc(SilcStack stack, SilcUInt32 items, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_srealloc
 *
 * SYNOPSIS
 *
 *    void *silc_srealloc(SilcStack stack, SilcUInt32 old_size,
 *                        void *ptr, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Change the size of the memory block indicated by `ptr' to the new
 *    size of `size' bytes.  The contents of `ptr' will not be changed.
 *    If `ptr' is NULL the call is equivalent to silc_smalloc.  If `size'
 *    is zero (0) error will occur.  Returns NULL on error and the old
 *    pointer remain intact.
 *
 * NOTES
 *
 *    This function reallocates successfully only if the previous allocation
 *    to `stack' was `ptr'.  If there was another memory allocation between
 *    allocating `ptr' and this call, this routine will return NULL.  The
 *    NULL is also returned if the `size' does not fit to current stack
 *    and allocating new block would require slow copying of the data.  It
 *    is left to the caller to decide whether to allocate new pointer and
 *    copy the old data in case this function returns NULL.
 *
 *    This function can be used to reallocate only aligned memory allocated
 *    with silc_smalloc.
 *
 *    If `stack' is NULL this function calls silc_realloc.
 *
 ***/
void *silc_srealloc(SilcStack stack, SilcUInt32 old_size,
		    void *ptr, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_srealloc_ua
 *
 * SYNOPSIS
 *
 *    void *silc_srealloc_ua(SilcStack stack, SilcUInt32 old_size,
 *                           void *ptr, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Same as silc_srealloc but reallocates unaligned memory.
 *
 * NOTES
 *
 *    This function can be used to reallocate only unaligned memory
 *    allocated with silc_smalloc_ua.
 *
 *    If `stack' is NULL this function calls silc_realloc.
 *
 ***/
void *silc_srealloc_ua(SilcStack stack, SilcUInt32 old_size,
		       void *ptr, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_smemdup
 *
 * SYNOPSIS
 *
 *    void *silc_smemdup(SilcStack stack, const void *ptr, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Duplicates the memory area indicated by `ptr' which is the size of
 *    `size' bytes.  Returns pointer to the duplicated memory area.  This
 *    NULL terminates the dupped memory area by allocating `size' + 1
 *    bytes, so this function can be used to duplicate strings that does not
 *    have NULL termination.  This function allocates aligned memory so
 *    it can be used to duplicate also structures.  Returns NULL on error.
 *
 * NOTES
 *
 *    Be careful with this function:  do not free the returned pointer
 *    explicitly and do not save the returned pointer to a permanent
 *    location.
 *
 *    If `stack' is NULL this function calls silc_memdup.
 *
 ***/
void *silc_smemdup(SilcStack stack, const void *ptr, SilcUInt32 size);

/****f* silcutil/SilcMemoryAPI/silc_sstrdup
 *
 * SYNOPSIS
 *
 *    char *silc_sstrdup(SilcStack stack, const char *str);
 *
 * DESCRIPTION
 *
 *    Duplicates the string indicated by `str' and returns the duplicated
 *    string.  This function allocates unaligned memory.  Returns NULL
 *    on error.
 *
 * NOTES
 *
 *    Be careful with this function:  do not free the returned pointer
 *    explicitly and do not save the returned pointer to a permanent
 *    location.
 *
 *    If `stack' is NULL this function calls silc_strdup.
 *
 ***/
char *silc_sstrdup(SilcStack stack, const char *str);

#endif /* SILCMEMORY_H */
