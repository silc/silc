/*

  stacktrace.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef MEMTRACE_H
#define MEMTRACE_H

#ifndef SILCMEMORY_H
#error "Do not include internal header file directly"
#endif

#if defined(__GNUC__)

#undef strdup
#define silc_malloc(s)      silc_st_malloc((s), __FILE__, __LINE__)
#define silc_calloc(i, s)   silc_st_calloc((i), (s), __FILE__, __LINE__)
#define silc_realloc(p, s)  silc_st_realloc((p), (s), __FILE__, __LINE__)
#define silc_free(p)        silc_st_free((p), __FILE__, __LINE__)
#define silc_memdup(p, s)   silc_st_memdup((p), (s), __FILE__, __LINE__)
#define silc_strdup(s)      silc_st_strdup((s), __FILE__, __LINE__)
#define strdup(s)           silc_st_strdup((s), __FILE__, __LINE__)

void *silc_st_malloc(size_t size, const char *file, int line);
void *silc_st_calloc(size_t items, size_t size, const char *file, int line);
void *silc_st_realloc(void *ptr, size_t size, const char *file, int line);
void silc_st_free(void *ptr, const char *file, int line);
void *silc_st_memdup(const void *ptr, size_t size, const char *file, int line);
void *silc_st_strdup(const char *string, const char *file, int line);
void silc_st_dump(void);

#else
#error "memory allocation stack trace not supported on this platform"
#endif /* __GNUC__ */

#endif /* MEMTRACE_H */
