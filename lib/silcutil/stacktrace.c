/*

  stacktrace.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* This file implements memory leak checker and basic memory corruption
   and double free checker.  It is multi-thread safe.  It does the
   following:

   o Tracks all memory allocations and report any unfreed memory at the
     end of the program with backtrace where the memory was allocated.

   o Checks if a memory location has been freed already and abort the
     program with the backtrace of the location of the double free.

   o Checks if a given pointer has been allocated at all and abort the
     program with the backtrace where the invalid free was given.

   o Checks at the time of free if the memory was written out of bounds
     (overflow) and abort with the backtrace of the free.  The backtrace
     might not help to find the overflow but at least it is detected.
     By setting SILC_MALLOC_DUMP the memory is dummped to help and see
     what it contains.

   o Can detect if the memory is read or written out of bounds (overflow)
     and abort immediately the with the backtrace when the illegal access
     occurs.  This can be enabled by using SILC_MALLOC_PROTECT.

   The following environment variables can be used:

   SILC_MALLOC_NO_FREE

     When set to value 1, the program doesn't actually free any memory.
     This provides more detailed information especially in case of double
     free.  If the location of the double free cannot be located, by
     setting this variable the program will show where the memory was
     originally allocated and freed.

   SILC_MALLOC_DUMP

     When set to value 1, in case of fatal error, dumps the memory location,
     if possible.  This can help see what the memory contains.

   SILC_MALLOC_PROTECT

     When set to value 1 each allocation will have an inaccesible memory
     page following the allocated memory area.  This will detect if the
     the memory is accessed (read or write) beyond its boundaries.  This
     will help to identify the place where illegal memory access occurs.

   To work correctly this of course expects that code uses SILC memory
   allocation and access routines.

*/

#include "silc.h"

#ifdef SILC_STACKTRACE
#include <execinfo.h>
#include <signal.h>
#include <malloc.h>
#include <sys/mman.h>

static void *st_blocks = NULL;
static unsigned long st_blocks_count = 0;
static unsigned long st_num_malloc = 0;
static SilcBool dump = FALSE;
static SilcBool no_free = FALSE;
static SilcBool dump_mem = FALSE;
static SilcUInt32 pg = 0;
static SilcMutex lock = NULL;

#ifdef SILC_DEBUG
#define SILC_ST_DEPTH 15
#else
#define SILC_ST_DEPTH 8
#endif /* SILC_DEBUG */

/* Memory block with stack trace */
typedef struct SilcStBlockStruct {
  struct SilcStBlockStruct *next;
  struct SilcStBlockStruct *prev;
  void *stack[SILC_ST_DEPTH];	/* Stack trace */
  const char *file;		/* Allocation file in program */
  const char *free_file;	/* Free file in program */
  SilcUInt32 size;		/* Allocated memory size */
  SilcUInt16 line;		/* Allocation line in program */
  SilcUInt16 free_line;		/* Free line in program */
  SilcUInt16 depth;		/* Depth of stack trace */
  SilcUInt16 dumpped;		/* Block is dumpped */
  SilcUInt32 bound;		/* Top bound */
} *SilcStBlock;

#define SILC_ST_TOP_BOUND 0xfeed1977
#define SILC_ST_BOTTOM_BOUND 0x9152beef
#define SILC_ST_GET_SIZE(size) ((size + sizeof(struct SilcStBlockStruct) + 4))
#define SILC_ST_GET_STACK(p) ((SilcStBlock)(((unsigned char *)p) -	\
			    sizeof(struct SilcStBlockStruct)))
#define SILC_ST_GET_PTR(p) (((unsigned char *)p) +		\
			    sizeof(struct SilcStBlockStruct))
#define SILC_ST_GET_BOUND(p, size) (SilcUInt32 *)(((unsigned char *)p) + \
				    SILC_ST_GET_SIZE(size) - 4)

#define SILC_ST_ALIGN(bytes, align) (((bytes) + (align - 1)) & ~(align - 1))
#define SILC_ST_GET_SIZE_ALIGN(size, align) \
  SILC_ST_ALIGN(SILC_ST_GET_SIZE(size) - 4, align)
#define SILC_ST_GET_PTR_ALIGN(stack, align)				  \
  (((unsigned char *)stack) - (SILC_ST_GET_SIZE_ALIGN(stack->size, pg) -  \
			       SILC_ST_GET_SIZE(stack->size)) - 4)
#define SILC_ST_GET_STACK_ALIGN(p, size, align)				    \
  ((SilcStBlock)(((unsigned char *)p) + (SILC_ST_GET_SIZE_ALIGN(size, pg) - \
					 SILC_ST_GET_SIZE(size)) + 4))

#define silc_hexdump(ptr, size, file) \
  silc_log_output_hexdump("", "", 0, ptr, size, "")

void silc_st_abort(SilcStBlock stack, const char *file, int line,
		   char *fmt, ...)
{
  void *bt[SILC_ST_DEPTH];
  SilcUInt32 *bound;
  va_list va;
  int btc;

  va_start(va, fmt);
  vfprintf(stderr, fmt, va);
  va_end(va);

  fprintf(stderr, "----- BACKTRACE -----\n%s:%d:\n", file, line);
  btc = backtrace(bt, SILC_ST_DEPTH);
  backtrace_symbols_fd(bt, btc, 2);

  if (stack) {
    fprintf(stderr, "----- MEMORY TRACE -----\n");
    if (stack->free_file)
      fprintf(stderr, "Freed at: %s:%d\n", stack->free_file,
	      stack->free_line);
    fprintf(stderr, "Originally allocated at:\n");
    fprintf(stderr, "%s:%d:\n", stack->file, stack->line);
    backtrace_symbols_fd(stack->stack, stack->depth, 2);
    fflush(stderr);

    if (dump_mem) {
      fprintf(stderr, "----- MEMORY HEADER -----\n");
      fprintf(stderr, "Header length: %lu, total length %lu\n",
	      sizeof(struct SilcStBlockStruct), SILC_ST_GET_SIZE(stack->size));
      silc_hexdump((void *)stack, sizeof(struct SilcStBlockStruct), stderr);
      fflush(stderr);
      fprintf(stderr, "Header bound is: %p\n",
	      SILC_32_TO_PTR(stack->bound));
      if (stack->bound != SILC_ST_TOP_BOUND) {
	fprintf(stderr, "Header bound should be: %p\n",
		SILC_32_TO_PTR(SILC_ST_TOP_BOUND));
        fprintf(stderr, "MEMORY IS CORRUPTED (UNDERFLOW)!\n");
      }

      fprintf(stderr, "----- USER MEMORY -----\n");
      fprintf(stderr, "Length: %d\n", stack->size);
      silc_hexdump(((unsigned char *)stack) +
		    sizeof(struct SilcStBlockStruct), stack->size, stderr);
      fflush(stderr);

      fprintf(stderr, "----- MEMORY FOOTER -----\n");
      bound = SILC_ST_GET_BOUND(stack, stack->size);
      silc_hexdump((unsigned char *)bound, 4, stderr);
      fprintf(stderr, "Footer bound is: %p\n", SILC_32_TO_PTR(*bound));
      if (*bound != SILC_ST_BOTTOM_BOUND) {
	fprintf(stderr, "Footer bound should be: %p\n",
		SILC_32_TO_PTR(SILC_ST_BOTTOM_BOUND));
        fprintf(stderr, "MEMORY IS CORRUPTED (OVERFLOW)!\n");
      }
    }
  }

  fflush(stderr);

  abort();
}

void silc_st_sigsegv(int sig, siginfo_t *si, void *context)
{
  SilcStBlock orig, stack = (SilcStBlock)si->si_addr;

  /* Make the page accessible again */
  mprotect(si->si_addr, pg, PROT_READ | PROT_WRITE);

  /* Get the original page from the violated page */
  orig = (SilcStBlock)(((unsigned char *)si->si_addr) -
			SILC_ST_GET_SIZE_ALIGN(stack->size, pg));
  stack = SILC_ST_GET_STACK_ALIGN(orig, stack->size, pg);

  silc_st_abort(stack, __FILE__, __LINE__,
		"SILC_MALLOC: access violation (overflow)\n");
}

void silc_st_stacktrace_init(void)
{
  const char *var;

  atexit(silc_st_dump);
  dump = TRUE;

  var = getenv("SILC_MALLOC_NO_FREE");
  if (var && *var == '1')
    no_free = TRUE;

  var = getenv("SILC_MALLOC_DUMP");
  if (var && *var == '1')
    dump_mem = TRUE;

  var = getenv("SILC_MALLOC_PROTECT");
  if (var && *var == '1') {
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = silc_st_sigsegv;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

#if defined(_SC_PAGESIZE)
    pg = sysconf(_SC_PAGESIZE);
#elif defined(_SC_PAGE_SIZE)
    pg = sysconf(_SC_PAGE_SIZE);
#else
    pg = getpagesize();
#endif /* _SC_PAGESIZE */
  }

  /* Linux libc malloc check */
  setenv("MALLOC_CHECK_", "3", 1);

  /* NetBSD malloc check */
  setenv("MALLOC_OPTIONS", "AJ", 1);

  silc_mutex_alloc(&lock);
}

void *silc_st_malloc(size_t size, const char *file, int line)
{
  SilcStBlock stack;

  if (silc_unlikely(!dump))
    silc_st_stacktrace_init();

  if (pg) {
    unsigned char *ptr;

    if (posix_memalign((void *)&ptr, pg,
		       SILC_ST_GET_SIZE_ALIGN(size, pg) + pg))
      return NULL;

    /* The inaccessible page too will include the allocation information
       so that we can get it when access violation occurs in that page. */
    stack = (SilcStBlock)(ptr + SILC_ST_GET_SIZE_ALIGN(size, pg));
    stack->size = size;

    /* Protect the page */
    if (mprotect(stack, pg, PROT_NONE))
      silc_st_abort(NULL, file, line, "SILC_MALLOC: mprotect() error: %s\n",
		    errno == ENOMEM ? "Cannot allocate memory. \nYour program "
		    "leaks memory, allocates too much or system \n"
		    "is out of memory.  The SILC_MALLOC_PROTECT cannot "
		    "be used." : strerror(errno));

    /* Get the accessible page */
    stack = SILC_ST_GET_STACK_ALIGN(ptr, size, pg);
  } else {
    stack = (SilcStBlock)malloc(SILC_ST_GET_SIZE(size));
    if (!stack)
      return NULL;
  }

  stack->dumpped = 0;
  stack->file = file;
  stack->free_file = NULL;
  stack->line = line;
  stack->size = size;
  stack->bound = SILC_ST_TOP_BOUND;
  stack->depth = backtrace(stack->stack, SILC_ST_DEPTH);

  silc_mutex_lock(lock);

  stack->next = st_blocks;
  stack->prev = NULL;
  if (st_blocks)
    ((SilcStBlock)st_blocks)->prev = stack;
  st_blocks = stack;
  st_blocks_count++;
  st_num_malloc++;

  silc_mutex_unlock(lock);

  if (!pg)
    *SILC_ST_GET_BOUND(stack, size) = SILC_ST_BOTTOM_BOUND;

  return SILC_ST_GET_PTR(stack);
}

void *silc_st_calloc(size_t items, size_t size, const char *file, int line)
{
  void *addr = (void *)silc_st_malloc(items * size, file, line);
  if (addr)
    memset(addr, 0, items * size);
  return addr;
}

void *silc_st_realloc(void *ptr, size_t size, const char *file, int line)
{
  SilcStBlock stack;

  if (!ptr)
    return silc_st_malloc(size, file, line);

  stack = SILC_ST_GET_STACK(ptr);
  if (!pg && stack->size >= size) {
    /* Must update footer when the size changes */
    if (stack->size != size)
      *SILC_ST_GET_BOUND(stack, size) = SILC_ST_BOTTOM_BOUND;

    stack->size = size;
    return ptr;
  } else {
    void *addr = (void *)silc_st_malloc(size, file, line);
    if (addr) {
      memcpy(addr, ptr, size > stack->size ? stack->size : size);
      silc_st_free(ptr, file, line);
    }
    return addr;
  }
}

void silc_st_free(void *ptr, const char *file, int line)
{
  SilcStBlock stack, s;

  if (!ptr)
    return;

  /* Check for double free */
  if (!memcmp((unsigned char *)ptr - sizeof(struct SilcStBlockStruct),
	      "\x47\x47\x47\x47", 4))
    silc_st_abort(no_free ? ptr - sizeof(struct SilcStBlockStruct) : NULL,
		  file, line, "SILC_MALLOC: double free: %p already freed\n",
		  ptr - sizeof(struct SilcStBlockStruct));

  stack = SILC_ST_GET_STACK(ptr);

  silc_mutex_lock(lock);

  /* Check if we have ever made this allocation */
  for (s = st_blocks; s; s = s->next)
    if (s == stack)
      break;
  if (s == NULL)
    silc_st_abort(NULL, file, line,
		  "SILC_MALLOC: %p was never allocated\n", stack);

  if (!pg) {
    /* Check for underflow */
    if (stack->bound != SILC_ST_TOP_BOUND)
      silc_st_abort(stack, file, line,
		    "SILC_MALLOC: %p was written out of bounds (underflow)\n",
		    stack);

    /* Check for overflow */
    if (*SILC_ST_GET_BOUND(stack, stack->size) != SILC_ST_BOTTOM_BOUND)
      silc_st_abort(stack, file, line,
		    "SILC_MALLOC: %p was written out of bounds (overflow)\n",
		    stack);
  }

  if (stack->next)
    stack->next->prev = stack->prev;
  if (stack->prev)
    stack->prev->next = stack->next;
  else
    st_blocks = stack->next;

  st_blocks_count--;

  silc_mutex_unlock(lock);

  stack->free_file = file;
  stack->free_line = line;

  if (no_free) {
    memset(stack, 0x47, 8);
    return;
  }

  if (pg) {
    ptr = SILC_ST_GET_PTR_ALIGN(stack, pg);
    mprotect(ptr + SILC_ST_GET_SIZE_ALIGN(stack->size, pg), pg,
	     PROT_READ | PROT_WRITE);
    memset(ptr, 0x47, SILC_ST_GET_SIZE_ALIGN(stack->size, pg));
    free(ptr);
  } else {
    memset(stack, 0x47, SILC_ST_GET_SIZE(stack->size));
    free(stack);
  }
}

void *silc_st_memdup(const void *ptr, size_t size, const char *file, int line)
{
  unsigned char *addr = (unsigned char *)silc_st_malloc(size + 1, file, line);
  if (addr) {
    memcpy((void *)addr, ptr, size);
    addr[size] = '\0';
  }
  return (void *)addr;
}

void *silc_st_strdup(const char *string, const char *file, int line)
{
  return silc_st_memdup(string, strlen(string), file, line);
}

/* Dumps the stack into file if there are leaks. */

void silc_st_dump(void)
{
  SilcStBlock stack, s;
  unsigned long leaks = 0, blocks, bytes;
  FILE *fp = NULL;
  char **syms, *cp;
  int i;
  SilcMutex l;

  l = lock;
  lock = NULL;
  silc_mutex_free(l);

  for (stack = st_blocks; stack; stack = stack->next) {
    bytes = blocks = 0;

    if (stack->dumpped)
      continue;

    leaks++;

    if (!fp) {
      fp = fopen("stacktrace.log", "wb");
      if (!fp)
	fp = stderr;
    }

    /* Get symbol names */
    syms = backtrace_symbols(stack->stack, stack->depth);

    /* Find number of leaks and bytes leaked for this leak */
    for (s = stack; s; s = s->next) {
      if (s->file == stack->file && s->line == stack->line &&
	  s->depth == stack->depth &&
	  !memcmp(s->stack, stack->stack,
		  (s->depth * sizeof(stack->stack[0])))) {
	blocks++;
	bytes += s->size;
	s->dumpped = 1;
      }
    }

    if (blocks) {
      fprintf(fp, "<leak>%s:%d: #blocks=%lu, bytes=%lu\n",
	      stack->file, stack->line, blocks, bytes);
      for (i = 0; i < stack->depth; i++) {
	if (syms) {
	  cp = syms[i];
	  if (strchr(cp, '('))
	    cp = strchr(cp, '(') + 1;
	  else if (strchr(cp, ' '))
	    cp = strchr(cp, ' ') + 1;
	  if (strchr(cp, ')'))
	    *strchr(cp, ')') = ' ';
	  fprintf(fp, "\t%s\n", cp);
	} else {
	  fprintf(fp, "\tpc=%p\n", stack->stack[i]);
	}
      }
      fprintf(fp, "\n");
      free(syms);
    }
  }

  if (!leaks) {
    fprintf(stderr, "\nNo memory leaks\n");
  } else {
    fprintf(stderr,
	    "-----------------------------------------\n"
	    "-----------------------------------------\n"
	    " Memory leaks dumped to 'stacktrace.log'\n"
	    " Leaks: %lu leaks, %lu blocks\n"
	    "-----------------------------------------\n"
	    "-----------------------------------------\n",
	    leaks, st_blocks_count);
    fprintf(stderr, "Number of allocations: %lu\n", st_num_malloc);
  }

  if (fp && fp != stderr)
    fclose(fp);
}

#endif /* SILC_STACKTRACE */
