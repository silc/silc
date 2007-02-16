/*

  stacktrace.c 

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

#include "silc.h"

#ifdef SILC_STACKTRACE

static void *st_blocks = NULL;
static unsigned long st_blocks_count = 0;
static SilcBool dump = FALSE;
static SilcBool malloc_check = FALSE;

#define SILC_ST_DEPTH 10

/* Memory block with stack trace */
typedef struct SilcStBlockStruct {
  unsigned int dumpped  : 1;	/* Block is dumpped */
  unsigned int depth    : 8;	/* Depth of stack trace */
  unsigned int line     : 23;	/* Allocation line in program */
  void *stack[SILC_ST_DEPTH];	/* Stack trace */
  const char *file;		/* Allocation file in program */
  unsigned long size;		/* Allocated memory size */
  struct SilcStBlockStruct *next;
  struct SilcStBlockStruct *prev;
} *SilcStBlock;

/* Get current frame pointer */
#define SILC_ST_GET_FP(ret_fp)			\
do {						\
  register void *cfp;				\
  asm volatile ("movl %%ebp, %0" : "=r" (cfp));	\
  (ret_fp) = cfp;				\
} while(0);

#define SILC_ST_GET_SIZE(size) ((size + sizeof(struct SilcStBlockStruct)))
#define SILC_ST_GET_STACK(p) ((SilcStBlock)(((unsigned char *)p) -	\
			    sizeof(struct SilcStBlockStruct)))
#define SILC_ST_GET_PTR(p) (((unsigned char *)p) +		\
			    sizeof(struct SilcStBlockStruct))

void silc_st_stacktrace(SilcStBlock stack)
{
  void *fp;

  if (!dump) {
    atexit(silc_st_dump);
    dump = TRUE;
  }

  if (!malloc_check) {
    /* Linux libc malloc check */
    setenv("MALLOC_CHECK_", "2", 1);

    /* NetBSD malloc check */
    setenv("MALLOC_OPTIONS", "AJ", 1);

    malloc_check = TRUE;
  }

  /* Save the stack */
  SILC_ST_GET_FP(fp);
  for (stack->depth = 0; fp; stack->depth++) {
    if (stack->depth == SILC_ST_DEPTH)
      break;

    /* Get program pointer and frame pointer from this frame */
    stack->stack[stack->depth] = *((void **)(((unsigned char *)fp) + 4));
    fp = *((void **)fp);
  }
}

void *silc_st_malloc(size_t size, const char *file, int line)
{
  SilcStBlock stack = (SilcStBlock)malloc(SILC_ST_GET_SIZE(size));
  assert(stack != NULL);

  stack->dumpped = 0;
  stack->file = file;
  stack->line = line;
  stack->size = size;
  silc_st_stacktrace(stack);

  stack->next = st_blocks;
  stack->prev = NULL;
  if (st_blocks)
    ((SilcStBlock)st_blocks)->prev = stack;
  st_blocks = stack;
  st_blocks_count++;

  return SILC_ST_GET_PTR(stack);
}

void *silc_st_calloc(size_t items, size_t size, const char *file, int line)
{
  void *addr = (void *)silc_st_malloc(items * size, file, line);
  memset(addr, 0, items * size);
  return addr;
}

void *silc_st_realloc(void *ptr, size_t size, const char *file, int line)
{
  SilcStBlock stack;

  if (!ptr)
    return silc_st_malloc(size, file, line);

  stack = SILC_ST_GET_STACK(ptr);
  if (stack->size >= size) {
    stack->size = size;
    return ptr;
  } else {
    void *addr = (void *)silc_st_malloc(size, file, line);
    memcpy(addr, ptr, stack->size);
    silc_st_free(ptr, file, line);
    return addr;
  }
}

void silc_st_free(void *ptr, const char *file, int line)
{
  SilcStBlock stack;

  if (!ptr)
    return;

  stack = SILC_ST_GET_STACK(ptr);
  if (stack->next)
    stack->next->prev = stack->prev;
  if (stack->prev)
    stack->prev->next = stack->next;
  else
    st_blocks = stack->next;

  st_blocks_count--;
  free(stack);
}

void *silc_st_memdup(const void *ptr, size_t size, const char *file, int line)
{
  unsigned char *addr = (unsigned char *)silc_st_malloc(size + 1, file, line);
  memcpy((void *)addr, ptr, size);
  addr[size] = '\0';
  return (void *)addr;
}

void *silc_st_strdup(const char *string, const char *file, int line)
{
  return silc_st_memdup(string, strlen(string), file, line);
}

/* Dumps the stack into file if there are leaks.  The file can be read
   with a special stacktrace tool. */

void silc_st_dump(void)
{
  SilcStBlock stack, s;
  unsigned long leaks = 0, blocks, bytes;
  FILE *fp = NULL;
  int i;

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
      fprintf(fp, "<stacktrace>%s:%d: #blocks=%lu, bytes=%lu\n",
	      stack->file, stack->line, blocks, bytes);
      for (i = 0; i < stack->depth; i++)
	fprintf(fp, "\tpc=%p\n", stack->stack[i]);
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
  }

  if (fp && fp != stderr)
    fclose(fp);
}

#endif /* SILC_STACKTRACE */
