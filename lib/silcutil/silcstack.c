/*

  silcstack.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* #define SILC_STACK_DEBUG 1 */

#include "silc.h"

/* Allocate the stack */

SilcStack silc_stack_alloc(SilcUInt32 stack_size)
{
  SilcStack stack;

  stack = silc_calloc(1, sizeof(*stack));
  if (!stack)
    return NULL;

  stack->frames = silc_calloc(SILC_STACK_DEFAULT_NUM,
			      sizeof(*stack->frames));
  if (!stack->frames) {
    silc_free(stack);
    return NULL;
  }

  /* Create initial stack */
  stack->stack_size = stack_size ? stack_size : SILC_STACK_DEFAULT_SIZE;
  stack->stack[0] = silc_malloc(stack->stack_size +
  				SILC_STACK_ALIGN(sizeof(*stack->stack[0]),
  						 SILC_STACK_DEFAULT_ALIGN));
  if (!stack->stack[0]) {
    silc_free(stack->frames);
    silc_free(stack);
    return NULL;
  }
  stack->stack[0]->bytes_left = stack->stack_size;

  /* Use the allocated stack in first stack frame */
  stack->frame = &stack->frames[0];
  stack->frame->prev = NULL;
  stack->frame->bytes_used = stack->stack_size;
  stack->frame->sp = 1;
  stack->frame->si = 0;

  return stack;
}

/* Frees the stack and all allocated memory */

void silc_stack_free(SilcStack stack)
{
  int i;

  silc_free(stack->frames);
  for (i = 0; i < SILC_STACK_BLOCK_NUM; i++)
    silc_free(stack->stack[i]);
  silc_free(stack);
}

/* Push to next stack frame */

SilcUInt32 silc_stack_push(SilcStack stack, SilcStackFrame *frame)
{
  if (!stack)
    return 0;

  if (!frame) {
    /* See if all frames are in use, and allocate SILC_STACK_DEFAULT_NUM
       many new frames if needed. */
    if (stack->frame->sp >= SILC_STACK_ALIGN(stack->frame->sp,
					     SILC_STACK_DEFAULT_NUM)) {
      int i = stack->frame->sp;
      SILC_LOG_DEBUG(("Allocating more stack frames"));
      frame = silc_realloc(stack->frames,
			   SILC_STACK_ALIGN(i + 1, SILC_STACK_DEFAULT_NUM) *
			   sizeof(*stack->frames));
      if (!frame)
	return 0;
      stack->frames = frame;
      stack->frame = &stack->frames[i - 1];

      /* The prev pointers may become invalid in silc_realloc() */
      for (i = 1; i < stack->frame->sp; i++)
	stack->frames[i].prev = &stack->frames[i - 1];
    }

    frame = &stack->frames[stack->frame->sp];
  }

  /* Push */
  frame->prev = stack->frame;
  frame->sp = stack->frame->sp + 1;
  frame->si = stack->frame->si;
  frame->bytes_used = stack->stack[frame->si]->bytes_left;
  stack->frame = frame;

  SILC_ST_DEBUG(("Push %p: sp %d -> %d, si %d", stack, frame->prev->sp,
		 frame->sp, frame->si));

  return stack->frame->sp;
}

/* Pop to previous stack frame */

SilcUInt32 silc_stack_pop(SilcStack stack)
{
  SilcUInt32 si;

  if (!stack)
    return 0;

  /* Pop */
  assert(stack->frame->prev);
  si = stack->frame->si;
  while (si > stack->frame->prev->si) {
    if (stack->stack[si])
      stack->stack[si]->bytes_left = SILC_STACK_BLOCK_SIZE(stack, si);
    si--;
  }
  stack->stack[si]->bytes_left = stack->frame->bytes_used;
  stack->frame = stack->frame->prev;

  SILC_ST_DEBUG(("Pop %p: sp %d -> %d, si %d", stack, stack->frame->sp + 1,
		 stack->frame->sp, stack->frame->si));

  return stack->frame->sp + 1;
}

/* Allocate memory.  If the `aligned' is FALSE this allocates unaligned
   memory, otherwise memory is aligned.  Returns pointer to the memory
   or NULL on error. */

void *silc_stack_malloc(SilcStack stack, SilcUInt32 size, SilcBool aligned)
{
  void *ptr;
  SilcUInt32 bsize, bsize2;
  SilcUInt32 si = stack->frame->si;

  SILC_STACK_STAT(stack, num_malloc, 1);
  SILC_ST_DEBUG(("Allocating %d bytes (%s) from %p",
		 size, aligned ? "align" : "not align", stack));

  if (!size) {
    SILC_LOG_ERROR(("Allocation by zero (0)"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  if (size > SILC_STACK_MAX_ALLOC) {
    SILC_LOG_ERROR(("Allocating too much"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  /* Align properly if wanted */
  size = (aligned ? SILC_STACK_ALIGN(size, SILC_STACK_DEFAULT_ALIGN) : size);

  /* Compute the size of current stack block */
  bsize = SILC_STACK_BLOCK_SIZE(stack, si);

  /* See if there is space in the current stack block */
  if (stack->stack[si]->bytes_left >= size) {
    /* Get pointer to the memory */
    ptr = SILC_STACK_DATA(stack, si, bsize);
    stack->stack[si]->bytes_left -= size;
    SILC_STACK_STAT(stack, bytes_malloc, size);
    return ptr;
  }

  /* There is not enough space in this block.  Find the spot to stack
     block that can handle this size memory. */
  if (bsize < SILC_STACK_DEFAULT_SIZE)
    bsize = SILC_STACK_DEFAULT_SIZE;
  bsize += size;
  bsize2 = SILC_STACK_DEFAULT_SIZE;
  si = 0;
  while (bsize2 < bsize) {
    bsize2 <<= 1;
    si++;
  }
  if (si >= SILC_STACK_BLOCK_NUM) {
    SILC_LOG_ERROR(("Allocating too large block"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  /* Allocate the block if it doesn't exist yet */
  if (!stack->stack[si]) {
    SILC_ST_DEBUG(("Allocating new stack block, %d bytes", bsize2));
    stack->stack[si] = silc_malloc(bsize2 +
				   SILC_STACK_ALIGN(sizeof(**stack->stack),
						    SILC_STACK_DEFAULT_ALIGN));
    if (!stack->stack[si]) {
      SILC_STACK_STAT(stack, num_errors, 1);
      return NULL;
    }
    stack->stack[si]->bytes_left = bsize2;
  }

  /* Now return memory from this new block.  It is guaranteed that in this
     block there is enough space for this memory. */
  assert(stack->stack[si]->bytes_left >= size);
  ptr = SILC_STACK_DATA(stack, si, bsize2);
  stack->stack[si]->bytes_left -= size;
  stack->frame->si = si;
  SILC_STACK_STAT(stack, bytes_malloc, size);

  return ptr;
}

/* Attempts to reallocate memory by changing the size of the `ptr' into
   `size'.  This routine works only if the previous allocation to `stack'
   was `ptr'.  If there is another memory allocation between allocating
   `ptr' and this call this routine will return NULL.  NULL is also returned
   if the `size' does not fit into the current block.  If NULL is returned
   the old memory remains intact. */

void *silc_stack_realloc(SilcStack stack, SilcUInt32 old_size,
			 void *ptr, SilcUInt32 size, SilcBool aligned)
{
  SilcUInt32 si = stack->frame->si;
  SilcUInt32 bsize;
  void *sptr;

  if (!ptr)
    return silc_stack_malloc(stack, size, aligned);

  SILC_STACK_STAT(stack, num_malloc, 1);
  SILC_ST_DEBUG(("Reallocating %d bytes (%d) (%s) from %p", size, old_size,
		 aligned ? "align" : "not align", stack));

  if (!size || !old_size) {
    SILC_LOG_ERROR(("Allocation by zero (0)"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  if (size > SILC_STACK_MAX_ALLOC) {
    SILC_LOG_ERROR(("Allocating too much"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  /* Align the old size if needed */
  old_size = (aligned ?
	      SILC_STACK_ALIGN(old_size,
			       SILC_STACK_DEFAULT_ALIGN) : old_size);

  /* Compute the size of current stack block */
  bsize = SILC_STACK_BLOCK_SIZE(stack, si);

  /* Check that `ptr' is last allocation */
  sptr = (unsigned char *)stack->stack[si] +
    SILC_STACK_ALIGN(sizeof(**stack->stack), SILC_STACK_DEFAULT_ALIGN);
  if (stack->stack[si]->bytes_left + old_size + (ptr - sptr) != bsize) {
    SILC_LOG_DEBUG(("Cannot reallocate"));
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  /* Now check that the new size fits to this block */
  if (stack->stack[si]->bytes_left >= size) {
    /* It fits, so simply return the old pointer */
    size = (aligned ? SILC_STACK_ALIGN(size,
				       SILC_STACK_DEFAULT_ALIGN) : size);
    stack->stack[si]->bytes_left -= (size - old_size);
    SILC_STACK_STAT(stack, bytes_malloc, (size - old_size));
    return ptr;
  }

  SILC_LOG_DEBUG(("Cannot reallocate in this block"));
  SILC_STACK_STAT(stack, num_errors, 1);
  return NULL;
}

#ifdef SILC_DIST_INPLACE
/* Statistics dumping. */

void silc_stack_stats(SilcStack stack)
{
  SilcUInt32 stack_size = 0;
  int i, c = 0;

  for (i = 0; i < SILC_STACK_BLOCK_NUM; i++) {
    if (!stack->stack[i])
      continue;
    stack_size += SILC_STACK_BLOCK_SIZE(stack, i);
    c++;
  }

  fprintf(stdout, "\nSilcStack %p statistics :\n\n", stack);
  fprintf(stdout, "  Size of stack           : %u\n",
	  (unsigned int)stack_size);
  fprintf(stdout, "  Number of allocs        : %u\n",
	  (unsigned int)stack->snum_malloc);
  fprintf(stdout, "  Bytes allocated         : %u\n",
	  (unsigned int)stack->sbytes_malloc);
  fprintf(stdout, "  Average alloc size      : %.2f\n",
	  (double)((double)stack->sbytes_malloc / (double)stack->snum_malloc));
  fprintf(stdout, "  Number of alloc errors  : %u\n",
	  (unsigned int)stack->snum_errors);
  fprintf(stdout, "  Number of frames        : %u\n",
	  (unsigned int)SILC_STACK_ALIGN(stack->frame->sp,
					 SILC_STACK_DEFAULT_NUM));
  fprintf(stdout, "  Number of blocks        : %u\n", c);
}
#endif /* SILC_DIST_INPLACE */
