/*

  silcstack.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/************************** Types and definitions ***************************/

/* The SilcStack context */
struct SilcStackStruct {
  SilcStack parent;			      /* Parent stack */
  SilcMutex lock;			      /* Stack lock */
  SilcList stacks;			      /* List of stacks for childs */
  SilcStackDataEntry stack;		      /* The allocated stack */
  SilcStackFrame *frames;		      /* Allocated stack frames */
  SilcStackFrame *frame;		      /* Current stack frame */
  SilcStackOomHandler oom_handler;	      /* OOM handler */
  void *oom_context;			      /* OOM handler context */
  SilcUInt32 stack_size;		      /* Default stack size */
  SilcUInt32 alignment;			      /* Memory alignment */
#ifdef SILC_DIST_INPLACE
  /* Statistics */
  SilcUInt32 snum_malloc;
  SilcUInt32 sbytes_malloc;
  SilcUInt32 snum_errors;
#endif /* SILC_DIST_INPLACE */
};

/************************ Static utility functions **************************/

/* Compute stack block index for the `size'. */

static SilcUInt32 silc_stack_get_index(SilcUInt32 size, SilcUInt32 *ret_bsize)
{
  SilcUInt32 bsize, si;

  if (size < SILC_STACK_DEFAULT_SIZE)
    size = SILC_STACK_DEFAULT_SIZE;
  si = 0;
  bsize = SILC_STACK_DEFAULT_SIZE;
  while (bsize < size) {
    bsize <<= 1;
    si++;
  }

  *ret_bsize = bsize;

  return si;
}

/* Get stack from `stack' or allocate new one. */

static SilcStackDataEntry silc_stack_ref_stack(SilcStack stack,
					       SilcUInt32 size,
					       SilcUInt32 *ret_si,
					       SilcUInt32 *ret_bsize)
{
  SilcStackDataEntry e;
  SilcUInt32 si, bsize;

  /* Get stack block index and block size for requested size */
  si = silc_stack_get_index(size, &bsize);
  *ret_si = si;
  *ret_bsize = bsize;

  SILC_ST_DEBUG(("Get stack block, si %d, size %lu, stack %p",
		 si, bsize, stack));

  silc_mutex_lock(stack->lock);

  /* Get stack that has block that can house our size requirement. */
  silc_list_start(stack->stacks);
  while ((e = silc_list_get(stack->stacks))) {
    if (!e->data[si])
      continue;

    silc_list_del(stack->stacks, e);
    SILC_ST_DEBUG(("Got stack blocks %p from stack %p", e->data, stack));
    silc_mutex_unlock(stack->lock);
    return e;
  }

  silc_mutex_unlock(stack->lock);

  /* If we are child, get block from parent */
  if (stack->parent)
    return silc_stack_ref_stack(stack->parent, size, ret_si, ret_bsize);

  SILC_ST_DEBUG(("Allocate new stack blocks"));

  /* Allocate new stack blocks */
  e = silc_calloc(1, sizeof(*e));
  if (!e)
    return NULL;
  e->data[si] = silc_malloc(bsize + SILC_STACK_ALIGN(sizeof(*e->data[0]),
						     stack->alignment));
  if (!e->data[si]) {
    silc_free(e);
    return NULL;
  }
  e->data[si]->bytes_left = bsize;
  e->si = si;
  e->bsize = bsize;

  SILC_ST_DEBUG(("Got stack blocks %p from stack %p", e->data, stack));

  return e;
}

/* Return the `data' back to the `stack'. */

static void silc_stack_unref_stack(SilcStack stack, SilcStackDataEntry e)
{
  int i;

  SILC_LOG_DEBUG(("Release stack blocks %p to stack %p, si %d",
		  e->data, stack, e->si));

  /* Release all blocks from allocations */
  for (i = e->si; i < SILC_STACK_BLOCK_NUM; i++) {
    if (!e->data[i])
      continue;
    if (!i)
      e->data[i]->bytes_left = e->bsize;
    else
      e->data[i]->bytes_left = SILC_STACK_BLOCK_SIZE(stack, i);
  }

  silc_mutex_lock(stack->lock);
  silc_list_add(stack->stacks, e);
  silc_mutex_unlock(stack->lock);
}

/* Allocate memory from a specific stack block */

static void *silc_stack_alloc_block(SilcStack stack, SilcStackDataEntry e,
				    SilcUInt32 items, SilcUInt32 size)
{
  SilcUInt32 asize;
  void *ptr;

  /* Get pointer and consume the stack block */
  asize = SILC_STACK_ALIGN(items * size, stack->alignment);
  ptr = SILC_STACK_DATA_EXT(e->data, e->si, e->bsize, stack->alignment);
  e->data[e->si]->bytes_left -= asize;
  memset(ptr, 0, items * size);

  return ptr;
}

/***************************** SilcStack API ********************************/

/* Allocate the stack */

SilcStack silc_stack_alloc(SilcUInt32 stack_size, SilcStack parent)
{
  SilcStack stack;
  SilcStackDataEntry e;
  SilcUInt32 si = 0, bsize = 0;

  stack_size = stack_size ? stack_size : SILC_STACK_DEFAULT_SIZE;
  if (stack_size < SILC_STACK_DEFAULT_SIZE)
    stack_size = SILC_STACK_DEFAULT_SIZE;

  /* Align by 8 */
  stack_size += ((-stack_size) % 8);

  if (parent) {
    /* Get stack from parent.  The stack itself is allocated from the
       parent (but does not consume parent's own stack). */
    e = silc_stack_ref_stack(parent, stack_size, &si, &bsize);
    if (!e)
      return NULL;

    /* Allocate stack from the returned stack.  We allocate ourselves from
       our own stack. */
    stack = silc_stack_alloc_block(parent, e, 1, sizeof(*stack));
    if (!stack) {
      silc_stack_unref_stack(parent, e);
      return NULL;
    }

    stack->parent = parent;
    stack->stack_size = stack_size;
    stack->alignment = SILC_STACK_DEFAULT_ALIGN;
    stack->oom_handler = parent->oom_handler;
    stack->oom_context = parent->oom_context;
    stack->lock = parent->lock;
    silc_list_init(stack->stacks, struct SilcStackDataEntryStruct, next);

    /* Allocate stack frames from the stack itself */
    stack->frames = silc_stack_alloc_block(stack, e, SILC_STACK_BLOCK_NUM,
					   sizeof(*stack->frames));
    if (!stack->frames) {
      silc_stack_unref_stack(parent, e);
      return NULL;
    }

    /* Set the initial stack */
    stack->stack = e;
  } else {
    /* Dynamically allocate new stack */
    stack = silc_calloc(1, sizeof(*stack));
    if (!stack)
      return NULL;

    stack->stack_size = stack_size;
    stack->alignment = SILC_STACK_DEFAULT_ALIGN;
    silc_list_init(stack->stacks, struct SilcStackDataEntryStruct, next);

    /* Create initial stack */
    stack->stack = silc_calloc(1, sizeof(*stack->stack));
    if (!stack->stack) {
      silc_free(stack);
      return NULL;
    }
    stack->stack->data[0] =
      silc_malloc(stack->stack_size +
		  SILC_STACK_ALIGN(sizeof(*stack->stack->data[0]),
				   stack->alignment));
    if (!stack->stack->data[0]) {
      silc_free(stack->stack);
      silc_free(stack);
      return NULL;
    }
    stack->stack->data[0]->bytes_left = stack->stack_size;
    stack->stack->si = 0;
    stack->stack->bsize = stack->stack_size;

    /* Allocate stack frames from the stack itself */
    stack->frames = silc_stack_alloc_block(stack, stack->stack,
					   SILC_STACK_DEFAULT_NUM,
					   sizeof(*stack->frames));
    if (!stack->frames) {
      silc_free(stack->stack->data[0]);
      silc_free(stack->stack);
      silc_free(stack);
      return NULL;
    }

    /* Allocate lock */
    silc_mutex_alloc(&stack->lock);
  }

  /* Use the allocated stack in first stack frame */
  stack->frame = &stack->frames[0];
  stack->frame->prev = NULL;
  stack->frame->bytes_used = stack->stack_size;
  stack->frame->sp = 1;
  stack->frame->si = si;

  SILC_LOG_DEBUG(("New stack %p, size %d bytes", stack, stack->stack_size));

  return stack;
}

/* Frees the stack and all allocated memory */

void silc_stack_free(SilcStack stack)
{
  SilcStackDataEntry e;
  int i;

  if (!stack)
    return;

  SILC_LOG_DEBUG(("Free stack %p", stack));

  if (!stack->parent) {
    silc_list_start(stack->stacks);
    while ((e = silc_list_get(stack->stacks))) {
      for (i = 0; i < SILC_STACK_BLOCK_NUM; i++)
	silc_free(e->data[i]);
      silc_free(e);
    }

    for (i = 0; i < SILC_STACK_BLOCK_NUM; i++)
      silc_free(stack->stack->data[i]);
    silc_free(stack->stack);

    if (stack->lock)
      silc_mutex_free(stack->lock);

    silc_free(stack);
  } else {
    /* Return all stack blocks to the parent */
    silc_list_start(stack->stacks);
    while ((e = silc_list_get(stack->stacks)))
      silc_stack_unref_stack(stack->parent, e);

    silc_stack_unref_stack(stack->parent, stack->stack);
  }
}

/* Push to next stack frame */

SilcUInt32 silc_stack_push(SilcStack stack, SilcStackFrame *frame)
{
  if (!stack)
    return 0;

  if (!frame) {
    if (stack->frame->sp >= SILC_STACK_ALIGN(stack->frame->sp,
					     SILC_STACK_DEFAULT_NUM)) {
      SILC_LOG_DEBUG(("SilcStack %p running out of frames, cannot push",
		      stack));
      return stack->frame->sp;
    }

    frame = &stack->frames[stack->frame->sp];
  }

  /* Push */
  frame->prev = stack->frame;
  frame->sp = stack->frame->sp + 1;
  frame->si = stack->frame->si;
  frame->bytes_used = stack->stack->data[frame->si]->bytes_left;
  stack->frame = frame;

  SILC_ST_DEBUG(("Push %p: sp %d -> %d, si %d", stack, frame->prev->sp,
		 frame->sp, frame->si));

  return stack->frame->sp;
}

/* Pop to previous stack frame */

SilcUInt32 silc_stack_pop(SilcStack stack)
{
  SilcUInt32 si;

  if (!stack || !stack->frame->prev)
    return 0;

  /* Pop */
  si = stack->frame->si;
  while (si > stack->frame->prev->si) {
    if (stack->stack->data[si])
      stack->stack->data[si]->bytes_left = SILC_STACK_BLOCK_SIZE(stack, si);
    si--;
  }
  stack->stack->data[si]->bytes_left = stack->frame->bytes_used;
  stack->frame = stack->frame->prev;

  SILC_ST_DEBUG(("Pop %p: sp %d -> %d, si %d", stack, stack->frame->sp + 1,
		 stack->frame->sp, stack->frame->si));

  return stack->frame->sp + 1;
}

/* Allocate memory.  Returns pointer to the memory or NULL on error. */

void *silc_stack_malloc(SilcStack stack, SilcUInt32 size)
{
  void *ptr;
  SilcUInt32 bsize, bsize2;
  SilcUInt32 si = stack->frame->si;

  SILC_STACK_STAT(stack, num_malloc, 1);
  SILC_ST_DEBUG(("Allocating %d bytes from %p", size, stack));

  if (silc_unlikely(!size)) {
    SILC_LOG_DEBUG(("Allocation by zero (0)"));
    silc_set_errno_nofail(SILC_ERR_ZERO_ALLOCATION);
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  if (silc_unlikely(size > SILC_STACK_MAX_ALLOC)) {
    SILC_LOG_DEBUG(("Allocating too much"));
    silc_set_errno_nofail(SILC_ERR_TOO_LARGE_ALLOCATION);
    SILC_STACK_STAT(stack, num_errors, 1);
    if (stack->oom_handler)
      stack->oom_handler(stack, stack->oom_context);
    return NULL;
  }

  /* Align properly  */
  size = SILC_STACK_ALIGN(size, stack->alignment);

  /* Compute the size of current stack block */
  bsize = SILC_STACK_BLOCK_SIZE(stack, si);

  /* See if there is space in the current stack block */
  if (stack->stack->data[si]->bytes_left >= size) {
    /* Get pointer to the memory */
    ptr = SILC_STACK_DATA(stack, si, bsize);
    stack->stack->data[si]->bytes_left -= size;
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
  if (silc_unlikely(si >= SILC_STACK_BLOCK_NUM)) {
    SILC_LOG_DEBUG(("Allocating too large block"));
    silc_set_errno_nofail(SILC_ERR_TOO_LARGE_ALLOCATION);
    SILC_STACK_STAT(stack, num_errors, 1);
    if (stack->oom_handler)
      stack->oom_handler(stack, stack->oom_context);
    return NULL;
  }

  /* Allocate the block if it doesn't exist yet */
  if (!stack->stack->data[si]) {
    SILC_ST_DEBUG(("Allocating new stack block, %d bytes", bsize2));
    stack->stack->data[si] =
      silc_malloc(bsize2 +
		  SILC_STACK_ALIGN(sizeof(**stack->stack->data),
				   stack->alignment));
    if (silc_unlikely(!stack->stack->data[si])) {
      SILC_STACK_STAT(stack, num_errors, 1);
      if (stack->oom_handler)
	stack->oom_handler(stack, stack->oom_context);
      return NULL;
    }
    stack->stack->data[si]->bytes_left = bsize2;
  }

  /* Now return memory from this new block.  It is guaranteed that in this
     block there is enough space for this memory. */
  assert(stack->stack->data[si]->bytes_left >= size);
  ptr = SILC_STACK_DATA(stack, si, bsize2);
  stack->stack->data[si]->bytes_left -= size;
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
			 void *ptr, SilcUInt32 size)
{
  SilcUInt32 si = stack->frame->si;
  SilcUInt32 bsize;
  void *sptr;

  if (!ptr)
    return silc_stack_malloc(stack, size);

  SILC_STACK_STAT(stack, num_malloc, 1);
  SILC_ST_DEBUG(("Reallocating %d bytes (%d) from %p", size, old_size, stack));

  if (silc_unlikely(!size || !old_size)) {
    SILC_LOG_DEBUG(("Allocation by zero (0)"));
    silc_set_errno_nofail(SILC_ERR_ZERO_ALLOCATION);
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  if (silc_unlikely(size > SILC_STACK_MAX_ALLOC)) {
    SILC_LOG_DEBUG(("Allocating too much"));
    silc_set_errno_nofail(SILC_ERR_TOO_LARGE_ALLOCATION);
    SILC_STACK_STAT(stack, num_errors, 1);
    if (stack->oom_handler)
      stack->oom_handler(stack, stack->oom_context);
    return NULL;
  }

  /* Align properly */
  old_size = SILC_STACK_ALIGN(old_size, stack->alignment);

  /* Compute the size of current stack block */
  bsize = SILC_STACK_BLOCK_SIZE(stack, si);

  /* Check that `ptr' is last allocation */
  sptr = (unsigned char *)stack->stack->data[si] +
    SILC_STACK_ALIGN(sizeof(**stack->stack->data), stack->alignment);
  if (stack->stack->data[si]->bytes_left + old_size +
      ((unsigned char *)ptr - (unsigned char *)sptr) != bsize) {
    SILC_LOG_DEBUG(("Cannot reallocate"));
    silc_set_errno_nofail(SILC_ERR_INVALID_ARGUMENT);
    SILC_STACK_STAT(stack, num_errors, 1);
    return NULL;
  }

  /* Now check that the new size fits to this block */
  if (stack->stack->data[si]->bytes_left >= size) {
    /* It fits, so simply return the old pointer */
    size = SILC_STACK_ALIGN(size, stack->alignment);
    stack->stack->data[si]->bytes_left -= (size - old_size);
    SILC_STACK_STAT(stack, bytes_malloc, (size - old_size));
    return ptr;
  }

  SILC_LOG_DEBUG(("Cannot reallocate in this block"));
  silc_set_errno_reason_nofail(SILC_ERR_TOO_LARGE_ALLOCATION,
			       "Cannot reallocate in this memory block");
  SILC_STACK_STAT(stack, num_errors, 1);
  return NULL;
}

/* Set OOM handler */

void silc_stack_set_oom_handler(SilcStack stack,
				SilcStackOomHandler oom_handler,
				void *context)
{
  stack->oom_handler = oom_handler;
  stack->oom_context = context;
}

/* Set default alignment */

void silc_stack_set_alignment(SilcStack stack, SilcUInt32 alignment)
{
  SILC_LOG_DEBUG(("Set stack %p alignment to %d bytes", stack, alignment));
  stack->alignment = alignment;
}

/* Get default alignment */

SilcUInt32 silc_stack_get_alignment(SilcStack stack)
{
  return stack->alignment;
}

/* Purge stack */

SilcBool silc_stack_purge(SilcStack stack)
{
  SilcStackDataEntry e;
  SilcBool ret = FALSE;
  int i;

  SILC_LOG_DEBUG(("Purge stack %p", stack));

  /* Go through the default stack */
  for (i = SILC_STACK_BLOCK_NUM - 1; i > 3; i--) {
    if (stack->stack->data[i] &&
	stack->stack->data[i]->bytes_left == SILC_STACK_BLOCK_SIZE(stack, i)) {
      SILC_LOG_DEBUG(("Purge %d bytes",
		      SILC_STACK_BLOCK_SIZE(stack, i)));
      silc_free(stack->stack->data[i]);
      stack->stack->data[i] = NULL;
      ret = TRUE;
    }
  }

  silc_mutex_lock(stack->lock);

  /* Remove one child stack */
  if (silc_list_count(stack->stacks) > 2) {
    silc_list_start(stack->stacks);
    e = silc_list_get(stack->stacks);

    SILC_LOG_DEBUG(("Remove stack blocks %p", e->data));
    silc_list_del(stack->stacks, e);
    ret = TRUE;

    for (i = 0; i < SILC_STACK_BLOCK_NUM; i++)
      silc_free(e->data[i]);
    silc_free(e);
  }

  /* Go through the child stacks */
  silc_list_start(stack->stacks);
  while ((e = silc_list_get(stack->stacks))) {
    for (i = SILC_STACK_BLOCK_NUM - 1; i > 3; i--) {
      if (e->data[i]) {
	SILC_LOG_DEBUG(("Purge %d bytes",
			SILC_STACK_BLOCK_SIZE(stack, i)));
	silc_free(e->data[i]);
	e->data[i] = NULL;
	ret = TRUE;
      }
    }
  }

  silc_mutex_unlock(stack->lock);

  return ret;
}

/* Set global stack */

void silc_stack_set_global(SilcStack stack)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls) {
    /* Try to initialize Tls */
    tls = silc_thread_tls_init();
    SILC_VERIFY(tls);
    if (!tls)
      return;
  }

  tls->stack = stack;
}

/* Return global stack */

SilcStack silc_stack_get_global(void)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls)
    return NULL;

  return tls->stack;
}

#ifdef SILC_DIST_INPLACE
/* Statistics dumping. */

void silc_stack_stats(SilcStack stack)
{
  SilcStackDataEntry e;
  SilcUInt32 stack_size = 0;
  int i, c = 0;

  for (i = 0; i < SILC_STACK_BLOCK_NUM; i++) {
    if (!stack->stack->data[i])
      continue;
    stack_size += SILC_STACK_BLOCK_SIZE(stack, i);
    c++;
  }

  fprintf(stdout, "\nSilcStack %p statistics :\n\n", stack);
  fprintf(stdout, "  Size of stack           : %u\n",
	  (unsigned int)stack_size);
  fprintf(stdout, "  Stack alignment         : %d\n",
	  (int)stack->alignment);
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
  fprintf(stdout, "  Number of stacks        : %d\n",
	  silc_list_count(stack->stacks));

  silc_list_start(stack->stacks);
  while ((e = silc_list_get(stack->stacks))) {
    stack_size = 0;
    c = 0;
    for (i = 0; i < SILC_STACK_BLOCK_NUM; i++) {
      if (!e->data[i])
	continue;
      stack_size += e->data[i]->bytes_left;
      c++;
    }
    fprintf(stdout, "\n  Size of stack           : %u\n",
	    (unsigned int)stack_size);
    fprintf(stdout, "  Number of blocks        : %u\n", c);
  }
}
#endif /* SILC_DIST_INPLACE */
