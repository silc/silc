/*

  silcstack_i.h

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

#ifndef SILCSTACK_I_H
#define SILCSTACK_I_H

#ifndef SILCSTACK_H
#error "Do not include this header directly"
#endif

/* The default stack size when stack is created */
#define SILC_STACK_DEFAULT_SIZE       1024

/* Number of pre-allocated stack frames */
#define SILC_STACK_DEFAULT_NUM        8

/* Default alignment */
#define SILC_STACK_DEFAULT_ALIGN      sizeof(unsigned long)

/* Maximum allocation that can be made with SilcStack.  This is
   SILC_STACK_DEFAULT_SIZE * (2 ^ (SILC_STACK_BLOCK_NUM - 1)). */
#define SILC_STACK_MAX_ALLOC          0x02000000
#define SILC_STACK_BLOCK_NUM          16

/* Stack frame data area */
typedef struct SilcStackDataStruct {
  SilcUInt32 bytes_left;		      /* Free bytes in stack */
  /* Stack data area starts here */
} *SilcStackData;

/* Stack frame */
struct SilcStackFrameStruct {
  struct SilcStackFrameStruct *prev;          /* Pointer to previous frame */
  SilcUInt32 bytes_used;		      /* Bytes used when pushed */
  unsigned int sp : 27;			      /* Stack pointer */
  unsigned int si : 5;			      /* Stack index */
};

/* The SilcStack context */
struct SilcStackStruct {
  SilcStackData stack[SILC_STACK_BLOCK_NUM];  /* Allocated stack blocks */
  SilcStackFrame *frames;		      /* Allocated stack frames */
  SilcStackFrame *frame;		      /* Current stack frame */
  SilcUInt32 stack_size;		      /* Default stack size */
#ifdef SILC_DIST_INPLACE
  /* Statistics */
  SilcUInt32 snum_malloc;
  SilcUInt32 sbytes_malloc;
  SilcUInt32 snum_errors;
#endif /* SILC_DIST_INPLACE */
};

/* Align the requested amount bytes.  The `align' defines the requested
   alignment. */
#define SILC_STACK_ALIGN(bytes, align) (((bytes) + (align - 1)) & ~(align - 1))

/* Computes the size of stack block si. */
#define SILC_STACK_BLOCK_SIZE(stack, si)		\
  (((si) == 0) ? stack->stack_size :			\
   SILC_STACK_DEFAULT_SIZE * (1L << ((si) - 1)) << 1);

/* Returns a pointer to the data in the frame */
#define SILC_STACK_DATA(stack, si, bsize)				  \
  (((unsigned char *)(stack)->stack[si]) +				  \
   SILC_STACK_ALIGN(sizeof(**(stack)->stack), SILC_STACK_DEFAULT_ALIGN) + \
   ((bsize) - (stack)->stack[si]->bytes_left))

#ifdef SILC_DIST_INPLACE
/* Statistics updating */
#define SILC_STACK_STAT(stack, stat, val) ((stack)->s ## stat += (val))
#define SILC_ST_DEBUG(fmt) SILC_LOG_DEBUG(fmt)
#else /* !SILC_DIST_INPLACE */
#define SILC_STACK_STAT(stack, stat, val)
#define SILC_ST_DEBUG(fmt)
#endif /* SILC_DIST_INPLACE */

/* Allocate memory.  If the `aligned' is FALSE this allocates unaligned
   memory, otherwise memory is aligned.  Returns pointer to the memory
   or NULL on error. */
void *silc_stack_malloc(SilcStack stack, SilcUInt32 size, SilcBool aligned);

/* Attempts to reallocate memory by changing the size of the `ptr' into
   `size'.  This routine works only if the previous allocation to `stack'
   was `ptr'.  If there is another memory allocation between allocating
   `ptr' and this call this routine will return NULL.  NULL is also returned
   if the `size' does not fit into the current block.  If NULL is returned
   the old memory remains intact. */
void *silc_stack_realloc(SilcStack stack, SilcUInt32 old_size,
			 void *ptr, SilcUInt32 size, SilcBool aligned);

#ifdef SILC_DIST_INPLACE
/* Prints statistics of the usage of SilcStack to stdout. */
void silc_stack_stats(SilcStack stack);
#endif /* SILC_DIST_INPLACE */

#endif /* SILCSTACK_I_H */
