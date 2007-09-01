/*

  silcstack_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2007 Pekka Riikonen

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
#define SILC_STACK_DEFAULT_SIZE 1024

/* Number of pre-allocated stack frames.  Frames are allocated from the
   stack itself. */
#define SILC_STACK_DEFAULT_NUM 32

/* Default alignment */
#define SILC_STACK_DEFAULT_ALIGN SILC_ALIGNMENT

/* Maximum allocation that can be made with SilcStack. */
#define SILC_STACK_BLOCK_NUM 21
#define SILC_STACK_MAX_ALLOC \
  (SILC_STACK_DEFAULT_SIZE * (1L << (SILC_STACK_BLOCK_NUM - 1)) << 1)

/* Stack frame data area */
typedef struct SilcStackDataStruct {
  SilcUInt32 bytes_left;		      /* Free bytes in stack */
  /* Stack data area starts here */
} *SilcStackData;

/* Stack data entry */
typedef struct SilcStackDataEntryStruct {
  struct SilcStackDataEntryStruct *next;
  SilcStackData data[SILC_STACK_BLOCK_NUM];   /* Blocks */
  SilcUInt32 bsize;		              /* Default block size */
  SilcUInt32 si;			      /* Default block index */
} *SilcStackDataEntry;

/* Stack frame */
struct SilcStackFrameStruct {
  struct SilcStackFrameStruct *prev;          /* Pointer to previous frame */
  SilcUInt32 bytes_used;		      /* Bytes used when pushed */
  unsigned int sp : 27;			      /* Stack pointer */
  unsigned int si : 5;			      /* Stack index */
};

/* Align the requested amount bytes.  The `align' defines the requested
   alignment. */
#define SILC_STACK_ALIGN(bytes, align) (((bytes) + (align - 1)) & ~(align - 1))

/* Computes the size of stack block si. */
#define SILC_STACK_BLOCK_SIZE(stack, si)		\
  (((si) == 0) ? stack->stack_size :			\
   SILC_STACK_DEFAULT_SIZE * (1L << ((si) - 1)) << 1)

/* Returns a pointer to the data in the given stack block */
#define SILC_STACK_DATA_EXT(data, si, bsize, alignment)			\
  (((unsigned char *)(data)[si]) +					\
   SILC_STACK_ALIGN(sizeof(**(data)), alignment) +			\
   ((bsize) - (data)[si]->bytes_left))

/* Returns a pointer to the data in the frame */
#define SILC_STACK_DATA(stack, si, bsize)				\
  SILC_STACK_DATA_EXT((stack)->stack->data, si, bsize, (stack)->alignment)

#ifdef SILC_DIST_INPLACE
/* Statistics updating */
#define SILC_STACK_STAT(stack, stat, val) ((stack)->s ## stat += (val))
#define SILC_ST_DEBUG(fmt) SILC_LOG_DEBUG(fmt)
#else /* !SILC_DIST_INPLACE */
#define SILC_STACK_STAT(stack, stat, val)
#define SILC_ST_DEBUG(fmt)

/* Prints statistics of the usage of SilcStack to stdout. */
void silc_stack_stats(SilcStack stack);
#endif /* SILC_DIST_INPLACE */

#endif /* SILCSTACK_I_H */
