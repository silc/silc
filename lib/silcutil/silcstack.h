/*

  silcstack.h

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

/****h* silcutil/SilcStack Interface
 *
 * DESCRIPTION
 *
 * Implementation of data stack which can be used to allocate memory from
 * the stack.  Basicly SilcStack is a pre-allocated memory pool system
 * which allows fast memory allocation for routines and applications that
 * frequently allocate small amounts of memory.  Other advantage of this
 * system is that there are no memory leaks, as long as the stack is
 * freed eventually.  Since the stack is usually allocated only once this
 * is not an issue.
 *
 * SilcStack can be used to allocate both aligned and unaligned memory so
 * it is suitable for allocating structures and is optimal for allocating
 * strings and data buffers.  SilcStack also supports stack pushing and
 * popping allowing to push the stack, allocate memory and then pop it
 * to free the allocated memory.  The freeing does not actually do any
 * real memory freeing so it is optimized for performance.
 *
 * A basic set of utility functions are provided for application that wish
 * to use the SilcStack as their primary memory allocation source.  The
 * following functions support SilcStack:
 *
 * silc_smalloc, silc_smalloc_ua, silc_scalloc, silc_srealloc, silc_smemdup,
 * silc_sstrdup, silc_buffer_salloc, silc_buffer_salloc_size,
 * silc_buffer_srealloc, silc_buffer_srealloc_size, silc_buffer_scopy,
 * silc_buffer_sclone, silc_buffer_sformat, silc_buffer_sformat_vp,
 * silc_buffer_sstrformat, silc_buffer_senlarge, silc_mp_sinit
 *
 * The data stack is not thread-safe.  If the same stack context must be
 * used in multithreaded environment concurrency control must be employed.
 * Each thread should allocate their own SilcStack.
 *
 ***/

#ifndef SILCSTACK_H
#define SILCSTACK_H

/****s* silcutil/SilcStackAPI/SilcStack
 *
 * NAME
 *
 *    typedef struct SilcStackStruct *SilcStack;
 *
 * DESCRIPTION
 *
 *    This context represents the stack and it is allocated by
 *    silc_stack_alloc and is destroyed with silc_stack_free functions.
 *    The context is given as argument to all routines that use this
 *    stack allocation library.
 *
 ***/
typedef struct SilcStackStruct *SilcStack;

/****s* silcutil/SilcStackAPI/SilcStackFrame
 *
 * NAME
 *
 *    typedef struct SilcStackFrameStruct SilcStackFrame;
 *
 * DESCRIPTION
 *
 *    Static stack frame context that optionally can be used as stack
 *    frame in SilcStack.  By default silc_stack_push use pre-allocated
 *    stack frame (or allocates new one if all frames are reserved), but
 *    user may also use statically allocated SilcStackFrame instead.  This
 *    is recommended when using SilcStack in recursive routine and the
 *    recursion may become deep.  Using static frame assures that during
 *    recursion frames never run out and silc_stack_push never allocates
 *    any memory.  In other normal usage statically allocated SilcStackFrame
 *    is not needed, unless performance is critical.
 *
 ***/
typedef struct SilcStackFrameStruct SilcStackFrame;

/****f* silcutil/SilcStackAPI/silc_stack_alloc
 *
 * SYNOPSIS
 *
 *    SilcStack silc_stack_alloc(SilcUInt32 stack_size);
 *
 * DESCRIPTION
 *
 *    Allocates new data stack that can be used as stack for fast memory
 *    allocation by various routines.  Returns the pointer to the stack
 *    that must be freed with silc_stack_free function when it is not
 *    needed anymore.  If the `stack_size' is zero (0) by default a
 *    1 kilobyte (1024 bytes) stack is allocated.  If the `stack_size'
 *    is non-zero the byte value must be multiple by 8.
 *
 ***/
SilcStack silc_stack_alloc(SilcUInt32 stack_size);

/****f* silcutil/SilcStackAPI/silc_stack_free
 *
 * SYNOPSIS
 *
 *    void silc_stack_free(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Frees the data stack context.  The stack cannot be used anymore after
 *    this and all allocated memory are freed.
 *
 ***/
void silc_stack_free(SilcStack stack);

/****f* silcutil/SilcStackAPI/silc_stack_push
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_stack_push(SilcStack stack, SilcStackFrame *frame);
 *
 * DESCRIPTION
 *
 *    Push the top of the stack down which becomes the new top of the stack.
 *    For every silc_stack_push call there must be silc_stack_pop call.  All
 *    allocations between these two calls will be done from the top of the
 *    stack and all allocated memory is freed after the next silc_stack_pop
 *    is called.  This returns so called stack pointer for the new stack
 *    frame, which the caller may use to check that all calls to
 *    silc_stack_pop has been made.  This call may do a small memory
 *    allocation in some cases, but usually it does not allocate any memory.
 *    If this returns zero (0) the system is out of memory.
 *
 *    If the `frame' is non-NULL then that SilcStackFrame is used as
 *    stack frame.  Usually `frame' is set to NULL by user.  Statically
 *    allocated SilcStackFrame should be used when using silc_stack_push
 *    in recursive function and the recursion may become deep.  In this
 *    case using statically allocated SilcStackFrame is recommended since
 *    it assures that frames never run out and silc_stack_push never
 *    allocates any memory.  If your routine is not recursive then
 *    setting `frame' to NULL is recommended, unless performance is
 *    critical.
 *
 *    This function is used when a routine is doing frequent allocations
 *    from the stack.  If the stack is not pushed and later popped all
 *    allocations are made from the stack and the stack eventually runs out
 *    (it gets enlarged by normal memory allocation).  By pushing and then
 *    later popping the frequent allocations does not consume the stack.
 *
 *    If `stack' is NULL this call has no effect.
 *
 * EXAMPLE
 *
 *    All memory allocations in silc_foo_parse_packet will be done in
 *    a fresh stack frame and that data is freed after the parsing is
 *    completed.
 *
 *    silc_stack_push(stack, NULL);
 *    silc_foo_parse_packet(packet, stack);
 *    silc_stack_pop(stack);
 *
 *    Another example with recursion and using statically allocated
 *    SilcStackFrame.  After popping the statically allocated frame can
 *    be reused if necessary.
 *
 *    void silc_foo_this_function(SilcStack stack)
 *    {
 *      SilcStackFrame frame;
 *      ...
 *      silc_stack_push(stack, &frame);
 *      silc_foo_this_function(stack);   // Call recursively
 *      silc_stack_pop(stack);
 *      ...
 *    }
 *
 ***/
SilcUInt32 silc_stack_push(SilcStack stack, SilcStackFrame *frame);

/****f* silcutil/SilcStackAPI/silc_stack_pop
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_stack_pop(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Pop the top of the stack upwards which reveals the previous stack frame
 *    and becomes the top of the stack.  After popping, memory allocated in
 *    the old frame is freed.  For each silc_stack_push call there must be
 *    silc_stack_pop call to free all memory (in reality any memory is not
 *    freed but within the stack it is).  This returns the stack pointer of
 *    old frame after popping and caller may check that it is same as
 *    returned by the silc_stack_push.  If it they differ, some routine
 *    has called silc_stack_push but has not called silc_stack_pop, or
 *    silc_stack_pop has been called too many times.  Application should
 *    treat this as a fatal error, as it is a bug in the application code.
 *
 *    If `stack' is NULL this call has no effect.
 *
 * EXAMPLE
 *
 *    This example saves the stack pointer which is checked when popping
 *    the current stack frame.  If the stack pointer differs then someone
 *    has pushed the stack frame but forgot to pop it (or has called it
 *    too many times).
 *
 *    sp = silc_stack_push(stack, NULL);
 *    silc_foo_parse_packet(packet, stack);
 *    if (silc_stack_pop(stack) != sp)
 *      fatal("corrupted stack");
 *
 ***/
SilcUInt32 silc_stack_pop(SilcStack stack);

#include "silcstack_i.h"

#endif /* SILCSTACK_H */
