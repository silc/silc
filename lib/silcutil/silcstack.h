/*

  silcstack.h

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

/****h* silcutil/SilcStack Interface
 *
 * DESCRIPTION
 *
 * Implementation of data stack which can be used to allocate memory from
 * the stack.  Basically SilcStack is a pre-allocated memory pool system
 * which allows fast memory allocation for routines and applications that
 * frequently allocate small amounts of memory.  Other advantage of this
 * system is that there are no memory leaks, as long as the stack is
 * freed eventually.  Since the stack is usually allocated only once this
 * is not an issue.
 *
 * SilcStack supports stack pushing and popping allowing to push the stack,
 * allocate memory and then pop it to free the allocated memory.  The freeing
 * does not actually do any real memory freeing so it is optimized for
 * performance.  The memory alignment may also be specified by user for
 * the stack.  This allows the caller to use special alignment for memory
 * allocations, if needed.
 *
 * SilcStack is also a full featured memory pool which allows user to group
 * together multiple stacks.  Child stacks may be created from a parent stack
 * without consuming the parent stack.  When the child is freed, its memory
 * is returned back to the parent and can be used again by other childs.
 * It is also possible to create child stacks from another child stack.
 *
 * A basic set of utility functions are provided for application that wish
 * to use the SilcStack as their primary memory allocation source.  The
 * following functions support SilcStack:
 *
 * silc_smalloc, silc_smalloc, silc_scalloc, silc_srealloc, silc_smemdup,
 * silc_sfree, silc_sstrdup, silc_buffer_salloc, silc_buffer_salloc_size,
 * silc_buffer_srealloc, silc_buffer_srealloc_size, silc_buffer_scopy,
 * silc_buffer_sclone, silc_buffer_sformat, silc_buffer_sformat_vp,
 * silc_buffer_sstrformat, silc_buffer_senlarge, silc_mp_sinit,
 * silc_dlist_sinit, silc_hash_table_alloc
 *
 * The SilcStack is not thread-safe so that same context could be used for
 * allocations from multiple threads.  It is however safe to create and use
 * child stacks in a different thread from the parent stack.  Each thread
 * should allocate their own SilcStack, however they may be child stacks.
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
 *    stack frame, but user may also use statically allocated SilcStackFrame
 *    instead.  This is recommended when using SilcStack in recursive routine
 *    and the recursion may become deep.  Using static frame assures that
 *    during recursion frames never run out.
 *
 ***/
typedef struct SilcStackFrameStruct SilcStackFrame;

/****f* silcutil/SilcStackAPI/SilcStackOomHandler
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcStackOomHandler)(SilcStack stack, void *context);
 *
 * DESCRIPTION
 *
 *    Callback of this type can be given to silc_stack_set_oom_handler
 *    to set Out of Memory handler to `stack'.  If memory allocation from
 *    `stack' fails this callback is called to indicate error.  The `context'
 *    is the context given to silc_stack_set_oom_handler.
 *
 ***/
typedef void (*SilcStackOomHandler)(SilcStack stack, void *context);

/****f* silcutil/SilcStackAPI/silc_stack_alloc
 *
 * SYNOPSIS
 *
 *    SilcStack silc_stack_alloc(SilcUInt32 stack_size, SilcStack parent);
 *
 * DESCRIPTION
 *
 *    Allocates new data stack that can be used as stack for fast memory
 *    allocation by various routines.  Returns the pointer to the stack
 *    that must be freed with silc_stack_free function when it is not
 *    needed anymore.  If the `stack_size' is zero (0) by default a
 *    1 kilobyte (1024 bytes) stack is allocated.
 *
 *    If `parent' is non-NULL the created stack is a child of the `parent'
 *    stack.  All of childs the memory is allocated from the `parent' and
 *    will be returned back to the parent when the child is freed.  Note
 *    that, even though child allocates memory from the parent, the parent's
 *    stack is not consumed.
 *
 *    Returns NULL on error.
 *
 ***/
SilcStack silc_stack_alloc(SilcUInt32 stack_size, SilcStack parent);

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
 *    If `stack' is a child stack, its memory is returned back to its
 *    parent.  If `stack' is NULL this function does nothing.
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
 *    silc_stack_pop has been made.
 *
 *    If the `frame' is non-NULL then that SilcStackFrame is used as
 *    stack frame.  Usually `frame' is set to NULL by user.  Statically
 *    allocated SilcStackFrame should be used when using silc_stack_push
 *    in recursive function and the recursion may become deep.  In this
 *    case using statically allocated SilcStackFrame is recommended since
 *    it assures that frames never run out.  If your routine is not recursive
 *    then setting `frame' to NULL is recommended.
 *
 *    This function is used when a routine is doing frequent allocations
 *    from the stack.  If the stack is not pushed and later popped all
 *    allocations are made from the stack and the stack eventually runs out
 *    (it gets enlarged by normal memory allocation).  By pushing and then
 *    later popping the frequent allocations does not consume the stack.
 *
 *    If `stack' is NULL this call has no effect.  This function does not
 *    allocate any memory.
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
 *    Pop the top of the stack which removes the previous stack frame and
 *    becomes the top of the stack.  After popping, memory allocated in
 *    the old frame is freed.  For each silc_stack_push call there must be
 *    silc_stack_pop call to free all memory (in reality any memory is not
 *    freed but within the stack it is).  This returns the stack pointer of
 *    old frame after popping and caller may check that it is same as
 *    returned by the silc_stack_push.  If it they differ, some routine
 *    has called silc_stack_push but has not called silc_stack_pop, or
 *    silc_stack_pop has been called too many times.  Application should
 *    treat this as a fatal error, as it is a bug in the application code.
 *
 *    If `stack' is NULL this call has no effect.   This function does not
 *    allocate any memory.
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

/****f* silcutil/SilcStackAPI/silc_stack_malloc
 *
 * SYNOPSIS
 *
 *    void *silc_stack_malloc(SilcStack stack, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Low level memory allocation routine.  Allocates memory block of size of
 *    `size' from the `stack'.  The allocated memory is aligned so it can be
 *    used to allocate memory for structures, for example.  Returns the
 *    allocated memory address or NULL if memory could not be allocated from
 *    the `stack'.
 *
 * NOTES
 *
 *    This function should be used only if low level memory allocation with
 *    SilcStack is needed.  Instead, silc_smalloc and silc_scalloc could
 *    be used.
 *
 ***/
void *silc_stack_malloc(SilcStack stack, SilcUInt32 size);

/****f* silcutil/SilcStackAPI/silc_stack_realloc
 *
 * SYNOPSIS
 *
 *    void *silc_stack_realloc(SilcStack stack, SilcUInt32 old_size,
 *                             void *ptr, SilcUInt32 size);
 *
 * DESCRIPTION
 *
 *    Attempts to reallocate memory by changing the size of the `ptr' into
 *    `size'.  This routine works only if the previous allocation to `stack'
 *    was `ptr'.  If there is another memory allocation between allocating
 *    `ptr' and this call this routine will return NULL (and silc_errno is
 *    set to SILC_ERR_INVALID_ARGUMENT).  NULL is also returned if the `size'
 *    does not fit into the current stack block.  If NULL is returned the old
 *    memory remains intact.
 *
 * NOTES
 *
 *    This function should be used only if low level memory allocation with
 *    SilcStack is needed.  Instead, silc_srealloc could be used.
 *
 ***/
void *silc_stack_realloc(SilcStack stack, SilcUInt32 old_size,
			 void *ptr, SilcUInt32 size);

/****f* silcutil/SilcStackAPI/silc_stack_set_oom_handler
 *
 * SYNOPSIS
 *
 *    void silc_stack_set_oom_handler(SilcStack stack,
 *                                    SilcStackOomHandler oom_handler,
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Sets Out of Memory handler `oom_handler' to `stack' to be called
 *    if memory allocation from `stack' fails.  The `context' is delivered
 *    to `oom_handler'.
 *
 *    Usually Out of Memory handler is set only when failed memory allocation
 *    is a fatal error.  In this case the application would abort() inside
 *    the `oom_handler'.  It may also be set if in case of failed allocation
 *    application wants to do clean up properly.
 *
 ***/
void silc_stack_set_oom_handler(SilcStack stack,
				SilcStackOomHandler oom_handler,
				void *context);

/****f* silcutil/SilcStackAPI/silc_stack_set_alignment
 *
 * SYNOPSIS
 *
 *    void silc_stack_set_alignment(SilcStack stack, SilcUInt32 alignment);
 *
 * DESCRIPTION
 *
 *    Sets/changes the memory alignment in the `stack' to `alignment' which
 *    is the alignment in bytes.  By default, the SilcStack will use alignment
 *    suited for the platform where it is used.  This function can be used
 *    to change this alignment, if such change is needed.  You may check the
 *    current alignment by calling silc_stack_get_alignment.
 *
 * NOTES
 *
 *    It is not mandatory to call this function.  By default the SilcStack
 *    will always use alignment suited for the used platform.  This function
 *    should be called only if the alignment needs to be changed to something
 *    other than the default on the used platform.  For example, some
 *    hardware device, such as crypto accelerator, may require special
 *    alignment.
 *
 ***/
void silc_stack_set_alignment(SilcStack stack, SilcUInt32 alignment);

/****f* silcutil/SilcStackAPI/silc_stack_get_alignment
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_stack_get_alignment(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Returns the memory alignment used with `stack'.  The alignment is in
 *    bytes.
 *
 ***/
SilcUInt32 silc_stack_get_alignment(SilcStack stack);

/****f* silcutil/SilcStackAPI/silc_stack_purge
 *
 * SYNOPSIS
 *
 *    SilcBool silc_stack_purge(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Purges the `stack' from extra unused memory.  This purges only `stack'
 *    and not its parent if `stack' is a child.  This purges only large
 *    allocations.  The 1024, 2048, 4096 and 8192 bytes of allocations remain.
 *    Call this multiple times to purge even more.  Returns FALSE when there
 *    is no more to purge.  This does not purge memory blocks that currently
 *    have allocations.  No memory allocations from the stack are lost, so
 *    this is always safe to call.
 *
 ***/
SilcBool silc_stack_purge(SilcStack stack);

/****f* silcutil/SilcStackAPI/silc_stack_set_global
 *
 * SYNOPSIS
 *
 *    void silc_stack_set_global(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Sets global SilcStack `stack' that can be retrieved at any time
 *    by using silc_stack_get_global.  The global stack is global only
 *    to the current thread.  Each thread can have their own global stack.
 *    If each thread must have own stack this must be called in each
 *    thread.  If the global stack has been set already, new call will
 *    replace the old one.
 *
 *    This routine is provided only as a convenience function to store
 *    program's or thread's stack in one global place.  It is not mandatory
 *    to call this function in order to use SilcStack.
 *
 ***/
void silc_stack_set_global(SilcStack stack);

/****f* silcutil/SilcStackAPI/silc_stack_get_global
 *
 * SYNOPSIS
 *
 *    SilcStack silc_stack_get_global(void);
 *
 * DESCRIPTION
 *
 *    Returns the thread's global stack that was set by calling the
 *    silc_stack_set_global or NULL if global stack has not been set.
 *
 ***/
SilcStack silc_stack_get_global(void);

#include "silcstack_i.h"

#endif /* SILCSTACK_H */
