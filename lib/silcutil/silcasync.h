/*

  silcasync.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Async Operation Interface
 *
 * DESCRIPTION
 *
 * SILC Async Operation API is an interface that can be used to control
 * asynchronous operations.  All functions that take callback as argument
 * should return SilcAsyncOperation context.  That context then can be
 * used to control, such as, abort the asynchronous operation.  Using
 * SILC Async Operation API, asynchronous functions can be controlled
 * and aborted safely.
 *
 * The SILC Async Operation API is divided in two levels; the underlaying
 * operation level that implements the asynchronous operation, and the
 * upper layer that can control the asynchronous operation.  The operation
 * layer must guarantee that if the upper layer aborts the asynchronous
 * operation, no callback function will be called back to the upper layer.
 * This must be remembered when implementing the operation layer.
 *
 ***/

#ifndef SILCASYNC_H
#define SILCASYNC_H

/****s* silcutil/SilcAsyncOperationAPI/SilcAsyncOperation
 *
 * NAME
 *
 *    typedef struct SilcAsyncOperationObject *SilcAsyncOperation;
 *
 * DESCRIPTION
 *
 *    The asynchronous operation context allocated by silc_async_alloc.
 *    The layer that implements the asynchronous operation allocates this
 *    context.  The layer that receives this context can use it to control
 *    the underlaying asynchronous operation.  It is also possible to use
 *    a pre-allocated context by using SilcAsyncOperationStruct instead
 *    SilcAsyncOperation.
 *
 ***/
typedef struct SilcAsyncOperationObject *SilcAsyncOperation;

/****s* silcutil/SilcAsyncOperationAPI/SilcAsyncOperationStruct
 *
 * NAME
 *
 *    typedef struct SilcAsyncOperationObject SilcAsyncOperationStruct;
 *
 * DESCRIPTION
 *
 *    The asynchronous operation context that can be used as a pre-allocated
 *    context.  This is initialized with silc_async_init.  It need not
 *    be uninitialized.  The layer that implements the asynchronous
 *    operation initializes this context.  The layer that has access to this
 *    context can use it to control the underlaying asynchronous operation.
 *
 ***/
typedef struct SilcAsyncOperationObject SilcAsyncOperationStruct;

/****f* silcutil/SilcAsyncOperationAPI/SilcAsyncOperationAbort
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcAsyncOperationAbort)(SilcAsyncOperation op,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    This callback is called when upper layer calls the silc_async_abort,
 *    and is used to actually perform the abortion of the asynchronous
 *    operation.  The silc_async_free must not be called in this function.
 *
 *    This callback type can also be provided to silc_async_abort function
 *    by the upper layer, if it wants that callback is called to the upper
 *    layer when aborting the operation.
 *
 ***/
typedef void (*SilcAsyncOperationAbort)(SilcAsyncOperation op,
					void *context);

/****f* silcutil/SilcAsyncOperationAPI/SilcAsyncOperationPause
 *
 * SYNOPSIS
 *
 *    typedef SilcBool (*SilcAsyncOperationPause)(SilcAsyncOperation op,
 *                                            SilcBool pause_operation,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    This callback is used to halt an operation, if upper layer calls the
 *    silc_async_halt function, or to resume an operation if upper layer
 *    calls the silc_async_resume, after it has earlier halted the operation.
 *    If this callback is implemented it is guaranteed that the asynchronous
 *    operation is not progressed when it is halted.  If the `pause_operation'
 *    is TRUE the operation is halted.  If it is FALSE, then the operation
 *    resumes its execution.  This function returns TRUE if the operation
 *    was (or is going to be) halted or resumed, and FALSE on error.
 *
 ***/
typedef SilcBool (*SilcAsyncOperationPause)(SilcAsyncOperation op,
                                        SilcBool pause_operation,
				        void *context);

/* Upper layer functions for managing asynchronous operations.  Layer
   that has received SilcAsyncOperation context can control the async
   operation with these functions. */

/****f* silcutil/SilcAsyncOperationAPI/silc_async_halt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_async_halt(SilcAsyncOperation op);
 *
 * DESCRIPTION
 *
 *    Halt the execution of the asynchronous operation.  If the operation
 *    supports this feature, it is guaranteed that the operation is halted
 *    and its execution is not progressed until the silc_async_resume function
 *    is called.  The operation still can be aborted even if it is halted.
 *    If this function is not supported, calling this has no effect and the
 *    function returns FALSE.  This function is for the upper layer that
 *    controls the asynchronous operation.
 *
 ***/
SilcBool silc_async_halt(SilcAsyncOperation op);

/****f* silcutil/SilcAsyncOperationAPI/silc_async_resume
 *
 * SYNOPSIS
 *
 *    SilcBool silc_async_resume(SilcAsyncOperation op);
 *
 * DESCRIPTION
 *
 *    Resume the execution of the asynchronous operation.  If the halting of
 *    the operation was supported, then this function is used to resume the
 *    execution of the operation after it was halted.  If this function is
 *    not supported, calling this has no effect and the function returns
 *    FALSE.  This function is for the upper layer that controls the
 *    asynchronous operation.
 *
 ***/
SilcBool silc_async_resume(SilcAsyncOperation op);

/****f* silcutil/SilcAsyncOperationAPI/silc_async_abort
 *
 * SYNOPSIS
 *
 *    void silc_async_abort(SilcAsyncOperation op,
 *                          SilcAsyncOperationAbort abort_cb, void *context);
 *
 * DESCRIPTION
 *
 *    This function is used by upper layer that received SilcAsyncOperation
 *    context from an asynchronous function, to abort the asynchronous
 *    operation.  The `op' becomes invalid after this function returns.
 *    It is also guaranteed (assuming the use of this API is implemented
 *    correctly) that some other completion callback is not called after
 *    the operation was aborted.  However, if the caller wants to receive
 *    a callback when aborting the caller may specify the `abort_cb' and
 *    `context' which will be called after the operation is aborted, but
 *    before the `op' becomes invalid.  The `abort_cb' is called immediately
 *    inside this function.
 *
 ***/
void silc_async_abort(SilcAsyncOperation op,
                      SilcAsyncOperationAbort abort_cb, void *context);

/* The operation layer functions.  The layer that performs the async
   operation use these functions. */

/****f* silcutil/SilcAsyncOperationAPI/silc_async_alloc
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_async_alloc(SilcAsyncOperationAbort abort_cb,
 *                                        SilcAsyncOperationPause pause_cb,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Start asynchronous operation, and assign `abort_cb' callback for it,
 *    which can be used by some upper layer to abort the asynchronous
 *    operation, by calling the silc_async_abort.  The layer which calls
 *    this function must also call silc_async_free when the asynchronous
 *    operation is successfully completed.  If it is aborted by upper layer
 *    then silc_async_free must not be called, since it is called by the
 *    silc_async_abort function.
 *
 *    If the `pause_cb' is provided then the upper layer may also halt and
 *    then later resume the execution of the operation, by calling the
 *    silc_async_halt and silc_async_resume respectively.  If `pause_cb' is
 *    not provided then these functions has no effect for this operation.
 *
 * EXAMPLE
 *
 *    SilcAsyncOperation silc_async_call(Callback callback, void *cb_context)
 *    {
 *      SilcAsyncOperation op;
 *      ...
 *
 *      // Allocate async operation so that caller can control us, like abort
 *      op = silc_async_alloc(silc_async_call_abort, NULL, ctx);
 *
 *      // Start async operation in FSM
 *      silc_fsm_init(&ctx->fsm, ctx, fsm_destructor, ctx, schedule);
 *      silc_fsm_start(&ctx->fsm, first_state);
 *      ...
 *
 *      // Return async operation for upper layer
 *      return op;
 *    }
 *
 ***/
SilcAsyncOperation silc_async_alloc(SilcAsyncOperationAbort abort_cb,
				    SilcAsyncOperationPause pause_cb,
				    void *context);

/****f* silcutil/SilcAsyncOperationAPI/silc_async_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_async_init(SilcAsyncOperation op,
 *                         SilcAsyncOperationAbort abort_cb,
 *                         SilcAsyncOperationPause pause_cb,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Initializes and starts a pre-allocated asynchronous operation context,
 *    and assigns `abort_cb' callback for it, which can be used by some upper
 *    layer to abort the asynchronous operation, by calling the
 *    silc_async_abort.  Since this use pre-allocated context, the function
 *    silc_async_free need not be called.  This function is equivalent
 *    to silc_async_alloc except this does not allocate any memory.
 *
 *    If the `pause_cb' is provided then the upper layer may also halt and
 *    then later resume the execution of the operation, by calling the
 *    silc_async_halt and silc_async_resume respectively.  If `pause_cb' is
 *    not provided then these functions has no effect for this operation.
 *
 ***/
SilcBool silc_async_init(SilcAsyncOperation op,
		     SilcAsyncOperationAbort abort_cb,
		     SilcAsyncOperationPause pause_cb,
		     void *context);

/****f* silcutil/SilcAsyncOperationAPI/silc_async_free
 *
 * SYNOPSIS
 *
 *    void silc_async_free(SilcAsyncOperation op);
 *
 * DESCRIPTION
 *
 *    Stop the asynchronous operation.  If the asynchronous operation ended
 *    normally (ie. it was not aborted) this function must be called by the
 *    caller who called silc_async_alloc.  The `op' will become invalid after
 *    this and the upper layer must not call silc_async_abort after this
 *    function is called.  The layer that calls this, must call some other
 *    completion callback to the upper layer, so that it knows that the
 *    asynchronous operation is completed.
 *
 ***/
void silc_async_free(SilcAsyncOperation op);

/****f* silcutil/SilcAsyncOperationAPI/silc_async_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_async_get_context(SilcAsyncOperation op);
 *
 * DESCRIPTION
 *
 *    Returns the context that was given to the silc_async_alloc or
 *    silc_async_init.
 *
 ***/
void *silc_async_get_context(SilcAsyncOperation op);

#include "silcasync_i.h"

#endif /* SILCASYNC_H */
