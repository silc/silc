/*

  silcfsm.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005, 2006, 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Finite State Machine
 *
 * DESCRIPTION
 *
 * SILC FSM Interface implements a finite state machine.  The FSM can be
 * used to implement all kinds of machines and protocols.  The FSM supports
 * also threads and can be synchronized by using mutex locks.  The FSM
 * also supports real system threads.  It is possible to create new FSM
 * thread and then execute in real system thread, if platform supports
 * threads.
 *
 * The FSM provides also asynchronous events that can be used to wait for
 * some events or states to occur.  The FSM events may be used as condition
 * variables and signallers.  The FSM events can safely be used in FSM
 * threads that are executed in real system threads.
 *
 * To synchronize machines that use FSM threads that are executed in real
 * system threads the SILC Mutex API (silcmutex.h) may be used.  Normal
 * multi-threaded coding conventions apply when programming with real FSM
 * threads.  If the FSM threads are not real system threads, synchronization
 * is not required.
 *
 ***/

#ifndef SILCFSM_H
#define SILCFSM_H

/****s* silcutil/SilcFSMAPI/SilcFSM
 *
 * NAME
 *
 *    typedef struct SilcFSMObject *SilcFSM;
 *
 * DESCRIPTION
 *
 *    The actual FSM context and is allocated with silc_fsm_alloc and
 *    given as argument to all silc_fsm_* functions.  It is freed by
 *    silc_fsm_free function.  It is also possible to use pre-allocated
 *    FSM context by using SilcFSMStruct instead of SilcFSM.
 *
 ***/
typedef struct SilcFSMObject *SilcFSM;

/****s* silcutil/SilcFSMAPI/SilcFSMStruct
 *
 * NAME
 *
 *    typedef struct SilcFSMObject SilcFSMStruct;
 *
 * DESCRIPTION
 *
 *    The actual FSM context and can be used as pre-allocated FSM context,
 *    instead of SilcFSM context.  This context is initialized with the
 *    silc_fsm_init function.  It need not be uninitialized.
 *
 ***/
typedef struct SilcFSMObject SilcFSMStruct;

/****s* silcutil/SilcFSMAPI/SilcFSMThread
 *
 * NAME
 *
 *    typedef struct SilcFSMObject *SilcFSMThread;
 *
 * DESCRIPTION
 *
 *    FSM thread context.  The SILC FSM supports threads, virtual machine
 *    threads (inside FSM) and actual real system threads if platorm
 *    supports them.  In a complex machine certain complex operations may
 *    be desired to execute in a thread.  The SilcFSMThread is allocated
 *    by silc_fsm_thread_alloc and feed by silc_fsm_free.  It is also
 *    possible to use pre-allocated thread by using SilcFSMThreadStruct
 *    instead of SilcFSMThread.
 *
 ***/
typedef struct SilcFSMObject *SilcFSMThread;

/****s* silcutil/SilcFSMAPI/SilcFSM
 *
 * NAME
 *
 *    typedef struct SilcFSMObject SilcFSMThreadStruct;
 *
 * DESCRIPTION
 *
 *    FSM thread context and can be used as a pre-allocated FSM thread context,
 *    instead of SilcFSMThread context.  This context is initialized with the
 *    silc_fsm_thread_init function.  It need not be uninitialized.
 *
 ***/
typedef struct SilcFSMObject SilcFSMThreadStruct;

/****d* silcutil/SilcFSMAPI/SILC_FSM_CONTINUE
 *
 * NAME
 *
 *    #define SILC_FSM_CONTINUE ...
 *
 * DESCRIPTION
 *
 *    Moves to next state synchronously.  This type is used is returned
 *    from state functions to immediately move to next state.
 *
 * EXAMPLE
 *
 *    SILC_FSM_STATE(silc_foo_state)
 *    {
 *      ...
 *
 *      // Move to next state now
 *      silc_fsm_next(fsm, silc_foo_next_state);
 *      return SILC_FSM_CONTINUE;
 *    }
 *
 ***/
#if defined(SILC_DEBUG)
#define SILC_FSM_CONTINUE \
  fsm->next_state(fsm, fsm->fsm_context, fsm->state_context);
#else
#define SILC_FSM_CONTINUE SILC_FSM_ST_CONTINUE;
#endif /* SILC_DEBUG */

/****d* silcutil/SilcFSMAPI/SILC_FSM_YIELD
 *
 * NAME
 *
 *    #define SILC_FSM_YIELD ...
 *
 * DESCRIPTION
 *
 *    Moves to next state through the machine scheduler.  Other threads
 *    running in the machine will get running time with SILC_FSM_YIELD.
 *    When using real threads, using SILC_FSM_YIELD is usually unnecessary.
 *    This type is returned in the state function.
 *
 ***/
#define SILC_FSM_YIELD SILC_FSM_ST_YIELD;

/****d* silcutil/SilcFSMAPI/SILC_FSM_WAIT
 *
 * NAME
 *
 *    #define SILC_FSM_WAIT ...
 *
 * DESCRIPTION
 *
 *    Suspends the machine or thread until it is awaken.  This is used
 *    when asynchronous call is made or timer is set, or something else
 *    that requires waiting.  This type is returned in the state function.
 *
 ***/
#define SILC_FSM_WAIT SILC_FSM_ST_WAIT

/****d* silcutil/SilcFSMAPI/SILC_FSM_FINISH
 *
 * NAME
 *
 *    #define SILC_FSM_FINISH ...
 *
 * DESCRIPTION
 *
 *    Finishes the machine or thread and calls its destructor, if defined.
 *    If the machine is finished when it has running threads the machine
 *    will fatally fail.  User must always finish the threads before
 *    finishing the machine.  This type is returned in the state function.
 *
 ***/
#define SILC_FSM_FINISH SILC_FSM_ST_FINISH

/****f* silcutil/SilcFSMAPI/SilcFSMDestructor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcFSMDestructor)(SilcFSM fsm, void *fsm_context,
 *                                      void *destructor_context);
 *
 * DESCRIPTION
 *
 *    The destructor callback that was set in silc_fsm_alloc or in
 *    silc_fsm_init function.  It will be called when a state function
 *    returns SILC_FSM_FINISH.  This function will be called through
 *    the scheduler; it will not be called immediately after the state
 *    function returns SILC_FSM_FINISH, but will be called later.  The
 *    `fsm' can be freed in this function.
 *
 ***/
typedef void (*SilcFSMDestructor)(SilcFSM fsm, void *fsm_context,
                                  void *destructor_context);

/****f* silcutil/SilcFSMAPI/SilcFSMThreadDestructor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcFSMThreadDestructor)(SilcFSMThread thread,
 *                                            void *thread_context,
 *                                            void *destructor_context);
 *
 * DESCRIPTION
 *
 *    The destructor callback that was set in silc_fsm_thread_alloc or in
 *    silc_fsm_thread_init function.  It will be called when a state function
 *    returns SILC_FSM_FINISH.  This function will be called through the
 *    scheduler; it will not be called immediately after the state function
 *    returns SILC_FSM_FINISH, but will be called later.  The `thread' can
 *    be freed in this function.
 *
 * NOTES
 *
 *    Even if the `thread' was executed in real system thread, this callback
 *    is always received in the main machine thread, not in the created
 *    thread.
 *
 ***/
typedef void (*SilcFSMThreadDestructor)(SilcFSMThread thread,
					void *thread_context,
					void *destructor_context);

/****d* silcutil/SilcFSMAPI/SILC_FSM_STATE
 *
 * NAME
 *
 *    #define SILC_FSM_STATE(name)
 *
 * DESCRIPTION
 *
 *    This macro is used to declare an FSM state function.  The `fsm' is
 *    the SilcFSM or SilcFSMThread context, the `fsm_context' is the context
 *    given as argument to silc_fsm_alloc, silc_fsm_init, silc_fsm_thread_init,
 *    or silc_fsm_thread_alloc function.  The `state_context' is the optional
 *    state specific context set with silc_fsm_set_state_context function.
 *
 * SOURCE
 */
#define SILC_FSM_STATE(name)						\
int name(struct SilcFSMObject *fsm, void *fsm_context, void *state_context)
/***/

/* State function callback */
typedef int (*SilcFSMStateCallback)(struct SilcFSMObject *fsm,
				    void *fsm_context,
				    void *state_context);

/****d* silcutil/SilcFSMAPI/SILC_FSM_CALL
 *
 * NAME
 *
 *    SILC_FSM_CALL(function)
 *
 * DESCRIPTION
 *
 *    Macro used to call asynchronous calls from state function.  If the
 *    call is not really asynchronous then this will cause the machine to
 *    directly proceed to next state.  If the call is truly asynchronous
 *    then this will set the machine to wait state.  The silc_fsm_next
 *    must be called before this macro, so that the next state is set.
 *
 * NOTES
 *
 *    The state function returns in this macro.
 *
 * EXAMPLE
 *
 *    // Simple example
 *    silc_fsm_next(fsm, some_next_state);
 *    SILC_FSM_CALL(silc_some_async_call(server, some_callback, context));
 *
 *    // More complex example
 *    silc_fsm_next(fsm, some_next_state);
 *    SILC_FSM_CALL((some_context->operation =
 *                   silc_some_async_call(server, some_callback, context)));
 *
 ***/
#define SILC_FSM_CALL(function)			\
do {						\
  assert(!silc_fsm_set_call(fsm, TRUE));	\
  function;					\
  if (!silc_fsm_set_call(fsm, FALSE))		\
    return SILC_FSM_CONTINUE;			\
  return SILC_FSM_WAIT;				\
} while(0)

/****d* silcutil/SilcFSMAPI/SILC_FSM_CALL_CONTINUE
 *
 * NAME
 *
 *    SILC_FSM_CALL_CONTINUE(fsm)
 *
 * DESCRIPTION
 *
 *    Macro used to proceed after asynchornous call.  This is called in the
 *    callback of the asynchronous call to continue in the state machine.
 *
 * EXAMPLE
 *
 *    void some_callback(void *context) {
 *      SilcFSM fsm = context;
 *      ...
 *      // Continue to the next state
 *      SILC_FSM_CALL_CONTINUE(fsm);
 *    }
 *
 ***/
#define SILC_FSM_CALL_CONTINUE(fsm)		\
do {						\
  if (!silc_fsm_set_call(fsm, FALSE))		\
    silc_fsm_continue(fsm);			\
} while(0)

/****d* silcutil/SilcFSMAPI/SILC_FSM_CALL_CONTINUE_SYNC
 *
 * NAME
 *
 *    SILC_FSM_CALL_CONTINUE_SYNC(fsm)
 *
 * DESCRIPTION
 *
 *    Macro used to proceed after asynchornous call.  This is called in the
 *    callback of the asynchronous call to continue in the state machine.
 *    This continues to the next state synchronously, not through the
 *    scheduler.
 *
 * EXAMPLE
 *
 *    void some_callback(void *context) {
 *      SilcFSM fsm = context;
 *      ...
 *      // Continue to the next state immediately
 *      SILC_FSM_CALL_CONTINUE_SYNC(fsm);
 *    }
 *
 ***/
#define SILC_FSM_CALL_CONTINUE_SYNC(fsm)	\
do {						\
  if (!silc_fsm_set_call(fsm, FALSE))		\
    silc_fsm_continue_sync(fsm);		\
} while(0)

/****d* silcutil/SilcFSMAPI/SILC_FSM_THREAD_WAIT
 *
 * NAME
 *
 *    SILC_FSM_THREAD_WAIT(thread)
 *
 * DESCRIPTION
 *
 *    Macro used to wait for the `thread' to terminate.  The machine or
 *    thread will be suspended while it is waiting for the thread to
 *    terminate.
 *
 * NOTES
 *
 *    The state function returns in this macro.
 *
 *    This macro is the only way to safely make sure that the thread has
 *    terminated by the time FSM continues from the waiting state.  Using
 *    FSM events to signal from the thread before SILC_FSM_FINISH is returned
 *    works with normal FSM threads, but especially with real system threads
 *    it does not guarantee that the FSM won't continue before the thread has
 *    actually terminated.  Usually this is not a problem, but it can be a
 *    problem if the FSM is waiting to be freed.  In this case using this
 *    macro is strongly recommended.
 *
 ***/
#define SILC_FSM_THREAD_WAIT(thread)		\
do {						\
  silc_fsm_thread_wait(fsm, thread);		\
  return SILC_FSM_WAIT;				\
} while(0)

/****f* silcutil/SilcFSMAPI/silc_fsm_alloc
 *
 * SYNOPSIS
 *
 *    SilcFSM silc_fsm_alloc(void *fsm_context,
 *                           SilcFSMDestructor destructor,
 *                           void *destructor_context,
 *                           SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Allocates SILC Finite State Machine context.  The `destructor' with
 *    `destructor_context' will be called when the machines finishes.  The
 *    caller must free the returned context with silc_fsm_free.  The
 *    `fsm_context' is delivered to every FSM state function.  The `schedule'
 *    is the caller's scheduler and the FSM will be run in the scheduler.
 *
 * EXAMPLE
 *
 *    SilcAsyncOperation silc_async_call(Callback callback, void *cb_context)
 *    {
 *      SilcAsyncOperation op;
 *      SilcFSM fsm;
 *      ...
 *
 *      // Allocate async operation so that caller can control us, like abort
 *      op = silc_async_alloc(silc_async_call_abort, NULL, ourcontext);
 *
 *      // Start FSM
 *      fsm = silc_fsm_alloc(ourcontext, fsm_destructor, ourcontext,
 *                           schedule);
 *      silc_fsm_start(fsm, first_state);
 *      ...
 *
 *      // Return async operation for upper layer
 *      return op;
 *    }
 *
 ***/
SilcFSM silc_fsm_alloc(void *fsm_context,
                       SilcFSMDestructor destructor,
                       void *destructor_context,
                       SilcSchedule schedule);

/****f* silcutil/SilcFSMAPI/silc_fsm_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_fsm_init(SilcFSM fsm,
 *                           void *fsm_context,
 *                           SilcFSMDestructor destructor,
 *                           void *destructor_context,
 *                           SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Initializes a pre-allocated SilcFSM context.  This call is equivalent
 *    to silc_fsm_alloc except that this takes the pre-allocated context
 *    as argument.  The silc_fsm_free must not be called if this was called.
 *    Returns TRUE if the initialization is Ok or FALSE if error occurred.
 *    This function does not allocate any memory.  The `schedule' is the
 *    caller's scheduler and the FSM will be run in the scheduler.
 *
 * EXAMPLE
 *
 *    SilcFSMStruct fsm;
 *
 *    silc_fsm_init(&fsm, application, fsm_destructor, application, schedule);
 *    silc_fsm_start(&fsm, first_state);
 *
 ***/
SilcBool silc_fsm_init(SilcFSM fsm,
		       void *fsm_context,
                       SilcFSMDestructor destructor,
                       void *destructor_context,
                       SilcSchedule schedule);

/****f* silcutil/SilcFSMAPI/silc_fsm_thread_alloc
 *
 * SYNOPSIS
 *
 *    SilcFSMThread silc_fsm_thread_alloc(SilcFSM fsm,
 *                                        void *thread_context,
 *                                        SilcFSMThreadDestructor destructor,
 *                                        void *destructor_context,
 *                                        SilcBool real_thread);
 *
 * DESCRIPTION
 *
 *    Allocates FSM thread context.  The thread will be executed in the
 *    FSM machine indicated by `fsm'.  The caller must free the returned
 *    thread context with silc_fsm_free.  If the 'real_thread' is TRUE
 *    then the thread will actually be executed in real thread, if platform
 *    supports them.  The `thread_context' is delivered to every state
 *    function in the thread.
 *
 * NOTES
 *
 *    If the system does not support threads, then this function will revert
 *    back to normal FSM threads.
 *
 *    If the `real_thread' is TRUE then FSM will allocate new SilcSchedule
 *    for the FSM thread. If you need scheduler in the real thread it is
 *    strongly recommended that you use the SilcSchedule that is allocated
 *    for the thread.  You can retrieve the SilcSchedule from the thread
 *    using silc_fsm_get_schedule function.  Note that, the allocated
 *    SilcSchedule will become invalid after the thread finishes.
 *
 *    If `real_thread' is FALSE the silc_fsm_get_schedule will return
 *    the SilcSchedule that was originally given to silc_fsm_alloc or
 *    silc_fsm_init.
 *
 * EXAMPLE
 *
 *    SILC_FSM_STATE(silc_foo_state)
 *    {
 *      SilcFSMThread thread;
 *      ...
 *
 *      // Execute the route lookup in thread
 *      thread = silc_fsm_thread_alloc(fsm, fsm_context, NULL, NULL, FALSE);
 *      silc_fsm_start(thread, silc_route_lookup_start);
 *
 *      // Wait here for the thread to terminate. Set the state where to go
 *      // after the thread has terminated.
 *      silc_fsm_next(fsm, silc_foo_route_lookup_finished);
 *      SILC_FSM_THREAD_WAIT(thread);
 *    }
 *
 ***/
SilcFSMThread silc_fsm_thread_alloc(SilcFSM fsm,
				    void *thread_context,
				    SilcFSMThreadDestructor destructor,
				    void *destructor_context,
				    SilcBool real_thread);

/****f* silcutil/SilcFSMAPI/silc_fsm_thread_init
 *
 * SYNOPSIS
 *
 *    void silc_fsm_thread_init(SilcFSMThread thread,
 *                              SilcFSM fsm,
 *                              void *thread_context,
 *                              SilcFSMThreadDestructor destructor,
 *                              void *destructor_context,
 *                              SilcBool real_thread);
 *
 * DESCRIPTION
 *
 *    Initializes a pre-allocated SilcFSMThread context.  This call is
 *    equivalent to silc_fsm_thread_alloc except that this takes the
 *    pre-allocated context as argument.  The silc_fsm_free must not be
 *    called if this was called.  If the `real_thread' is TRUE then the
 *    thread will actually be executed in real thread, if platform supports
 *    them.
 *
 * NOTES
 *
 *    See the notes from the silc_fsm_thread_alloc.
 *
 * EXAMPLE
 *
 *    SilcFSMThreadStruct thread;
 *
 *    silc_fsm_thread_init(&thread, fsm, application, NULL, NULL, FALSE);
 *    silc_fsm_start(&thread, first_state);
 *
 ***/
void silc_fsm_thread_init(SilcFSMThread thread,
			  SilcFSM fsm,
			  void *thread_context,
			  SilcFSMThreadDestructor destructor,
			  void *destructor_context,
			  SilcBool real_thread);

/****f* silcutil/SilcFSMAPI/silc_fsm_free
 *
 * SYNOPSIS
 *
 *    void silc_fsm_free(void *fsm);
 *
 * DESCRIPTION
 *
 *    Free the SILC FSM context that was allocated with silc_fsm_alloc,
 *    or free the SILC FSM thread context that was allocated with
 *    silc_fsm_thread_alloc.  This function is used with both SilcFSM
 *    and SilcFSMThread contexts.
 *
 * NOTES
 *
 *    When freeing FSM, it must not have any active threads.
 *
 ***/
void silc_fsm_free(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_start
 *
 * SYNOPSIS
 *
 *    void silc_fsm_start(void *fsm, SilcFSMStateCallback start_state);
 *
 * DESCRIPTION
 *
 *    This function must be called after the SILC FSM context was created.
 *    This actually starts the state machine.  Note that, the machine is
 *    started later after this function returns.  The `start_state' is the
 *    state where the machine or thread is started.  This function is used
 *    with both SilcFSM and SilcFSMThread contexts.
 *
 * EXAMPLE
 *
 *    SilcFSM fsm;
 *
 *    fsm = silc_fsm_alloc(context, destructor, context, schedule);
 *    silc_fsm_start(fsm, first_state);
 *
 ***/
void silc_fsm_start(void *fsm, SilcFSMStateCallback start_state);

/****f* silcutil/SilcFSMAPI/silc_fsm_start_sync
 *
 * SYNOPSIS
 *
 *    void silc_fsm_start_sync(void *fsm, SilcFSMStateCallback start_state);
 *
 * DESCRIPTION
 *
 *    This function is same as silc_fsm_start, except that the FSM will
 *    be started immediately inside this function.  After this function
 *    returns the `start_state' has already been executed.  If the machine
 *    is completely synchronous (no waiting used in the machine) then
 *    the machine will have finished once this function returns.  Also
 *    note that if the machine is completely synchronous the destructor
 *    will also be called from inside this function.  This function is used
 *    with both SilcFSM and SilcFSMThread contexts.
 *
 ***/
void silc_fsm_start_sync(void *fsm, SilcFSMStateCallback start_state);

/****f* silcutil/SilcFSMAPI/silc_fsm_next
 *
 * SYNOPSIS
 *
 *    void silc_fsm_next(void *fsm, SilcFSMStateCallback next_state);
 *
 * DESCRIPTION
 *
 *    Set the next state to be executed.  If the state function that
 *    call this function returns SILC_FSM_CONTINUE, the `next_state'
 *    will be executed immediately.  If it returns SILC_FSM_YIELD it
 *    yields the thread and the `next_state' will be run after other
 *    threads have run first.  This function must always be used to set
 *    the next state in the machine or thread.  This function is used
 *    with both SilcFSM and SilcFSMThread contexts.
 *
 * EXAMPLE
 *
 *    // Move to next state
 *    silc_fsm_next(fsm, next_state);
 *    return SILC_FSM_CONTINUE;
 *
 ***/
void silc_fsm_next(void *fsm, SilcFSMStateCallback next_state);

/****f* silcutil/SilcFSMAPI/silc_fsm_next_later
 *
 * SYNOPSIS
 *
 *    void silc_fsm_next_later(void *fsm, SilcFSMStateCallback next_state,
 *                             SilcUInt32 seconds, SilcUInt32 useconds);
 *
 * DESCRIPTION
 *
 *    Set the next state to be executed later, at the specified time.
 *    The SILC_FSM_WAIT must be returned in the state function if this
 *    function is called.  If any other state is returned machine operation
 *    is undefined.  The machine or thread will move to `next_state' after
 *    the specified timeout.  This function is used with both SilcFSM and
 *    SilcFSMThread contexts.
 *
 * NOTES
 *
 *    If both `seconds' and `useconds' are 0, the effect is same as calling
 *    silc_fsm_next function, and SILC_FSM_CONTINUE must be returned.
 *
 *    If silc_fsm_continue or silc_fsm_continue_sync is called while the
 *    machine or thread is in SILC_FSM_WAIT state the timeout is automatically
 *    canceled and the state moves to the next state.
 *
 * EXAMPLE
 *
 *    // Move to next state after 10 seconds
 *    silc_fsm_next_later(fsm, next_state, 10, 0);
 *    return SILC_FSM_WAIT;
 *
 ***/
void silc_fsm_next_later(void *fsm, SilcFSMStateCallback next_state,
			 SilcUInt32 seconds, SilcUInt32 useconds);

/****f* silcutil/SilcFSMAPI/silc_fsm_continue
 *
 * SYNOPSIS
 *
 *    void silc_fsm_continue(void *fsm);
 *
 * DESCRIPTION
 *
 *    Continues in the state machine from a SILC_FSM_WAIT state.  This can
 *    be called from outside waiting FSM to continue to the next state.
 *    This function can be used instead of SILC_FSM_CALL_CONTINUE macro
 *    in case the SILC_FSM_CALL was not used.  This must not be used if
 *    SILC_FSM_CALL was used.  This function is used with both SilcFSM and
 *    SilcFSMThread contexts.
 *
 ***/
void silc_fsm_continue(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_continue_sync
 *
 * SYNOPSIS
 *
 *    void silc_fsm_continue_sync(void *fsm);
 *
 * DESCRIPTION
 *
 *    Continues immediately in the state machine from a SILC_FSM_WAIT state.
 *    This can be called from outside waiting FSM to immediately continue to
 *    the next state.  This function can be used instead of the
 *    SILC_FSM_CALL_CONTINUE_SYNC macro in case the SILC_FSM_CALL was not used.
 *    This must not be used if SILC_FSM_CALL was used.  This function is used
 *    with both SilcFSM and SilcFSMThread contexts.
 *
 ***/
void silc_fsm_continue_sync(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_finish
 *
 * SYNOPSIS
 *
 *    void silc_fsm_finish(void *fsm);
 *
 * DESCRIPTION
 *
 *    Finishes the `fsm'.  This function may be used in case the FSM
 *    needs to be finished outside FSM states.  Usually FSM is finished
 *    by returning SILC_FSM_FINISH from the state, but if this is not
 *    possible this function may be called.  This function is used with
 *    both SilcFSM and SilcFSMThread contexts.
 *
 *    If the `fsm' is a machine and it has running threads, the machine
 *    will fatally fail.  The caller must first finish the threads and
 *    then the machine.
 *
 ***/
void silc_fsm_finish(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_set_context
 *
 * SYNOPSIS
 *
 *    void silc_fsm_set_context(void *fsm, void *fsm_context);
 *
 * DESCRIPTION
 *
 *    Set new context for the `fsm'.  This function can be used to change
 *    the context inside the `fsm', if needed.  This function is used with
 *    both SilcFSM and SilcFSMThread contexts.  The context is the
 *    `fsm_context' in the state function (SILC_FSM_STATE).
 *
 ***/
void silc_fsm_set_context(void *fsm, void *fsm_context);

/****f* silcutil/SilcFSMAPI/silc_fsm_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_fsm_get_context(void *fsm);
 *
 * DESCRIPTION
 *
 *    Returns the context associated with the `fsm'.  It is the context that
 *    was given to silc_fsm_alloc, silc_fsm_init, silc_fsm_thread_alloc or
 *    silc_fsm_thread_init.  This function is used with both SilcFSM and
 *    SilcFSMThread contexts.
 *
 ***/
void *silc_fsm_get_context(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_set_state_context
 *
 * SYNOPSIS
 *
 *    void silc_fsm_set_state_context(void *fsm, void *state_context);
 *
 * DESCRIPTION
 *
 *    Set's a state specific context for the `fsm'.  This function can be
 *    used to change the state context inside the `fsm', if needed.  This
 *    function is used with both SilcFSM and SilcFSMThread contexts.  The
 *    context is the `state_context' in the state function (SILC_FSM_STATE).
 *
 ***/
void silc_fsm_set_state_context(void *fsm, void *state_context);

/****f* silcutil/SilcFSMAPI/silc_fsm_get_state_context
 *
 * SYNOPSIS
 *
 *    void *silc_fsm_get_state_context(void *fsm);
 *
 * DESCRIPTION
 *
 *    Returns the state context associated with the `fsm'.  It is the context
 *    that was set with silc_fsm_set_state_context function.  This function
 *    is used with both SilcFSM and SilcFSMThread contexts.
 *
 ***/
void *silc_fsm_get_state_context(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_get_schedule
 *
 * SYNOPSIS
 *
 *    SilcSchedule silc_fsm_get_schedule(void *fsm);
 *
 * DESCRIPTION
 *
 *    Returns the SilcSchedule that has been associated with the `fsm'.
 *    If caller needs scheduler it may retrieve it with this function.  This
 *    function is used with both SilcFSM and SilcFSMThread contexts.
 *
 *    If the `fsm' is thread and real system threads are being used, and this
 *    is called from the thread, it will return the SilcSchedule that was
 *    allocated by the FSM for the thread.  It is strongly recommended to
 *    use this SilcSchedule if you are using real threads, and you need
 *    scheduler in the thread.  Note that, once the thread finishes the
 *    returned SilcSchedule becomes invalid.
 *
 *    In other times this returns the SilcSchedule pointer that was given
 *    to silc_fsm_alloc or silc_fsm_init.
 *
 ***/
SilcSchedule silc_fsm_get_schedule(void *fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_get_machine
 *
 * SYNOPSIS
 *
 *    SilcFSM silc_fsm_get_machine(SilcFSMThread thread);
 *
 * DESCRIPTION
 *
 *    Returns the machine from the FSM thread indicated by `thread'.
 *
 ***/
SilcFSM silc_fsm_get_machine(SilcFSMThread thread);

/****f* silcutil/SilcFSMAPI/silc_fsm_is_started
 *
 * SYNOPSIS
 *
 *    SilcBool silc_fsm_is_started(void *fsm);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the machine or thread `fsm' has been started and has
 *    not been finished yet.  This function is used with both SilcFSM and
 *    SilcFSMThread contexts.
 *
 ***/
SilcBool silc_fsm_is_started(void *fsm);

/* FSM Events */

/****s* silcutil/SilcFSMAPI/SilcFSMEvent
 *
 * NAME
 *
 *    typedef struct SilcFSMEventObject *SilcFSMEvent;
 *
 * DESCRIPTION
 *
 *    The FSM event context allocated with silc_fsm_event_alloc.  The
 *    caller must free it with silc_fsm_event_free.  It is also possible
 *    to use pre-allocated SilcFSMEventStruct instead of SilcFSMEvent context.
 *
 ***/
typedef struct SilcFSMEventObject *SilcFSMEvent;

/****s* silcutil/SilcFSMAPI/SilcFSMEventStruct
 *
 * NAME
 *
 *    typedef struct SilcFSMEventObject SilcFSMEventStruct;
 *
 * DESCRIPTION
 *
 *    The FSM event context that can be used as pre-allocated context.
 *    It is initialized with silc_fsm_event_init.  It need not be
 *    uninitialized.
 *
 ***/
typedef struct SilcFSMEventObject SilcFSMEventStruct;

/****f* silcutil/SilcFSMAPI/silc_fsm_event_alloc
 *
 * SYNOPSIS
 *
 *    SilcFSMEvent silc_fsm_event_alloc(SilcFSM fsm);
 *
 * DESCRIPTION
 *
 *    Allocates asynchronous FSM event.  FSM events are asynchronous events
 *    that can be waited and signalled.  They can be used as condition
 *    variables and signallers.  They can be used for example to wait that
 *    some event happens, some thread moves to a specific state or similar.
 *    The FSM Events may also be used in FSM threads that are executed in
 *    real system threads.  It is safe to wait and signal the event from
 *    threads.
 *
 *    Use the macros SILC_FSM_EVENT_WAIT and SILC_FSM_EVENT_TIMEDWAIT to wait
 *    for the event.  Use the SILC_FSM_EVENT_SIGNAL macro to signal all the
 *    waiters.
 *
 ***/
SilcFSMEvent silc_fsm_event_alloc(SilcFSM fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_event_init
 *
 * SYNOPSIS
 *
 *    void silc_fsm_event_init(SilcFSMEvent event, SilcFSM fsm);
 *
 * DESCRIPTION
 *
 *    Initializes a pre-allocates FSM event context.  This call is
 *    equivalent to silc_fsm_event_alloc except this use the pre-allocated
 *    context.  This fuction does not allocate any memory.
 *
 ***/
void silc_fsm_event_init(SilcFSMEvent event, SilcFSM fsm);

/****f* silcutil/SilcFSMAPI/silc_fsm_event_free
 *
 * SYNOPSIS
 *
 *    void silc_fsm_event_free(SilcFSMEvent event);
 *
 * DESCRIPTION
 *
 *    Free the event allocated by silc_fsm_event_alloc function.
 *
 ***/
void silc_fsm_event_free(SilcFSMEvent event);

/****d* silcutil/SilcFSMAPI/SILC_FSM_EVENT_WAIT
 *
 * NAME
 *
 *    SILC_FSM_EVENT_WAIT(event)
 *
 * DESCRIPTION
 *
 *    Macro used to wait for the `event' to be signalled.  The machine
 *    or thread will be suspended while it is waiting for the event.
 *    This macro can only be used in FSM state functions.  When the
 *    event is signalled the FSM will re-enter the current state (or
 *    state that was set with silc_fsm_next before waiting).
 *
 * EXAMPLE
 *
 *    // Signalling example
 *    ctx->async_event = silc_fsm_event_alloc(fsm);
 *    ...
 *
 *    SILC_FSM_STATE(silc_foo_state)
 *    {
 *      ...
 *
 *      // Wait here for async call to complete
 *      SILC_FSM_EVENT_WAIT(ctx->async_event);
 *
 *      // Async call completed
 *      if (ctx->async_success == FALSE)
 *        fatal(error);
 *      ...
 *    }
 *
 ***/
#define SILC_FSM_EVENT_WAIT(event)		\
do {						\
  if (silc_fsm_event_wait(event, fsm) == 0)	\
    return SILC_FSM_WAIT;			\
} while(0)

/****d* silcutil/SilcFSMAPI/SILC_FSM_EVENT_TIMEDWAIT
 *
 * NAME
 *
 *    SILC_FSM_EVENT_TIMEDWAIT(event, seconds, useconds, timedout)
 *
 * DESCRIPTION
 *
 *    Macro used to wait for the `event' to be signalled, or until
 *    the timeout specified by `seconds' and `useconds' has elapsed.  If
 *    the timeout occurs before the event is signalled, the machine
 *    will wakeup.  The `timedout' is SilcBool pointer and if it is
 *    non-NULL indication of whether timeout occurred or not is saved to
 *    the pointer.  This macro can only be used in FSM state functions.
 *    When the event is signalled or timedout the FSM will re-enter
 *    the current state (or state that was set with silc_fsm_next before
 *    waiting).
 *
 * EXAMPLE
 *
 *    SILC_FSM_STATE(silc_foo_state)
 *    {
 *      SilcBool timedout;
 *      ...
 *
 *      // Wait here for async call to complete, or 10 seconds for timeout
 *      SILC_FSM_EVENT_TIMEDWAIT(ctx->async_event, 10, 0, &timedout);
 *
 *      // See if timeout occurred
 *      if (timedout == TRUE)
 *        fatal(error);
 *
 *      // Async call completed
 *      if (ctx->async_success == FALSE)
 *        fatal(error);
 *      ...
 *    }
 *
 ***/
#define SILC_FSM_EVENT_TIMEDWAIT(event, seconds, useconds, ret_to)	\
do {									\
  if (silc_fsm_event_timedwait(event, fsm, seconds, useconds, ret_to) == 0) \
    return SILC_FSM_WAIT;						\
} while(0)

/****f* silcutil/SilcFSMAPI/SILC_FSM_EVENT_SIGNAL
 *
 * SYNOPSIS
 *
 *    SILC_FSM_EVENT_SIGNAL(event)
 *
 * DESCRIPTION
 *
 *    Signals the `event' and awakens everybody that are waiting for this
 *    event.  This macro never blocks.  It can be safely called at any place
 *    in state function and in asynchronous callbacks or other functions.
 *
 * EXAMPLE
 *
 *    SILC_FSM_STATE(silc_foo_async_completion)
 *    {
 *      ...
 *
 *      // Notify all waiters
 *      ctx->async_success = TRUE;
 *      SILC_FSM_EVENT_SIGNAL(ctx->async_event);
 *      ...
 *    }
 *
 ***/
#define SILC_FSM_EVENT_SIGNAL(event)		\
do {						\
  silc_fsm_event_signal(event);			\
} while(0)

#include "silcfsm_i.h"

#endif /* SILCFSM_H */
