/*

  silcfsm_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCFSM_I_H
#define SILCFSM_I_H

#ifndef SILCFSM_H
#error "Do not include this header directly"
#endif

/* FSM state status */
typedef enum {
  SILC_FSM_ST_CONTINUE,	     /* Continue immediately to next state */
  SILC_FSM_ST_YIELD,	     /* Continue to next state through scheduler */
  SILC_FSM_ST_WAIT,	     /* Wait for some async call or timeout */
  SILC_FSM_ST_FINISH,	     /* Finish state machine and call destructor
				through scheduler */
} SilcFSMStatus;

/* Event structure, holds list of FSM machines that are waiting for this
   event.  The SilcFSM has *next; pointer that is used with SilcList.
   Internally events act as semaphore counters. */
struct SilcFSMEventObject {
  SilcFSM fsm;			        /* Machine */
  SilcList waiters;			/* List of SilcFSM pointers */
  unsigned int value     : 21;		/* Current event semaphore value */
  unsigned int refcnt    : 10;		/* Reference counter */
  unsigned int allocated : 1;		/* Set if allocated */
};

/* FSM and FSM thread context */
struct SilcFSMObject {
  struct SilcFSMObject *next;
  void *fsm_context;		        /* Caller's context */
  SilcSchedule schedule;		/* Scheduler */
  SilcFSMEvent event;			/* Valid if waiting event timeout */
  SilcFSMStateCallback next_state;	/* Next state in machine */
  void *state_context;		        /* Extra state specific context */
  SilcFSMDestructor destructor;		/* Destructor */
  void *destructor_context;
  union {
    /* Machine */
    struct {
      SilcAtomic32 threads;		/* Number of threads */
      SilcMutex lock;		        /* Lock, valid if using real threads */
    } m;

    /* Thread */
    struct {
      struct SilcFSMObject *fsm;	/* Machine */
      SilcFSMEvent event;               /* Event for waiting termination */
    } t;
  } u;
  unsigned int thread           : 1;	/* Set if this is thread */
  unsigned int real_thread      : 1;    /* Set if to use real threads */
  unsigned int async_call       : 1;    /* Set if called real async call */
  unsigned int finished         : 1;    /* Set if SILC_FSM_FINISH returned */
  unsigned int event_timedout   : 1;    /* Set if waiting event timedout */
  unsigned int synchronous      : 1;    /* Set if silc_fsm_start_sync called */
  unsigned int next_later       : 1;    /* Set if silc_fsm_next_later called */
  unsigned int started          : 1;    /* Set when started and not finished */
};

/* Event signal context */
typedef struct {
  SilcFSMEvent event;		        /* Event */
  SilcFSM fsm;				/* Signalled FSM */
} *SilcFSMEventSignal;

/* Used internally by the SILC_FSM_CALL macros to detect whether async
   call is really async or not. */
static inline
SilcBool silc_fsm_set_call(struct SilcFSMObject *fsm, SilcBool async_call)
{
  SilcBool old = fsm->async_call;
  fsm->async_call = async_call;
  return old;
}

/* Wait for thread to terminate */
SilcBool silc_fsm_thread_wait(void *fsm, void *thread);

/* Events */
SilcUInt32 silc_fsm_event_wait(SilcFSMEvent event, void *fsm);
SilcUInt32 silc_fsm_event_timedwait(SilcFSMEvent event, void *fsm,
				    SilcUInt32 seconds, SilcUInt32 useconds,
				    SilcBool *ret_to);
void silc_fsm_event_signal(SilcFSMEvent event);

#endif /* SILCFSM_I_H */
