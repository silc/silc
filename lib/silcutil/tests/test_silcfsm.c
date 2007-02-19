/* SILC FSM tests */

#include "silc.h"
#include "silcfsm.h"

typedef void (*Callback)(void *context);

#define NUM_THREADS 200

typedef struct FooStruct *Foo;

typedef struct {
  SilcFSMThreadStruct thread;
  SilcFSMEventStruct sema;
  SilcBool finished;
  int rounds;
  Foo f;
} T;

struct FooStruct {
  SilcBool error;
  SilcFSM fsm;
  SilcFSMThreadStruct thread;
  int timeout;
  SilcFSMEventStruct sema;
  SilcFSMEventStruct wait2;
  SilcSchedule schedule;
  Callback cb;
  void *cb_context;
  T threads[NUM_THREADS];
  T threads2[NUM_THREADS];
  int c;
  int got_wait1 : 1;
  int got_wait2 : 1;
};

SILC_FSM_STATE(test_st_start);
SILC_FSM_STATE(test_st_second);
SILC_FSM_STATE(test_st_second_timeout);
SILC_FSM_STATE(test_st_third);
SILC_FSM_STATE(test_st_fourth);
SILC_FSM_STATE(test_st_fifth);
SILC_FSM_STATE(test_st_sixth);
SILC_FSM_STATE(test_st_seventh);
SILC_FSM_STATE(test_st_eighth);
SILC_FSM_STATE(test_st_ninth);
SILC_FSM_STATE(test_st_tenth);
SILC_FSM_STATE(test_st_finish);

SILC_FSM_STATE(test_st_wait1);
SILC_FSM_STATE(test_st_wait2);
SILC_FSM_STATE(test_st_signal1);
SILC_FSM_STATE(test_st_signal1_check);

SILC_FSM_STATE(test_thread_st_start);
SILC_FSM_STATE(test_thread_st_finish);
SILC_FSM_STATE(test_thread2_st_start);
SILC_FSM_STATE(test_thread2_st_finish);
SILC_FSM_STATE(test_thread3_st_start);
SILC_FSM_STATE(test_thread4_st_start);

static void test_fsm_destr(SilcFSMThread thread, void *thread_context,
			   void *user_context)
{
  silc_fsm_free(thread);
}

SILC_TASK_CALLBACK(async_call_timeout)
{
  Foo f = context;
  SILC_LOG_DEBUG(("Async call cb, continuing FSM"));
  f->cb(f->cb_context);
}

static void async_call(Callback cb, void *context)
{
  Foo f = context;
  f->cb = cb;
  f->cb_context = context;
  SILC_LOG_DEBUG(("Async call"));
  silc_schedule_task_add(f->schedule, 0, async_call_timeout, f, 0, 200000,
			 SILC_TASK_TIMEOUT);
}

SILC_FSM_STATE(test_st_start)
{
  SILC_LOG_DEBUG(("test_st_start"));

  /** Move to second state */
  SILC_LOG_DEBUG(("Move to next state"));
  silc_fsm_next(fsm, test_st_second);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_second)
{
  SILC_LOG_DEBUG(("test_st_second"));

  /** Move to second timeout state, timeout */
  SILC_LOG_DEBUG(("Move to next state with 2 second timeout"));
  silc_fsm_next_later(fsm, test_st_second_timeout, 2, 0);
  return SILC_FSM_WAIT;
}

SILC_TASK_CALLBACK(test_second_timeout)
{
  Foo f = context;
  SILC_LOG_DEBUG(("test_second_timeout"));

  SILC_LOG_DEBUG(("Interrupt 3 second wait and continue immediately"));
  f->c++;
  silc_fsm_next(f->fsm, test_st_third);
  silc_fsm_continue(f->fsm);
}

SILC_FSM_STATE(test_st_second_timeout)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_second_timeout"));

  /** Move to third state, timeout */
  SILC_LOG_DEBUG(("Move to next state with 3 second timeout"));
  SILC_LOG_DEBUG(("The timeout will be interrupted with silc_fsm_continue"));
  silc_fsm_next_later(fsm, test_st_third, 3, 0);
  silc_schedule_task_add_timeout(silc_fsm_get_schedule(fsm),
				 test_second_timeout, f, 2, 500000);
  return SILC_FSM_WAIT;
}

static void async_call_cb(void *context)
{
  Foo f = context;
  SILC_LOG_DEBUG(("Callback, continue to next state"));
  SILC_FSM_CALL_CONTINUE(f->fsm);
}

SILC_FSM_STATE(test_st_third)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_third"));

  f->c++;
  assert(f->c == 2);

  f->fsm = fsm;

  /** Wait async callback*/
  SILC_LOG_DEBUG(("Call async call"));
  silc_fsm_next(fsm, test_st_fourth);
  SILC_FSM_CALL(async_call(async_call_cb, f));
}

SILC_FSM_STATE(test_st_fourth)
{
  Foo f = fsm_context;
  SilcFSMThread t;

  SILC_LOG_DEBUG(("test_st_fourth"));

  f->timeout = 1;

  SILC_LOG_DEBUG(("Creating FSM thread"));
  silc_fsm_thread_init(&f->thread, fsm, f, NULL, NULL, FALSE);
  SILC_LOG_DEBUG(("Starting thread"));
  /*** Start thread */
  silc_fsm_start(&f->thread, test_thread_st_start);

  SILC_LOG_DEBUG(("Creating two waiting threads"));
  silc_fsm_event_init(&f->wait2, fsm);
  t = silc_fsm_thread_alloc(fsm, f, test_fsm_destr, NULL, FALSE);
  silc_fsm_start(t, test_st_wait1);
  t = silc_fsm_thread_alloc(fsm, f, test_fsm_destr, NULL, FALSE);
  silc_fsm_start(t, test_st_wait2);

  SILC_LOG_DEBUG(("Create signaller thread"));
  t = silc_fsm_thread_alloc(fsm, f, test_fsm_destr, NULL, FALSE);
  silc_fsm_start(t, test_st_signal1);

  /** Waiting thread to terminate */
  SILC_LOG_DEBUG(("Waiting for thread to terminate"));
  silc_fsm_next(fsm, test_st_fifth);
  SILC_FSM_THREAD_WAIT(&f->thread);
}

SILC_FSM_STATE(test_st_wait1)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("Waiter 1"));
  SILC_FSM_EVENT_WAIT(&f->wait2);
  SILC_LOG_DEBUG(("Waiter 1 signalled"));
  f->got_wait1 = 1;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_wait2)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("Waiter 2"));
  SILC_FSM_EVENT_WAIT(&f->wait2);
  SILC_LOG_DEBUG(("Waiter 2 signalled"));
  f->got_wait2 = 1;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_signal1)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("Signaller 1"));
  SILC_FSM_EVENT_SIGNAL(&f->wait2);
  silc_fsm_next_later(fsm, test_st_signal1_check, 0, 500000); 
  return SILC_FSM_WAIT;;
}

SILC_FSM_STATE(test_st_signal1_check)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("Signal check"));
  assert(f->got_wait1 && f->got_wait2);
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_thread_st_start)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_thread_st_start"));

  /** Move to final state, timeout */
  SILC_LOG_DEBUG(("Move to final state with %d second timeout", f->timeout));
  silc_fsm_next_later(fsm, test_thread_st_finish, f->timeout, 0);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(test_thread_st_finish)
{
  SILC_LOG_DEBUG(("test_thread_st_finish"));

  SILC_LOG_DEBUG(("Finishing the thread"));
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_fifth)
{
  Foo f = fsm_context;
  SILC_LOG_DEBUG(("test_st_fifth"));

  SILC_LOG_DEBUG(("Thread terminated, start new real thread"));

  f->timeout = 7;

  SILC_LOG_DEBUG(("Creating FSM event"));
  silc_fsm_event_init(&f->sema, fsm);

  SILC_LOG_DEBUG(("Creating FSM thread"));
  silc_fsm_thread_init(&f->thread, fsm, f, NULL, NULL, TRUE);
  SILC_LOG_DEBUG(("Starting thread"));
  silc_fsm_start(&f->thread, test_thread2_st_start);

  /** Waiting thread to terminate, timeout */
  SILC_LOG_DEBUG(("Waiting for thread to terminate for 5 seconds"));
  silc_fsm_next(fsm, test_st_sixth);
  SILC_FSM_EVENT_TIMEDWAIT(&f->sema, 5, 0, NULL);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_thread2_st_start)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_thread2_st_start"));

  /** Move to final state, timeout */
  SILC_LOG_DEBUG(("Move to final state with %d second timeout", f->timeout));
  silc_fsm_next_later(fsm, test_thread2_st_finish, f->timeout, 0);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(test_thread2_st_finish)
{
  Foo f = fsm_context;
  SILC_LOG_DEBUG(("test_thread2_st_finish"));

  SILC_LOG_DEBUG(("Post semaphore"));
  SILC_FSM_EVENT_SIGNAL(&f->sema);

  SILC_LOG_DEBUG(("Finishing the thread"));
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_sixth)
{
  SILC_LOG_DEBUG(("test_st_sixth"));

  SILC_LOG_DEBUG(("Thread wait timedout, OK"));

  /** Move to next state, timeout */
  SILC_LOG_DEBUG(("Continue to next state with 4 second timeout"));
  silc_fsm_next_later(fsm, test_st_seventh, 4, 0);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(test_thread3_st_start)
{
  T *t = fsm_context;

  if (t->rounds == 0) {
    SILC_FSM_EVENT_SIGNAL(&t->sema);
    return SILC_FSM_FINISH;
  }

  t->rounds--;

  /** Call in recursive */
  silc_fsm_next(fsm, test_thread3_st_start);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_seventh)
{
  Foo f = fsm_context;
  int i;

  SILC_LOG_DEBUG(("test_st_seventh"));


  SILC_LOG_DEBUG(("Creating %d FSM threads", NUM_THREADS));
  for (i = 0; i < NUM_THREADS; i++) {
    f->threads[i].rounds = 10;
    f->threads[i].f = f;
    silc_fsm_event_init(&f->threads[i].sema, fsm);
    silc_fsm_thread_init(&f->threads[i].thread, fsm,
			 &f->threads[i], NULL, NULL, FALSE);
    silc_fsm_start(&f->threads[i].thread, test_thread3_st_start);
  }

  /** Move to wait threads */
  silc_fsm_next(fsm, test_st_eighth);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_eighth)
{
  Foo f = fsm_context;
  int i;

  for (i = 0; i < NUM_THREADS; i++) {
    if (f->threads[i].finished == FALSE) {
      SILC_FSM_EVENT_WAIT(&f->threads[i].sema);
      f->threads[i].finished = TRUE;
    }
  }

  SILC_LOG_DEBUG(("All %d threads terminated", NUM_THREADS));

  /** Move to next thread */
  silc_fsm_next(fsm, test_st_ninth);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_thread4_st_start)
{
  T *t = fsm_context;

  if (t->rounds == 0) {
    SILC_FSM_EVENT_SIGNAL(&t->sema);
    return SILC_FSM_FINISH;
  }

  t->rounds--;

  /** Call in recursive */
  silc_fsm_next(fsm, test_thread4_st_start);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_ninth)
{
  Foo f = fsm_context;
  int i;

  SILC_LOG_DEBUG(("test_st_ninth"));

  SILC_LOG_DEBUG(("Creating FSM event"));
  silc_fsm_event_init(&f->sema, fsm);

  SILC_LOG_DEBUG(("Creating %d real FSM threads", NUM_THREADS));
  for (i = 0; i < NUM_THREADS; i++) {
    f->threads2[i].rounds = 10;
    f->threads2[i].f = f;
    silc_fsm_event_init(&f->threads2[i].sema, fsm);
    silc_fsm_thread_init(&f->threads2[i].thread, fsm,
			 &f->threads2[i], NULL, NULL, TRUE);
    silc_fsm_start(&f->threads2[i].thread, test_thread4_st_start);
  }

  /** Move to wait threads */
  silc_fsm_next(fsm, test_st_tenth);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_tenth)
{
  Foo f = fsm_context;
  int i;

  for (i = 0; i < NUM_THREADS; i++)
    if (f->threads2[i].finished == FALSE) {
      SILC_FSM_EVENT_WAIT(&f->threads2[i].sema);
      f->threads2[i].finished = TRUE;
    }

  SILC_LOG_DEBUG(("All %d real threads terminated", NUM_THREADS));

  /** Finished successfully */
  silc_fsm_next_later(fsm, test_st_finish, 2, 0);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(test_st_finish)
{
  SILC_LOG_DEBUG(("test_st_finish"));

  SILC_LOG_DEBUG(("Finish machine"));
  return SILC_FSM_FINISH;
}

static void destructor(SilcFSM fsm, void *fsm_context,
		       void *destructor_context)
{
  Foo f = destructor_context;
  SILC_LOG_DEBUG(("FSM destructor, stopping scheduler"));
  silc_fsm_free(fsm);
  silc_schedule_stop(f->schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcSchedule schedule;
  SilcFSM fsm;
  Foo f;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_quick(TRUE);
    silc_log_set_debug_string("*fsm*,*async*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);

  f = silc_calloc(1, sizeof(*f));
  if (!f)
    goto err;
  f->schedule = schedule;

  SILC_LOG_DEBUG(("Allocating FSM context"));
  f->fsm = fsm = silc_fsm_alloc(f, destructor, f, schedule);
  if (!fsm)
    goto err;
  silc_fsm_start(fsm, test_st_start);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  if (f->error)
    goto err;

  silc_schedule_uninit(schedule);
  silc_free(f);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
