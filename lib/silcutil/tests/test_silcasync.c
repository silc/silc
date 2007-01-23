/* SilcAsyncOperation tests */

#include "silc.h"
#include "silcfsm.h"
#include "silcasync.h"

typedef void (*Callback)(void *context);

SilcSchedule schedule;

typedef struct {
  SilcFSM fsm;
  SilcFSMEventStruct sema;
  SilcAsyncOperation op;
  Callback cb;
  void *cb_context;
  SilcBool aborted;
} *Foo;

SILC_FSM_STATE(test_st_start);
SILC_FSM_STATE(test_st_second);
SILC_FSM_STATE(test_st_finish);

SILC_TASK_CALLBACK(async_call_timeout)
{
  Foo f = context;
  SILC_LOG_DEBUG(("******Async call cb, continuing FSM"));
  silc_async_free(f->op);
  f->cb(f->cb_context);
}

static void async_abort(SilcAsyncOperation op, void *context)
{
  Foo f = context;
  SILC_LOG_DEBUG(("Async operation aborted"));
  silc_schedule_task_del_by_context(schedule, f);
  silc_schedule_task_del_by_callback(schedule, async_call_timeout);
  f->aborted = TRUE;
}

static SilcAsyncOperation async_call(Callback cb, void *context)
{
  Foo f = context;

  SILC_LOG_DEBUG(("Async call"));

  f->cb = cb;
  f->cb_context = context;
  f->op = silc_async_alloc(async_abort, NULL, f);

  silc_schedule_task_add(schedule, 0, async_call_timeout, f, 2, 1,
			 SILC_TASK_TIMEOUT);

  return f->op;
}

static void async_call_cb(void *context)
{
  Foo f = context;
  SILC_LOG_DEBUG(("*******Callback, signal and continue to next state"));
  f->op = NULL;
  SILC_FSM_EVENT_SIGNAL(&f->sema);
  SILC_FSM_CALL_CONTINUE(f->fsm);
}

SILC_FSM_STATE(test_st_start)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_start"));

  silc_fsm_event_init(&f->sema, fsm);

  /** Wait async callback */
  SILC_LOG_DEBUG(("Call async call"));
  silc_fsm_next_later(fsm, test_st_second, 1, 0);
  SILC_FSM_CALL((f->op = async_call(async_call_cb, f)));
}

SILC_FSM_STATE(test_st_second)
{
  Foo f = fsm_context;
  SilcBool timedout;

  SILC_LOG_DEBUG(("test_st_second"));

  SILC_FSM_EVENT_TIMEDWAIT(&f->sema, 0, 1, &timedout);

  if (timedout == TRUE) {
    SILC_LOG_DEBUG(("Sema timedout, aborting async operation"));
    if (f->op)
      silc_async_abort(f->op, NULL, NULL);
  }

  /** Finish */
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
  SILC_LOG_DEBUG(("FSM destructor, stopping scheduler"));
  silc_fsm_free(fsm);
  silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcFSM fsm;
  Foo f;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*async*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);

  f = silc_calloc(1, sizeof(*f));
  if (!f)
    goto err;

  SILC_LOG_DEBUG(("Allocating FSM context"));
  fsm = silc_fsm_alloc(f, destructor, NULL, schedule);
  if (!fsm)
    goto err;
  silc_fsm_start(fsm, test_st_start);
  f->fsm = fsm;

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  if (!f->aborted)
    goto err;

  silc_schedule_uninit(schedule);
  silc_free(f);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
