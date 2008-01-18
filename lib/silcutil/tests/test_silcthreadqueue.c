/* SilcThreadQueue tests */

#include "silcruntime.h"

SilcSchedule schedule;
SilcThreadQueue queue;
SilcBool success = FALSE;

SILC_FSM_STATE(test_st_start);
SILC_FSM_STATE(test_st_wait);
SILC_FSM_STATE(test_st_thread_start);
SILC_FSM_STATE(test_st_finish);

SILC_FSM_STATE(test_st_start)
{
  SilcFSMThread thread;

  SILC_LOG_DEBUG(("test_st_start"));

  queue = silc_thread_queue_alloc();
  if (!queue) {
    silc_fsm_next(fsm, test_st_finish);
    return SILC_FSM_CONTINUE;
  }

  thread = silc_fsm_thread_alloc(fsm, NULL, NULL, NULL, TRUE);
  if (!thread) {
    silc_fsm_next(fsm, test_st_finish);
    return SILC_FSM_CONTINUE;
  }

  silc_fsm_start(thread, test_st_thread_start);
  silc_fsm_set_state_context(fsm, thread);

  silc_fsm_next(fsm, test_st_wait);
  return SILC_FSM_YIELD;
}

SILC_FSM_STATE(test_st_wait)
{
  void *data;

  SILC_LOG_DEBUG(("Wait for data"));

  /* Wait for data */
  data = silc_thread_queue_pop(queue, TRUE);
  if (!data || data != (void *)100) {
    silc_fsm_next(fsm, test_st_finish);
    return SILC_FSM_CONTINUE;
  }

  success = TRUE;
  silc_fsm_next(fsm, test_st_finish);
  SILC_FSM_THREAD_WAIT(state_context);
}

SILC_FSM_STATE(test_st_thread_start)
{
  silc_thread_queue_connect(queue);

  sleep(1);

  /* Send data */
  SILC_LOG_DEBUG(("Send data"));
  silc_thread_queue_push(queue, (void *)100);

  silc_thread_queue_disconnect(queue);
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_finish)
{
  SILC_LOG_DEBUG(("test_st_finish"));

  silc_thread_queue_disconnect(queue);

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
  SilcFSM fsm;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*thread*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL, NULL, NULL);
  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Allocating FSM context"));
  fsm = silc_fsm_alloc(NULL, destructor, NULL, schedule);
  if (!fsm)
    goto err;
  silc_fsm_start(fsm, test_st_start);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  silc_schedule_uninit(schedule);

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return !success;
}
