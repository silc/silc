/* SilcThreadPool tests */

#include "silc.h"

SilcSchedule schedule;

static void func(SilcSchedule schedule, void *context)
{
  SILC_LOG_DEBUG(("func: %d", (int)context));
  sleep(1);
}

static void compl(SilcSchedule schedule, void *context)
{
  SILC_LOG_DEBUG(("completion: %d", (int)context));
  if ((int)context == 0xff)
    silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcThreadPool tp;
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*thread*");
  }

  schedule = silc_schedule_init(0, NULL);
  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Allocate thread pool"));
  tp = silc_thread_pool_alloc(NULL, 2, 4, TRUE);
  if (!tp)
    goto err;
  SILC_LOG_DEBUG(("Stop thread pool"));
  silc_thread_pool_free(tp, TRUE);


  SILC_LOG_DEBUG(("Allocate thread pool"));
  tp = silc_thread_pool_alloc(NULL, 0, 2, FALSE);
  if (!tp)
    goto err;
  for (i = 0; i < 4; i++) {
    SILC_LOG_DEBUG(("Run thread %d", i + 1));
    if (!silc_thread_pool_run(tp, TRUE, NULL, func, (void *) i + 1,
			      compl, (void *)i + 1))
      goto err;
  }
  sleep(4);
  SILC_LOG_DEBUG(("Stop thread pool"));
  silc_thread_pool_free(tp, TRUE);

  SILC_LOG_DEBUG(("Allocate thread pool"));
  tp = silc_thread_pool_alloc(NULL, 0, 2, TRUE);
  if (!tp)
    goto err;
  for (i = 0; i < 2; i++) {
    SILC_LOG_DEBUG(("Run thread %d", i + 1));
    if (!silc_thread_pool_run(tp, FALSE, NULL, func, (void *) i + 1,
			      compl, (void *)i + 1))
      goto err;
  }
  if (silc_thread_pool_run(tp, FALSE, NULL, func, (void *)3,
			   compl, (void *)3))
    goto err;
  sleep(3);
  SILC_LOG_DEBUG(("Stop thread pool"));
  silc_thread_pool_free(tp, TRUE);

  SILC_LOG_DEBUG(("Allocate thread pool"));
  tp = silc_thread_pool_alloc(NULL, 3, 20, TRUE);
  if (!tp)
    goto err;
  for (i = 0; i < 8; i++) {
    SILC_LOG_DEBUG(("Run thread %d", i + 1));
    if (!silc_thread_pool_run(tp, FALSE, schedule, func, (void *) i + 1,
			      compl, (void *)i + 1))
      goto err;
  }
  if (!silc_thread_pool_run(tp, FALSE, schedule, func, (void *)0xff,
			    compl, (void *)0xff))
    goto err;
  sleep(1);

  silc_thread_pool_purge(tp);

  silc_schedule(schedule);

  SILC_LOG_DEBUG(("Stop thread pool"));
  silc_thread_pool_free(tp, TRUE);

  silc_schedule_uninit(schedule);
  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
