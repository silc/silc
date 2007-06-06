/* SilcSchedule tests */

#include "silc.h"

typedef void (*Callback)(void *context);

#define NUM_TTASK 200
#ifdef FD_SETSIZE
#define NUM_FTASK FD_SETSIZE
#else
#define NUM_FTASK 250
#endif

SilcSchedule schedule;

void notify_cb(SilcSchedule schedule, SilcBool added, SilcTask task,
	       SilcBool fd_task, SilcUInt32 fd, long sec, long usec,
	       void *context)
{
  SILC_LOG_DEBUG(("Notify cb, %s %s task, fd %d, sec %d usec %d",
		  added ? "added" : "deleted", fd_task ? "fd" :"timeout",
		  fd, sec, usec));
}

SILC_TASK_CALLBACK(foo)
{

}

SILC_TASK_CALLBACK(timeout)
{
  int i = (int)context;
  SILC_LOG_DEBUG(("Timeout task %d", i));
}

SILC_TASK_CALLBACK(cont2)
{
#ifdef SILC_DEBUG
  silc_schedule_stats(schedule);
#endif /* SILC_DEBUG */

  SILC_LOG_DEBUG(("Adding %d fd tasks", NUM_FTASK - 10));

#if 0
  for (i = 0; i < NUM_FTASK - 10; i++)
    silc_schedule_task_add_fd(schedule, i + 5, foo, (void *)(i + 5));
#endif
}

SILC_TASK_CALLBACK(cont)
{
  int i;

#ifdef SILC_DEBUG
  silc_schedule_stats(schedule);
#endif /* SILC_DEBUG */

  SILC_LOG_DEBUG(("Adding %d timeout tasks", NUM_TTASK / 3));
  for (i = 0; i < NUM_TTASK / 3; i++)
    silc_schedule_task_add_timeout(schedule, timeout, (void *)i, 0, 0);

  silc_schedule_task_add_timeout(schedule, cont2, (void *)i, 0, 100);
}

SILC_TASK_CALLBACK(start)
{
  int i;

  SILC_LOG_DEBUG(("Adding %d timeout tasks", NUM_TTASK));

#if 0
  for (i = 0; i < NUM_TTASK; i++)
    silc_schedule_task_add_timeout(schedule, timeout, (void *)i,
	i + (i & 9999), (i * 720391) & 999999);
#endif

  for (i = 0; i < NUM_TTASK; i++)
    silc_schedule_task_add_timeout(schedule, timeout, (void *)i, 0, 1);

  silc_schedule_task_add_timeout(schedule, cont, (void *)i, 0, 100);
}

SILC_TASK_CALLBACK(interrupt)
{
  SILC_LOG_DEBUG(("SIGINT signal"));
  silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*sched*,*hash*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(NUM_FTASK, NULL);
  if (!schedule)
    goto err;
  silc_schedule_set_notify(schedule, notify_cb, NULL);

  silc_schedule_task_add_signal(schedule, SIGINT, interrupt, NULL);

  silc_schedule_task_add_timeout(schedule, start, NULL, 1, 0);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  silc_schedule_uninit(schedule);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
