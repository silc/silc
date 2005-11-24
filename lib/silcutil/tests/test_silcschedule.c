/* SilcSchedule tests */

#include "silcincludes.h"

typedef void (*Callback)(void *context);

#define NUM_TTASK 20
#ifdef FD_SETSIZE
#define NUM_FTASK FD_SETSIZE
#else
#define NUM_FTASK 250
#endif

SilcSchedule schedule;

SILC_TASK_CALLBACK(foo)
{

}

SILC_TASK_CALLBACK(cont)
{
  int i;

  SILC_LOG_DEBUG(("Adding %d fd tasks", NUM_FTASK - 10));

  for (i = 0; i < NUM_FTASK - 10; i++)
    silc_schedule_task_add_fd(schedule, i + 5, foo, (void *)(i + 5));
}

SILC_TASK_CALLBACK(timeout)
{
  int i = (int)context;
  SILC_LOG_DEBUG(("Timeout task %d", i));
}

SILC_TASK_CALLBACK(start)
{
  int i;

  SILC_LOG_DEBUG(("Adding %d timeout tasks", NUM_TTASK));

  for (i = 0; i < NUM_TTASK; i++)
    silc_schedule_task_add_timeout(schedule, timeout, (void *)i,
	0, (i * 720391) & 999999);

  silc_schedule_task_add_timeout(schedule, cont, (void *)i, 0, 100);
}

int main(int argc, char **argv)
{
  bool success = FALSE;

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

  silc_schedule_task_add_timeout(schedule, start, NULL, 0, 1);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  silc_schedule_uninit(schedule);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
