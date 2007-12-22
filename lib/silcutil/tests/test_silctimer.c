/* SilcTimer tests */

#include "silc.h"

SilcSchedule schedule;
SilcTimerStruct timer;
SilcBool success = FALSE;

SILC_TASK_CALLBACK(check);

SILC_TASK_CALLBACK(restart)
{
  SILC_LOG_DEBUG(("Timer is %s", silc_timer_is_running(&timer) ?
		  "running" : "stopped"));
  SILC_LOG_DEBUG(("Restart timer"));
  silc_timer_continue(&timer);
  silc_schedule_task_add_timeout(schedule, check, NULL, 1, 0);
}

SILC_TASK_CALLBACK(check)
{
  SilcUInt64 sec;
  SilcUInt32 usec;
  SilcTimeStruct t, st;
  char ts[32];

  SILC_LOG_DEBUG(("Timer is %s", silc_timer_is_running(&timer) ?
		  "running" : "stopped"));

  silc_timer_value(&timer, &sec, &usec);
  SILC_LOG_DEBUG(("Timer elapsed: %llu secs, %lu usec", sec, usec));

  if (sec == 5) {
    SILC_LOG_DEBUG(("Stop timer"));
    silc_timer_stop(&timer);

    silc_timer_value(&timer, &sec, &usec);
    SILC_LOG_DEBUG(("Timer elapsed: %llu secs, %lu usec", sec, usec));

    silc_timer_start_time(&timer, &st);
    silc_timer_value_time(&timer, &t);
    silc_time_universal_string(&st, ts, sizeof(ts));
    SILC_LOG_DEBUG(("Start time: %s", ts));    
    silc_time_universal_string(&t, ts, sizeof(ts));
    SILC_LOG_DEBUG(("End time: %s", ts));    

    success = TRUE;
    silc_schedule_stop(schedule);
    return;
  }

  if (sec == 2) {
    SILC_LOG_DEBUG(("Stopping timer, sleep 3 seconds"));
    silc_timer_stop(&timer);
    silc_schedule_task_add_timeout(schedule, restart, NULL, 3, 0);
    return;
  }

  silc_schedule_task_add_timeout(schedule, check, NULL, 0, 500000);
}


int main(int argc, char **argv)
{
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*timer*,*errno*");
  }

  schedule = silc_schedule_init(0, NULL, NULL);
  if (!schedule)
    goto err;

  silc_timer_synchronize(&timer);
  SILC_LOG_DEBUG(("sync_diff: %d", timer.sync_diff));
  SILC_LOG_DEBUG(("sync_tdiff: %d", timer.sync_tdiff));

  SILC_LOG_DEBUG(("Start timer"));
  silc_timer_start(&timer);

  silc_schedule_task_add_timeout(schedule, check, NULL, 1, 0);

  silc_schedule(schedule);

  silc_schedule_uninit(schedule);

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
