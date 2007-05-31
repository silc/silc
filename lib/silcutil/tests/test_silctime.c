/* SilcTime tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcTimeStruct curtime;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*time*");
  }

  SILC_LOG_DEBUG(("Get current time"));
  if (!silc_time_value(0, &curtime))
    goto err;
  SILC_LOG_DEBUG(("year      : %d", curtime.year));
  SILC_LOG_DEBUG(("month     : %d", curtime.month));
  SILC_LOG_DEBUG(("day       : %d", curtime.day));
  SILC_LOG_DEBUG(("hour      : %d", curtime.hour));
  SILC_LOG_DEBUG(("minute    : %d", curtime.minute));
  SILC_LOG_DEBUG(("second    : %d", curtime.second));
  SILC_LOG_DEBUG(("msecond   : %d", curtime.msecond));
  SILC_LOG_DEBUG(("utc_hour  : %d", curtime.utc_hour));
  SILC_LOG_DEBUG(("utc_min   : %d", curtime.utc_minute));
  SILC_LOG_DEBUG(("utc_east  : %d", curtime.utc_east));
  SILC_LOG_DEBUG(("dst       : %d", curtime.dst));

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
