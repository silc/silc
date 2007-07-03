/* SilcDll tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcDll dll;
  void *ptr;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*dll*");
  }

  SILC_LOG_DEBUG(("Load shared object /lib/libc.so.6"));
  dll = silc_dll_load("/lib/libc.so.6");
  if (!dll) {
    SILC_LOG_DEBUG(("Cannot load: %s", silc_dll_error(dll)));
    goto err;
  }

  SILC_LOG_DEBUG(("Get symbol 'fprintf'"));
  ptr = silc_dll_getsym(dll, "fprintf");
  if (!ptr)
    goto err;
  SILC_LOG_DEBUG(("Symbol address %p", ptr));

  SILC_LOG_DEBUG(("Close shared object"));
  silc_dll_close(dll);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
