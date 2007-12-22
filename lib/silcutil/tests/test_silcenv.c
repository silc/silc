/* environment tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*env*,*errno*");
  }

  silc_setenv("FOO", "BAR");
  SILC_LOG_DEBUG(("%s", silc_getenv("FOO")));
  silc_unsetenv("FOO");
  if (silc_getenv("FOO") != NULL)
    goto err;
  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
