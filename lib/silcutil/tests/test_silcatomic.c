/* atomic operation tests */

#include "silc.h"
#include "silcatomic.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcAtomic ref;
  SilcUInt8 ret8;
  SilcUInt16 ret16;
  SilcUInt32 ret32;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*atomic*");
  }

  silc_atomic_init(&ref, 1);

  ret8 = silc_atomic_add_int(&ref, 7);
  SILC_LOG_DEBUG(("ref8: 1 + 7 = %d (8)", ret8));
  ret8 = silc_atomic_add_int(&ref, 3);
  SILC_LOG_DEBUG(("ref8: 8 + 3 = %d (11)", ret8));
  ret8 = silc_atomic_sub_int(&ref, 10);
  SILC_LOG_DEBUG(("ref8: 11 - 10 = %d (1)", ret8));

  ret16 = silc_atomic_add_int(&ref, 1);
  SILC_LOG_DEBUG(("ref16: 1 + 1 = %d (2)", ret16));
  ret16 = silc_atomic_add_int(&ref, 31020);
  SILC_LOG_DEBUG(("ref16: 2 + 31020 = %d (31022)", ret16));
  ret16 = silc_atomic_add_int(&ref, 34000);
  SILC_LOG_DEBUG(("ref16: 31022 + 34000 = %d (65022)", ret16));
  ret16 = silc_atomic_sub_int(&ref, 0);
  SILC_LOG_DEBUG(("ref16: 65022 - 0 = %d (65022)", ret16));
  ret16 = silc_atomic_sub_int(&ref, 0xffff);
  SILC_LOG_DEBUG(("ref16: 65022 - 0xffff = %d (65023) (underflow)", ret16));

  SILC_LOG_DEBUG(("Current value: %d (-513)", silc_atomic_get_int(&ref)));

  SILC_LOG_DEBUG(("Swapping -513 with 8739200"));
  if (!silc_atomic_cas(&ref, silc_atomic_get_int(&ref), 8739200))
    goto err;
  SILC_LOG_DEBUG(("Current value: %d (8739200)", silc_atomic_get_int(&ref)));

  silc_atomic_uninit(&ref);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
