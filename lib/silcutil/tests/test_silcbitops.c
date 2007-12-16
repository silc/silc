/* Bit operation tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SILC_BITMAP_DECLARE(bitmap, 500);
  int size = SILC_BITMAP_SIZE(500), bit;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*bit*");
  }

  silc_bit_clear_bitmap(bitmap, size);

  SILC_LOG_DEBUG(("Setting bit 0"));
  if (!silc_bit_set(bitmap, size, 0))
    goto err;
  bit = silc_bit_get(bitmap, size, 0);
  SILC_LOG_DEBUG(("Get bit 0: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Setting bit 100"));
  if (!silc_bit_set(bitmap, size, 100))
    goto err;
  bit = silc_bit_get(bitmap, size, 100);
  SILC_LOG_DEBUG(("Get bit 100: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Clear bit 100"));
  if (!silc_bit_clear(bitmap, size, 100))
    goto err;
  bit = silc_bit_get(bitmap, size, 100);
  SILC_LOG_DEBUG(("Get bit 100: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 0)
    goto err;

  SILC_LOG_DEBUG(("Toggle bit 99"));
  if (!silc_bit_toggle(bitmap, size, 99))
    goto err;
  bit = silc_bit_get(bitmap, size, 99);
  SILC_LOG_DEBUG(("Get bit 99: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Test and toggle bit 499"));
  bit = silc_bit_test_and_toggle(bitmap, size, 499);
  if (bit != 0)
    goto err;
  bit = silc_bit_get(bitmap, size, 499);
  SILC_LOG_DEBUG(("Get bit 499: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Test and set bit 10"));
  bit = silc_bit_test_and_set(bitmap, size, 10);
  if (bit != 0)
    goto err;
  bit = silc_bit_get(bitmap, size, 10);
  SILC_LOG_DEBUG(("Get bit 10: %d", bit));
  if (bit < 0)
    goto err;
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Test overflow"));
  if (silc_bit_set(bitmap, size, 1500))
    goto err;
  SILC_LOG_DEBUG(("Overflow detected"));

  SILC_LOG_DEBUG(("Find first set bit"));
  bit = silc_bit_ffs(bitmap, size);
  SILC_LOG_DEBUG(("First set bit: %d", bit));
  if (bit != 0)
    goto err;

  SILC_LOG_DEBUG(("Find next set bit"));
  bit = silc_bit_fns(bitmap, size, bit + 1);
  SILC_LOG_DEBUG(("Next set bit: %d", bit));
  if (bit != 10)
    goto err;

  SILC_LOG_DEBUG(("Find all set bits"));
  bit = 0;
  do {
    bit = silc_bit_fns(bitmap, size, bit);
    if (bit != -1) {
      SILC_LOG_DEBUG(("Set bit: %d", bit));
      bit++;
    }
  } while (bit != -1);

  SILC_LOG_DEBUG(("Find first zero bit"));
  bit = silc_bit_ffz(bitmap, size);
  SILC_LOG_DEBUG(("First zero bit: %d", bit));
  if (bit != 1)
    goto err;

  SILC_LOG_DEBUG(("Find next zero bit"));
  bit = silc_bit_fnz(bitmap, size, bit + 1);
  SILC_LOG_DEBUG(("Next zero bit: %d", bit));
  if (bit != 2)
    goto err;

  SILC_LOG_DEBUG(("Clear bitmap"));
  silc_bit_clear_bitmap(bitmap, size);

  SILC_LOG_DEBUG(("Check for set bits"));
  bit = silc_bit_ffs(bitmap, size);
  if (bit > 0)
    goto err;
  SILC_LOG_DEBUG(("No set bits"));

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
