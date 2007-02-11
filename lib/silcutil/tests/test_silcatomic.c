/* atomic operation tests */

#include "silc.h"
#include "silcatomic.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcAtomic32 ref32;
  SilcAtomic16 ref16;
  SilcAtomic8 ref8;
  SilcAtomicPointer refptr;
  SilcUInt8 ret8;
  SilcUInt16 ret16;
  SilcUInt32 ret32;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*atomic*");
  }

  silc_atomic_init8(&ref8, 1);
  silc_atomic_init16(&ref16, 1);
  silc_atomic_init32(&ref32, 1);
  silc_atomic_init_pointer(&refptr, SILC_32_TO_PTR(0xdeadbeef));

  ret8 = silc_atomic_add_int8(&ref8, 7);
  SILC_LOG_DEBUG(("ref8: 1 + 7 = %d (8)", ret8));
  ret8 = silc_atomic_add_int8(&ref8, 3);
  SILC_LOG_DEBUG(("ref8: 8 + 3 = %d (11)", ret8));
  ret8 = silc_atomic_sub_int8(&ref8, 10);
  SILC_LOG_DEBUG(("ref8: 11 - 10 = %d (1)", ret8));

  ret16 = silc_atomic_add_int16(&ref16, 1);
  SILC_LOG_DEBUG(("ref16: 1 + 1 = %d (2)", ret16));
  ret16 = silc_atomic_add_int16(&ref16, 31020);
  SILC_LOG_DEBUG(("ref16: 2 + 31020 = %d (31022)", ret16));
  ret16 = silc_atomic_add_int16(&ref16, 34000);
  SILC_LOG_DEBUG(("ref16: 31022 + 34000 = %d (65022)", ret16));
  ret16 = silc_atomic_sub_int16(&ref16, 0);
  SILC_LOG_DEBUG(("ref16: 65022 - 0 = %d (65022)", ret16));
  ret16 = silc_atomic_sub_int16(&ref16, (SilcInt16)0xffff);
  SILC_LOG_DEBUG(("ref16: 65022 - 0xffff = %d (65023) (underflow)", ret16));

  SILC_LOG_DEBUG(("Current value: %d (-513)",
		  (SilcInt16)silc_atomic_get_int16(&ref16)));

  SILC_LOG_DEBUG(("Swapping -513 with 57392"));
  if (!silc_atomic_cas16(&ref16, silc_atomic_get_int16(&ref16), 57392))
    goto err;
  SILC_LOG_DEBUG(("Current value: %d (57392)",
		  silc_atomic_get_int16(&ref16)));
  SILC_LOG_DEBUG(("Swapping 57392 with -500"));
  if (!silc_atomic_cas16(&ref16, silc_atomic_get_int16(&ref16), -500))
    goto err;
  SILC_LOG_DEBUG(("Current value: %d (-500)",
		  (SilcInt16)silc_atomic_get_int16(&ref16)));

  ret32 = silc_atomic_add_int32(&ref32, 1);
  SILC_LOG_DEBUG(("ref32: 1 + 1 = %d (2)", ret32));
  ret32 = silc_atomic_add_int32(&ref32, 310200);
  SILC_LOG_DEBUG(("ref32: 2 + 310200 = %d (310202)", ret32));
  ret32 = silc_atomic_add_int32(&ref32, 34000000);
  SILC_LOG_DEBUG(("ref32: 310202 + 34000000 = %d (34310202)", ret32));
  ret32 = silc_atomic_sub_int32(&ref32, 0);
  SILC_LOG_DEBUG(("ref32: 34310202 - 0 = %d (34310202)", ret32));
  ret32 = silc_atomic_sub_int32(&ref32, 0xfffffff);
  SILC_LOG_DEBUG(("ref32: 34310202 - 0xfffffff = %d (-234125253) "
		  "(underflow)", ret32));

  SILC_LOG_DEBUG(("Current value: %d (-234125253)",
		  silc_atomic_get_int32(&ref32)));

  SILC_LOG_DEBUG(("Swapping -234125253 with 76327681"));
  if (!silc_atomic_cas32(&ref32, silc_atomic_get_int32(&ref32), 76327681))
    goto err;
  SILC_LOG_DEBUG(("Current value: %d (76327681)",
		  silc_atomic_get_int32(&ref32)));

  SILC_LOG_DEBUG(("Current ptr: %p (0xdeadbeef)",
		  silc_atomic_get_pointer(&refptr)));
  SILC_LOG_DEBUG(("Swapping %p with NULL", silc_atomic_get_pointer(&refptr)));
  if (!silc_atomic_cas_pointer(&refptr,
			       silc_atomic_get_pointer(&refptr), NULL))
    goto err;
  SILC_LOG_DEBUG(("Current ptr: %p (NULL)",
		  silc_atomic_get_pointer(&refptr)));

  SILC_LOG_DEBUG(("Setting val 34322111 (32-bit)"));
  silc_atomic_set_int32(&ref32, 34322111);
  if (silc_atomic_get_int32(&ref32) != 34322111)
    goto err;
  SILC_LOG_DEBUG(("Setting val 1432211119 (32-bit)"));
  silc_atomic_set_int32(&ref32, 1432211119);
  if (silc_atomic_get_int32(&ref32) != 1432211119)
    goto err;
  SILC_LOG_DEBUG(("Setting val 23422 (16-bit)"));
  silc_atomic_set_int16(&ref16, 23422);
  if (silc_atomic_get_int16(&ref16) != 23422)
    goto err;
  SILC_LOG_DEBUG(("Setting val 124 (8-bit)"));
  silc_atomic_set_int8(&ref8, 124);
  if (silc_atomic_get_int8(&ref8) != 124)
    goto err;

  silc_atomic_uninit8(&ref8);
  silc_atomic_uninit16(&ref16);
  silc_atomic_uninit32(&ref32);
  silc_atomic_uninit_pointer(&refptr);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
