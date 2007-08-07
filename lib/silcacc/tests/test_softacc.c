/* Software accelerator tests */

#include "silc.h"

SilcSchedule schedule;
SilcPublicKey public_key, accpub;
SilcPrivateKey private_key, accprv;
SilcHash hash;
unsigned char data[] = "Single block msg";
int data_len = 16;
int s = 200;

void sign_compl(SilcBool success, const unsigned char *signature,
	        SilcUInt32 signature_len, void *context)
{
  SILC_LOG_DEBUG(("Sign compl %s", success ? "Ok" : "failed"));
}

SILC_TASK_CALLBACK(stats)
{
  silc_stack_stats(silc_crypto_stack());
  silc_schedule_task_add_timeout(schedule, stats, NULL, 1, 1);
}

SILC_TASK_CALLBACK(quit)
{
  silc_schedule_stop(schedule);
}

SILC_TASK_CALLBACK(sign)
{
  silc_pkcs_sign(accprv, data, data_len, TRUE, hash, NULL, sign_compl, NULL);
  if (--s > 0)
    silc_schedule_task_add_timeout(schedule, sign, NULL, 0, 60000);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcAccelerator softacc;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*acc*");
  }

  silc_crypto_init(NULL);
  if (!silc_hash_alloc("sha1", &hash))
    goto err;

  if (!silc_create_key_pair("rsa", 2048, "pubkey.pub", "privkey.prv", NULL,
			    "", &public_key, &private_key, FALSE))
    goto err;

  schedule = silc_schedule_init(0, NULL, NULL);

  softacc = silc_acc_find("softacc");
  if (!softacc)
    goto err;

  if (!silc_acc_init(softacc, schedule, "min_threads", 2, "max_threads", 
		     8, NULL))
    goto err;

  accpub = silc_acc_public_key(softacc, public_key);
  if (!accpub)
    goto err;
  accprv = silc_acc_private_key(softacc, private_key);
  if (!accprv)
    goto err;

  if (silc_acc_get_public_key(softacc, accpub) != public_key)
    goto err;
  if (silc_acc_get_private_key(softacc, accprv) != private_key)
    goto err;

  silc_schedule_task_add_timeout(schedule, sign, NULL, 0, 1);
  silc_schedule_task_add_timeout(schedule, stats, NULL, 1, 1);
  silc_schedule_task_add_timeout(schedule, quit, NULL, 19, 0);
  silc_schedule(schedule);

  silc_acc_uninit(softacc);
  silc_schedule_uninit(schedule);
  silc_crypto_uninit();

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
