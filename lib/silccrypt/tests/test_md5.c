#include "silc.h"

/* Test vectors from RFC 1321 */

/* First test vector */
const unsigned char data1[] = "a";
const unsigned char data1_digest[] = "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61";

/* Second test vector. */
const unsigned char data2[] = "message digest";
const unsigned char data2_digest[] = "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0";

/* Third test vector. */
const unsigned char data3[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const unsigned char data3_digest[] = "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[16];
  SilcHash md5;
  
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*md5*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();

  SILC_LOG_DEBUG(("Allocating md5 hash function"));
  if (!silc_hash_alloc("md5", &md5)) {
    SILC_LOG_DEBUG(("Allocating md5 hash function failed"));
    goto err;
  }

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  silc_hash_init(md5);
  silc_hash_update(md5, data1, strlen(data1));
  silc_hash_final(md5, digest);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data1, strlen(data1));
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data1_digest,
		   sizeof(digest));
  if (memcmp(digest, data1_digest, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));
  
  /* Second test vector */
  SILC_LOG_DEBUG(("Second test vector"));
  silc_hash_init(md5);
  silc_hash_update(md5, data2, strlen(data2));
  silc_hash_final(md5, digest);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data2, strlen(data2));
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data2_digest,
		   sizeof(digest));
  if (memcmp(digest, data2_digest, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));

  /* Third test vector */
  SILC_LOG_DEBUG(("Third test vector"));
  silc_hash_init(md5);
  silc_hash_update(md5, data3, strlen(data3));
  silc_hash_final(md5, digest);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data3, strlen(data3));
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data3_digest,
		   sizeof(digest));
  if (memcmp(digest, data3_digest, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));

  success = TRUE;
  
 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_hash_free(md5);
  silc_hash_unregister_all();
  return success;
}
