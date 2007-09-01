#include "silc.h"

/* Test vectors from NIST secure hashing definition for SHA-256 */

/* First test vector */
const unsigned char data1[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const unsigned char data1_digest[] = "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";

/* Second test vector */
const unsigned char data2[] = "abc";
const unsigned char data2_digest[] = "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";

/* Third test vector */
const unsigned char data3[] ="ebaccc34d6d6d3d21ed0ad2ba7c07c21d253c4814f4ad89d32369237497f47a1adabfa2398ddd09d769cc46d3fd69c9303251c13c750799b8f151166bc2658609871168b30a4d0a162f183fb360f99b172811503681a11f813c16a446272ba6fd48586344533b9280856519c357059c344ef1718dbaf86fae5c10799e46b5316886fb4e68090757890539617e403c511a4f78a19c818c2ea2e9d4e2de9190c9dddb806";
const unsigned char data3_digest[] ="c907180443dee3cbccb4c31328e625158527a593b878de1b8e4ba37f1d69fb66";

SilcTimerStruct timer;

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[32], tmp[4096], digest2[32];
  SilcUInt32 tmp_len;
  SilcHash sha256;
  
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*sha256*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();

  SILC_LOG_DEBUG(("Allocating sha256 hash function"));
  if (!silc_hash_alloc("sha256", &sha256)) {
    SILC_LOG_DEBUG(("Allocating sha256 hash function failed"));
    goto err;
  }

  SilcUInt64 t1, t2;
  silc_timer_synchronize(&timer);

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  silc_hash_init(sha256);
  silc_hash_update(sha256, data1, strlen(data1));
  memset(digest, 0, sizeof(digest));
  t1 = silc_timer_tick(&timer, FALSE);
  silc_hash_final(sha256, digest);
  t2 = silc_timer_tick(&timer, TRUE);
  SILC_LOG_DEBUG(("cycles: %d", t2 - t1));
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
  silc_hash_init(sha256);
  silc_hash_update(sha256, data2, strlen(data2));
  silc_hash_final(sha256, digest);
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
  silc_hash_init(sha256);
  silc_hex2data(data3, tmp, sizeof(tmp), &tmp_len);
  silc_hash_update(sha256, tmp, tmp_len);
  silc_hash_final(sha256, digest);
  SILC_LOG_HEXDUMP(("Message"), tmp, tmp_len);
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  silc_hex2data(data3_digest, digest2, sizeof(digest2), NULL);
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)digest2,
		   sizeof(digest));
  if (memcmp(digest, digest2, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));
  
  success = TRUE;
  
 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_hash_free(sha256);
  silc_hash_unregister_all();
  return success;
}
