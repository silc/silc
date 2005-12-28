#include "silc.h"

/* Test vectors from RFC 2202 */

/* First test vector */
const unsigned char key1[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
int key1_len = 16;
const unsigned char data1[] = "Hi There";
const unsigned char data1_digest[] = "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d";

/* Second test vector */
const unsigned char key2[] = "Jefe";
int key2_len = 4;
const unsigned char data2[] = "what do ya want for nothing?";
const unsigned char data2_digest[] = "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38";

/* Third test vector, data 0xdd repeated 50 times */
const unsigned char key3[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
int key3_len = 16;
unsigned char data3[50];
const unsigned char data3_digest[] = "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6";

/* Fourth test vector, key 0xaa 80 times */
unsigned char key4[80];
int key4_len = 80;
const unsigned char data4[] = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
const unsigned char data4_digest[] = "\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[16];
  SilcUInt32 len;
  SilcHmac hmac;
  
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*md5*,*hmac*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();
  silc_hmac_register_default();

  SILC_LOG_DEBUG(("Allocating md5 HMAC"));
  if (!silc_hmac_alloc("hmac-md5", NULL, &hmac)) {
    SILC_LOG_DEBUG(("Allocating md5 HMAC failed"));
    goto err;
  }

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  silc_hmac_init_with_key(hmac, key1, key1_len);
  silc_hmac_update(hmac, data1, strlen(data1));
  silc_hmac_final(hmac, digest, &len);
  SILC_LOG_HEXDUMP(("Key"), (unsigned char *)key1, key1_len);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data1, strlen(data1));
  SILC_LOG_HEXDUMP(("Digest"), digest, len);
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data1_digest, len);
  if (memcmp(digest, data1_digest, len)) {
    SILC_LOG_DEBUG(("HMAC failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("HMAC is successful"));
  
  /* Second test vector */
  SILC_LOG_DEBUG(("Second test vector"));
  silc_hmac_init_with_key(hmac, key2, key2_len);
  silc_hmac_update(hmac, data2, strlen(data2));
  silc_hmac_final(hmac, digest, &len);
  SILC_LOG_HEXDUMP(("Key"), (unsigned char *)key2, key2_len);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data2, strlen(data2));
  SILC_LOG_HEXDUMP(("Digest"), digest, len);
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data2_digest, len);
  if (memcmp(digest, data2_digest, len)) {
    SILC_LOG_DEBUG(("HMAC failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("HMAC is successful"));
  
  /* Third test vector */
  SILC_LOG_DEBUG(("Third test vector"));
  silc_hmac_init_with_key(hmac, key3, key3_len);
  memset(data3, '\xdd', sizeof(data3));
  silc_hmac_update(hmac, data3, sizeof(data3));
  silc_hmac_final(hmac, digest, &len);
  SILC_LOG_HEXDUMP(("Key"), (unsigned char *)key3, key3_len);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data3, sizeof(data3));
  SILC_LOG_HEXDUMP(("Digest"), digest, len);
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data3_digest, len);
  if (memcmp(digest, data3_digest, len)) {
    SILC_LOG_DEBUG(("HMAC failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("HMAC is successful"));
  
  /* Fourth test vector */
  SILC_LOG_DEBUG(("Fourth test vector"));
  memset(key4, '\xaa', key4_len);
  silc_hmac_init_with_key(hmac, key4, key4_len);
  silc_hmac_update(hmac, data4, strlen(data4));
  silc_hmac_final(hmac, digest, &len);
  SILC_LOG_HEXDUMP(("Key"), (unsigned char *)key4, key4_len);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data4, sizeof(data4));
  SILC_LOG_HEXDUMP(("Digest"), digest, len);
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data4_digest, len);
  if (memcmp(digest, data4_digest, len)) {
    SILC_LOG_DEBUG(("HMAC failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("HMAC is successful"));
  
  success = TRUE;
  
 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_hmac_free(hmac);
  silc_hash_unregister_all();
  silc_hmac_unregister_all();
  return success;
}
