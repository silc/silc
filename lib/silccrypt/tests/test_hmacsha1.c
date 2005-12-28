#include "silc.h"

/* Test vectors from RFC 2202 */

/* First test vector */
const unsigned char key1[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
int key1_len = 20;
const unsigned char data1[] = "Hi There";
const unsigned char data1_digest[] = "\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00";

/* Second test vector */
const unsigned char key2[] = "Jefe";
int key2_len = 4;
const unsigned char data2[] = "what do ya want for nothing?";
const unsigned char data2_digest[] = "\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79";

/* Third test vector, data 0xdd repeated 50 times */
const unsigned char key3[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
int key3_len = 20;
unsigned char data3[50];
const unsigned char data3_digest[] = "\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3";

/* Fourth test vector, key 0xaa 80 times */
unsigned char key4[80];
int key4_len = 80;
const unsigned char data4[] = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
const unsigned char data4_digest[] = "\xe8\xe9\x9d\x0f\x45\x23\x7d\x78\x6d\x6b\xba\xa7\x96\x5c\x78\x08\xbb\xff\x1a\x91";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[20];
  SilcUInt32 len;
  SilcHmac hmac;
  
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*sha1*,*hmac*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();
  silc_hmac_register_default();

  SILC_LOG_DEBUG(("Allocating sha1 HMAC"));
  if (!silc_hmac_alloc("hmac-sha1", NULL, &hmac)) {
    SILC_LOG_DEBUG(("Allocating sha1 HMAC failed"));
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
