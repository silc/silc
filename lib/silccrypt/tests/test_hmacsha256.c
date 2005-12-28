#include "silc.h"

/* Test vectors from draft-ietf-ipsec-ciph-sha-256-01.txt */

/* First test vector */
const unsigned char key1[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x00";
int key1_len = 32;
const unsigned char data1[] = "abc";
const unsigned char data1_digest[] = "\xa2\x1b\x1f\x5d\x4c\xf4\xf7\x3a\x4d\xd9\x39\x75\x0f\x7a\x06\x6a\x7f\x98\xcc\x13\x1c\xb1\x6a\x66\x92\x75\x90\x21\xcf\xab\x81\x81";

/* Second test vector */
const unsigned char key2[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x00";
int key2_len = 32;
const unsigned char data2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const unsigned char data2_digest[] = "\x10\x4f\xdc\x12\x57\x32\x8f\x08\x18\x4b\xa7\x31\x31\xc5\x3c\xae\xe6\x98\xe3\x61\x19\x42\x11\x49\xea\x8c\x71\x24\x56\x69\x7d\x30";

/* Third test vector */
const unsigned char key3[] = "Jefe";
int key3_len = 4;
unsigned char data3[] = "what do ya want for nothing?";
const unsigned char data3_digest[] = "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";

/* Fourth test vector, key 0xaa 80 times */
unsigned char key4[80];
int key4_len = 80;
const unsigned char data4[] = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
const unsigned char data4_digest[] = "\x63\x55\xac\x22\xe8\x90\xd0\xa3\xc8\x48\x1a\x5c\xa4\x82\x5b\xc8\x84\xd3\xe7\xa1\xff\x98\xa2\xfc\x2a\xc7\xd8\xe0\x64\xc3\xb2\xe6";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[20];
  SilcUInt32 len;
  SilcHmac hmac;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*sha256*,*hmac*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();
  silc_hmac_register_default();

  SILC_LOG_DEBUG(("Allocating sha256 HMAC"));
  if (!silc_hmac_alloc("hmac-sha256", NULL, &hmac)) {
    SILC_LOG_DEBUG(("Allocating sha256 HMAC failed"));
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
  silc_hmac_update(hmac, data3, strlen(data3));
  silc_hmac_final(hmac, digest, &len);
  SILC_LOG_HEXDUMP(("Key"), (unsigned char *)key3, key3_len);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data3, strlen(data3));
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
