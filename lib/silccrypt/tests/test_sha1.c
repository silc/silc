#include "silc.h"

/* Test vectors from NIST secure hashing definition for SHA-1 */

/* First test vector */
const unsigned char data1[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const unsigned char data1_digest[] = "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1";

/* Second test vector. This will be allocated with 1000000 'a' characters
   and hashed */
char *data2 = NULL;
const unsigned char data2_digest[] = "\x34\xaa\x97\x3c\xd4\xc4\xda\xa4\xf6\x1e\xeb\x2b\xdb\xad\x27\x31\x65\x34\x01\x6f";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char digest[20];
  SilcHash sha1;
  
  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*hash*,*sha1*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_hash_register_default();

  SILC_LOG_DEBUG(("Allocating sha1 hash function"));
  if (!silc_hash_alloc("sha1", &sha1)) {
    SILC_LOG_DEBUG(("Allocating sha1 hash function failed"));
    goto err;
  }

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  silc_hash_init(sha1);
  silc_hash_update(sha1, data1, strlen(data1));
  silc_hash_final(sha1, digest);
  SILC_LOG_HEXDUMP(("Message"), (unsigned char *)data1, strlen(data1));
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data1_digest,
		   sizeof(digest));
  if (memcmp(digest, data1_digest, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));
  
  /* First test vector */
  SILC_LOG_DEBUG(("Second test vector"));
  data2 = silc_malloc(1000000);
  memset(data2, 'a', 1000000);
  silc_hash_init(sha1);
  silc_hash_update(sha1, data2, 1000000);
  silc_hash_final(sha1, digest);
  SILC_LOG_HEXDUMP(("Digest"), digest, sizeof(digest));
  SILC_LOG_HEXDUMP(("Expected digest"), (unsigned char *)data2_digest,
		   sizeof(digest));
  if (memcmp(digest, data2_digest, sizeof(digest))) {
    SILC_LOG_DEBUG(("Hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Hash is successful"));

  success = TRUE;
  
 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_free(data2);
  silc_hash_free(sha1);
  silc_hash_unregister_all();
  return success;
}
