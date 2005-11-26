
#include "silcincludes.h"

/* Test vectors from RFC3602. */

/* First test vector, 16 bytes plaintext, 128 bits key */
const unsigned char key1[] = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06";
int key1_len = 16 * 8;
const unsigned char iv1[] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";
const unsigned char p1[] = "Single block msg";
int p1_len = 16;
const unsigned char c1[] = "\xe3\x53\x77\x9c\x10\x79\xae\xb8\x27\x08\x94\x2d\xbe\x77\x18\x1a";

/* Second test vector, 32 bytes plaintext, 128 bits key */
const unsigned char key2[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
int key2_len = 16 * 8;
const unsigned char iv2[] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
const unsigned char p2[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
int p2_len = 32;
const unsigned char c2[] = "\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1";


int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcCipher cipher;
  unsigned char dst[256], pdst[256];
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*aes*,*cipher*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_cipher_register_default();

  if (!silc_cipher_is_supported("aes-128-cbc")) {
    SILC_LOG_DEBUG(("aes-128-cbc is not supported"));
    goto err;
  }

  SILC_LOG_DEBUG(("Allocating AES-CBC cipher"));
  if (!silc_cipher_alloc("aes-128-cbc", &cipher)) {
    SILC_LOG_DEBUG(("Allocating AES-CBC cipher failed"));
    goto err;
  }

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv1);
  assert(silc_cipher_set_key(cipher, key1, key1_len));
  assert(silc_cipher_encrypt(cipher, p1, dst, p1_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p1, p1_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p1_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c1, p1_len);
  if (memcmp(dst, c1, p1_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher, iv1);
  assert(silc_cipher_decrypt(cipher, dst, pdst, p1_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p1_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p1, p1_len);
  if (memcmp(pdst, p1, p1_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));


  /* Second test vector */
  SILC_LOG_DEBUG(("Second test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv2);
  assert(silc_cipher_set_key(cipher, key2, key2_len));
  assert(silc_cipher_encrypt(cipher, p2, dst, p2_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p2, p2_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p2_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c2, p2_len);
  if (memcmp(dst, c2, p2_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher, iv2);
  assert(silc_cipher_decrypt(cipher, dst, pdst, p2_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p2_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p2, p2_len);
  if (memcmp(pdst, p2, p2_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_cipher_free(cipher);
  silc_cipher_unregister_all();
  return success;
}
