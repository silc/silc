#include "silc.h"

/* First test vector, 8 bytes plaintext, 128 bits key */
const unsigned char key1[] = "\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45\x67\x89\x34\x56\x78\x9a";
int key1_len = 16 * 8;
const unsigned char iv1[] = "\xef\xcd\xab\x89\x67\x45\x23\x01";
const unsigned char p1[] = "\x01\x23\x45\x67\x89\xab\xcd\xef";
int p1_len = 8;
const unsigned char c1[] = "\x84\x00\x0a\x34\x1b\xf9\x1f\xb3";

/* Second test vector, 32 bytes plaintext, 128 bits key */
const unsigned char key2[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
int key2_len = 16 * 8;
const unsigned char iv2[] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
const unsigned char p2[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
int p2_len = 32;
const unsigned char c2[] = "\x23\xA5\xBD\xC5\x2A\x59\xD4\x06\x61\xBF\xF3\x47\x76\x4B\xC8\x41\x1C\x65\xE3\xE2\x1A\x1F\x42\x4B\xBD\x22\xDF\xEC\xD9\xC9\x52\x43";

/* CTR */

/* 32 bytes plaintext, 128 bits key */
const unsigned char key4[] = "\x7E\x24\x06\x78\x17\xFA\xE0\xD7\x43\xD6\xCE\x1F\x32\x53\x91\x63";
int key4_len = 16 * 8;
const unsigned char iv4[] = "\x00\x6C\xB6\xDB\xC0\x54\x3B\x59\xDA\x48\xD9\x0B\x00\x00\x00\x00";
const unsigned char p4[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
int p4_len = 32;
const unsigned char c4[] = "\xAA\x16\xEC\xEA\x77\x73\x12\xC1\x14\x0F\x10\x65\x06\x72\xF8\xE5\x89\xCF\x26\x2C\x84\xC6\x3A\x93\xEE\xC0\xB2\xBA\x92\xAD\x19\xCA";

/* CFB */

/* 36 bytes plaintext, 128 bits key */
const unsigned char key6[] = "\xFF\x7A\x61\x7C\xE6\x91\x48\xE4\xF1\x72\x6E\x2F\x43\x58\x1D\xE2\xAA\x62\xD9\xF8\x05\x53\x2E\xDF\xF1\xEE\xD6\x87\xFB\x54\x15\x3D";
int key6_len = 16 * 8;
const unsigned char iv6[] = "\x00\x1C\xC5\xB7\x51\xA5\x1D\x70\xA1\xC1\x11\x48\x00\x00\x00\x00";
const unsigned char p6[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23";
int p6_len = 36;
const unsigned char c6[] = "\xE2\x30\xB2\x57\x12\x31\x04\x54\x37\xEC\xF1\x43\xC1\x3F\x20\x53\xA4\xDD\x99\x29\x3C\xCA\x4A\x7C\xCC\xEA\x12\xBF\xA8\x05\x37\x89\xA9\xB3\x3B\x15";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcCipher cipher, cipher2;
  unsigned char dst[256], pdst[256];
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*cast*,*cipher*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_cipher_register_default();

  SILC_LOG_DEBUG(("Allocating cast5-CBC cipher"));
  if (!silc_cipher_alloc("cast5-128-cbc", &cipher)) {
    SILC_LOG_DEBUG(("Allocating cas5-CBC cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("cast5-128-cbc", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating cast5-CBC cipher failed"));
    goto err;
  }

  /* First test vector */
  SILC_LOG_DEBUG(("First test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv1);
  assert(silc_cipher_set_key(cipher, key1, key1_len, TRUE));
  assert(silc_cipher_set_key(cipher2, key1, key1_len, FALSE));
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
  silc_cipher_set_iv(cipher2, iv1);
  assert(silc_cipher_decrypt(cipher2, dst, pdst, p1_len, NULL));
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
  assert(silc_cipher_set_key(cipher, key2, key2_len, TRUE));
  assert(silc_cipher_set_key(cipher2, key2, key2_len, FALSE));
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
  silc_cipher_set_iv(cipher2, iv2);
  assert(silc_cipher_decrypt(cipher2, dst, pdst, p2_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p2_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p2, p2_len);
  if (memcmp(pdst, p2, p2_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));
  silc_cipher_free(cipher);
  silc_cipher_free(cipher2);

  SILC_LOG_DEBUG(("Allocating cast5-128-ctr cipher"));
  if (!silc_cipher_alloc("cast5-128-ctr", &cipher)) {
    SILC_LOG_DEBUG(("Allocating cast5-128-ctr cipher failed"));
    goto err;
  }

  /* Fourth test vector */
  SILC_LOG_DEBUG(("Fourth test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv4);
  assert(silc_cipher_set_key(cipher, key4, key4_len, TRUE));
  assert(silc_cipher_encrypt(cipher, p4, dst, p4_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p4, p4_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p4_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c4, p4_len);
  if (memcmp(dst, c4, p4_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher, iv4);
  assert(silc_cipher_decrypt(cipher, dst, pdst, p4_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p4_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p4, p4_len);
  if (memcmp(pdst, p4, p4_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));
  silc_cipher_free(cipher);


  SILC_LOG_DEBUG(("Allocating cast5-128-cfb cipher"));
  if (!silc_cipher_alloc("cast5-128-cfb", &cipher)) {
    SILC_LOG_DEBUG(("Allocating cast5-128-cfb cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("cast5-128-cfb", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating cast5-128-cfb cipher failed"));
    goto err;
  }

  SILC_LOG_DEBUG(("CFB test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv6);
  assert(silc_cipher_set_key(cipher, key6, key6_len, TRUE));
  assert(silc_cipher_set_key(cipher2, key6, key6_len, FALSE));
  assert(silc_cipher_encrypt(cipher, p6, dst, p6_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p6, p6_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p6_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c6, p6_len);
  if (memcmp(dst, c6, p6_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher2, iv6);
  assert(silc_cipher_decrypt(cipher2, dst, pdst, p6_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p6_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p6, p6_len);
  if (memcmp(pdst, p6, p6_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));
  silc_cipher_free(cipher2);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_cipher_unregister_all();
  return success;
}
