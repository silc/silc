#include "silc.h"

/* Test vectors from */

/* First test vector, 16 bytes plaintext, 56, 168 bits key */
const unsigned char key1[] = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06";
int key1_len = 8 * 8;
const unsigned char iv1[] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";
const unsigned char p1[] = "Single block msg";
int p1_len = 16;
const unsigned char c1[] = "\xD1\xB4\x0D\xB2\x53\x55\x82\xC4\x6A\xF4\xFC\xC4\x86\x8C\xCE\xCA";

/* Second test vector, 32 bytes plaintext, 56, 168 bits key */
const unsigned char key2[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
int key2_len = 8 * 8;
const unsigned char iv2[] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
const unsigned char p2[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
int p2_len = 32;
const unsigned char c2[] = "\xE8\xDE\x56\x51\x45\xD0\x68\xD8\x4D\x6F\x2F\x0C\xAF\xB5\xBE\xD7\xD1\x6C\xF6\x7B\x60\x24\xB7\x9D\x6E\xB7\x4D\xF7\x5B\xF1\x82\x0E";

/* CTR test vectors from RFC3686. */

/* 32 bytes plaintext, 56, 168 bits key */
const unsigned char key4[] = "\x7E\x24\x06\x78\x17\xFA\xE0\xD7\x43\xD6\xCE\x1F\x32\x53\x91\x63";
int key4_len = 8 * 8;
const unsigned char iv4[] = "\x00\x6C\xB6\xDB\xC0\x54\x3B\x59\xDA\x48\xD9\x0B\x00\x00\x00\x00";
const unsigned char p4[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
int p4_len = 32;
const unsigned char c4[] = "\xF0\xEC\xDF\xE4\x77\x2D\x9D\x94\x7E\xB0\x49\x06\x08\x8E\x48\x2A\x84\xF3\xF6\x01\x43\x8D\x9D\x4B\x78\x59\x5B\xAE\x3A\x8D\x59\x5D";

/* 36 bytes plaintext, 56, 168 bits key */
const unsigned char key5[] = "\xFF\x7A\x61\x7C\xE6\x91\x48\xE4\xF1\x72\x6E\x2F\x43\x58\x1D\xE2\xAA\x62\xD9\xF8\x05\x53\x2E\xDF\xF1\xEE\xD6\x87\xFB\x54\x15\x3D";
int key5_len = 8 * 8;
const unsigned char iv5[] = "\x00\x1C\xC5\xB7\x51\xA5\x1D\x70\xA1\xC1\x11\x48\x00\x00\x00\x00";
const unsigned char p5[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23";
int p5_len = 36;
const unsigned char c5[] = "\xEB\x6C\x52\x82\x1D\x0B\xBB\xF7\xCE\x75\x94\x46\x2A\xCA\x4F\xAA\xB4\x07\xDF\x86\x65\x69\xFD\x07\xF4\x8C\xC0\xB5\x83\xD6\x07\x1F\x1E\xC0\xE6\xB8";

/* CFB */

/* 36 bytes plaintext, 56, 168 bits key */
const unsigned char key6[] = "\xFF\x7A\x61\x7C\xE6\x91\x48\xE4\xF1\x72\x6E\x2F\x43\x58\x1D\xE2\xAA\x62\xD9\xF8\x05\x53\x2E\xDF\xF1\xEE\xD6\x87\xFB\x54\x15\x3D";
int key6_len = 32 * 8;
const unsigned char iv6[] = "\x00\x1C\xC5\xB7\x51\xA5\x1D\x70\xA1\xC1\x11\x48\x00\x00\x00\x00";
const unsigned char p6[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23";
int p6_len = 36;
const unsigned char c6[] = "\x7A\xD8\x13\x76\xB8\x0B\xEC\xC7\x0C\xA8\x5F\x7C\xEB\xB9\xD9\xCD\x39\x7E\x89\x94\xAA\xD2\x9C\xB6\x92\xF0\xD0\xEC\x7F\x80\x5B\x74\xBD\x1B\xFE\xB0";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcCipher cipher, cipher2;
  unsigned char dst[256], pdst[256];
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*des*,*cipher*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_cipher_register_default();

  SILC_LOG_DEBUG(("Allocating des-CBC cipher"));
  if (!silc_cipher_alloc("des-56-cbc", &cipher)) {
    SILC_LOG_DEBUG(("Allocating cas5-CBC cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("des-56-cbc", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating des-CBC cipher failed"));
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

  SILC_LOG_DEBUG(("Allocating des-56-ctr cipher"));
  if (!silc_cipher_alloc("des-56-ctr", &cipher)) {
    SILC_LOG_DEBUG(("Allocating des-56-ctr cipher failed"));
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


  SILC_LOG_DEBUG(("Allocating des-56-cfb cipher"));
  if (!silc_cipher_alloc("des-56-cfb", &cipher)) {
    SILC_LOG_DEBUG(("Allocating des-56-cfb cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("des-56-cfb", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating des-56-cfb cipher failed"));
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


  /* 3des */

  SILC_LOG_DEBUG(("Allocating 3des-CBC cipher"));
  if (!silc_cipher_alloc("3des-168-cbc", &cipher)) {
    SILC_LOG_DEBUG(("Allocating cas5-CBC cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("3des-168-cbc", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating 3des-CBC cipher failed"));
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
#if 0
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c1, p1_len);
  if (memcmp(dst, c1, p1_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
#endif
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
#if 0
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c2, p2_len);
  if (memcmp(dst, c2, p2_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
#endif
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

  SILC_LOG_DEBUG(("Allocating 3des-168-ctr cipher"));
  if (!silc_cipher_alloc("3des-168-ctr", &cipher)) {
    SILC_LOG_DEBUG(("Allocating 3des-168-ctr cipher failed"));
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
#if 0
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c4, p4_len);
  if (memcmp(dst, c4, p4_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
#endif
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


  SILC_LOG_DEBUG(("Allocating 3des-168-cfb cipher"));
  if (!silc_cipher_alloc("3des-168-cfb", &cipher)) {
    SILC_LOG_DEBUG(("Allocating 3des-168-cfb cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("3des-168-cfb", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating 3des-168-cfb cipher failed"));
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
#if 0
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c6, p6_len);
  if (memcmp(dst, c6, p6_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
#endif
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
