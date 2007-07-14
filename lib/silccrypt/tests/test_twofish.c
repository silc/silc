
#include "silc.h"

/* CBC */

/* First test vector, 16 bytes plaintext, 128 bits key */
const unsigned char key1[] = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06";
int key1_len = 16 * 8;
const unsigned char iv1[] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";
const unsigned char p1[] = "Single block msg";
int p1_len = 16;
const unsigned char c1[] = "\x6C\x98\x5B\xF3\x71\x63\x4D\x57\x01\x95\x8D\x2D\x45\x01\xAA\x27";

/* Second test vector, 32 bytes plaintext, 128 bits key */
const unsigned char key2[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
int key2_len = 16 * 8;
const unsigned char iv2[] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
const unsigned char p2[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
int p2_len = 32;
const unsigned char c2[] = "\x58\x31\x6E\xAB\x22\xF1\x13\x00\x03\xA6\x21\x7B\xAF\x9F\xF5\x4D\x60\x0E\xC3\x3F\xF8\x0B\xF9\x4D\x16\x47\x38\x64\x04\xFD\xFE\xD3";

/* CTR */

/* 16 bytes plaintext, 128 bits key */
const unsigned char key3[] = "\xAE\x68\x52\xF8\x12\x10\x67\xCC\x4B\xF7\xA5\x76\x55\x77\xF3\x9E";
int key3_len = 16 * 8;
const unsigned char iv3[] = "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const unsigned char p3[] = "Single block msg";
int p3_len = 16;
const unsigned char c3[] = "\x88\x56\x65\x38\x6F\xEB\x2C\x97\xCD\x35\xB7\xB5\x7B\x3C\xC7\x3E";

/* 32 bytes plaintext, 128 bits key */
const unsigned char key4[] = "\x7E\x24\x06\x78\x17\xFA\xE0\xD7\x43\xD6\xCE\x1F\x32\x53\x91\x63";
int key4_len = 16 * 8;
const unsigned char iv4[] = "\x00\x6C\xB6\xDB\xC0\x54\x3B\x59\xDA\x48\xD9\x0B\x00\x00\x00\x00";
const unsigned char p4[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
int p4_len = 32;
const unsigned char c4[] = "\x00\xAD\x58\xD3\x76\x12\x7D\xD4\x09\xDC\x38\x4D\x3E\x19\x3F\xC8\x58\x8E\x8A\xF6\xAD\x97\x39\x18\x16\xA6\x11\x06\xC4\x86\x5E\xB2";

/* 36 bytes plaintext, 256 bits key */
const unsigned char key5[] = "\xFF\x7A\x61\x7C\xE6\x91\x48\xE4\xF1\x72\x6E\x2F\x43\x58\x1D\xE2\xAA\x62\xD9\xF8\x05\x53\x2E\xDF\xF1\xEE\xD6\x87\xFB\x54\x15\x3D";
int key5_len = 32 * 8;
const unsigned char iv5[] = "\x00\x1C\xC5\xB7\x51\xA5\x1D\x70\xA1\xC1\x11\x48\x00\x00\x00\x00";
const unsigned char p5[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23";
int p5_len = 36;
const unsigned char c5[] = "\x71\x2F\x9C\xE1\x4F\xD5\x9E\xBF\x6A\x1E\x7D\x76\x0C\xBA\x70\xE9\x5E\xCE\x27\xAD\x5B\xE1\x38\xDB\x99\xEF\x46\x78\x4D\xCF\x99\x24\x63\x0E\x84\x58";

/* CFB */

/* 36 bytes plaintext, 256 bits key */
const unsigned char key6[] = "\xFF\x7A\x61\x7C\xE6\x91\x48\xE4\xF1\x72\x6E\x2F\x43\x58\x1D\xE2\xAA\x62\xD9\xF8\x05\x53\x2E\xDF\xF1\xEE\xD6\x87\xFB\x54\x15\x3D";
int key6_len = 32 * 8;
const unsigned char iv6[] = "\x00\x1C\xC5\xB7\x51\xA5\x1D\x70\xA1\xC1\x11\x48\x00\x00\x00\x00";
const unsigned char p6[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23";
int p6_len = 36;
const unsigned char c6[] = "\x2C\x0E\x4D\xEF\xE4\x71\xEB\x2A\x4B\x03\x21\x96\xD1\xCD\x73\xD7\x3A\xA9\xEB\x08\x87\xB2\xAB\x66\x28\x3A\xC2\x99\xB7\x13\x8C\x92\xEA\xD6\xFD\x41";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcCipher cipher, cipher2;
  unsigned char dst[256], pdst[256];
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*twofish*,*cipher*");
  }

  SILC_LOG_DEBUG(("Registering builtin hash functions"));
  silc_cipher_register_default();

  SILC_LOG_DEBUG(("Allocating twofish-CBC cipher"));
  if (!silc_cipher_alloc("twofish-128-cbc", &cipher)) {
    SILC_LOG_DEBUG(("Allocating twofish-CBC cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("twofish-128-cbc", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating twofish-CBC cipher failed"));
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


  SILC_LOG_DEBUG(("Allocating twofish-128-ctr cipher"));
  if (!silc_cipher_alloc("twofish-128-ctr", &cipher)) {
    SILC_LOG_DEBUG(("Allocating twofish-128-ctr cipher failed"));
    goto err;
  }

  /* Third test vector */
  SILC_LOG_DEBUG(("CTR test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv3);
  assert(silc_cipher_set_key(cipher, key3, key3_len, TRUE));
  assert(silc_cipher_encrypt(cipher, p3, dst, p3_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p3, p3_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p3_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c3, p3_len);
  if (memcmp(dst, c3, p3_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher, iv3);
  assert(silc_cipher_decrypt(cipher, dst, pdst, p3_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p3_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p3, p3_len);
  if (memcmp(pdst, p3, p3_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));


  /* Fourth test vector */
  SILC_LOG_DEBUG(("CTR test vector"));
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

  SILC_LOG_DEBUG(("Allocating twofish-256-ctr cipher"));
  if (!silc_cipher_alloc("twofish-256-ctr", &cipher)) {
    SILC_LOG_DEBUG(("Allocating twofish-256-ctr cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("twofish-256-ctr", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating twofish-256-ctr cipher failed"));
    goto err;
  }

  /* Fifth test vector */
  SILC_LOG_DEBUG(("CTR test vector"));
  memset(dst, 0, sizeof(dst));
  memset(pdst, 0, sizeof(pdst));
  silc_cipher_set_iv(cipher, iv5);
  assert(silc_cipher_set_key(cipher, key5, key5_len, TRUE));
  assert(silc_cipher_set_key(cipher2, key5, key5_len, FALSE));
  assert(silc_cipher_encrypt(cipher, p5, dst, p5_len, NULL));
  SILC_LOG_DEBUG(("block len %d, key len %d, name %s",
		 silc_cipher_get_block_len(cipher),
		 silc_cipher_get_key_len(cipher),
		 silc_cipher_get_name(cipher)));
  SILC_LOG_HEXDUMP(("Plaintext"), (unsigned char *)p5, p5_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), (unsigned char *)dst, p5_len);
  SILC_LOG_HEXDUMP(("Expected ciphertext"), (unsigned char *)c5, p5_len);
  if (memcmp(dst, c5, p5_len)) {
    SILC_LOG_DEBUG(("Encrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encrypt is successful"));
  silc_cipher_set_iv(cipher2, iv5);
  assert(silc_cipher_decrypt(cipher2, dst, pdst, p5_len, NULL));
  SILC_LOG_HEXDUMP(("Decrypted plaintext"), (unsigned char *)pdst, p5_len);
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p5, p5_len);
  if (memcmp(pdst, p5, p5_len)) {
    SILC_LOG_DEBUG(("Decrypt failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypt is successful"));
  silc_cipher_free(cipher2);


  SILC_LOG_DEBUG(("Allocating twofish-256-cfb cipher"));
  if (!silc_cipher_alloc("twofish-256-cfb", &cipher)) {
    SILC_LOG_DEBUG(("Allocating twofish-256-cfb cipher failed"));
    goto err;
  }
  if (!silc_cipher_alloc("twofish-256-cfb", &cipher2)) {
    SILC_LOG_DEBUG(("Allocating twofish-256-cfb cipher failed"));
    goto err;
  }

  /* Fifth test vector */
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
  SILC_LOG_HEXDUMP(("Expected plaintext"), (unsigned char *)p5, p6_len);
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

  silc_cipher_free(cipher);
  silc_cipher_unregister_all();
  return success;
}
