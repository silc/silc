/*
 * rc5.c				RC5-32/16/b
 *
 * Copyright (c) 1999 Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, dis-
 * tribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the fol-
 * lowing conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
 * ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT
 * SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABIL-
 * ITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of the authors shall
 * not be used in advertising or otherwise to promote the sale, use or
 * other dealings in this Software without prior written authorization from
 * the authors.
 *
 */

/*
 * Based on RC5 reference code and on description of Bruce Schneier's
 * Applied Cryptography.
 *
 * This implementation has a word size of 32 bits, a rounds of 16 and
 * variable key length from 128 and 192 up to 256 bits.
 *
 */

#include "silc.h"
#include "rc5_internal.h"
#include "rc5.h"

/*
 * SILC Crypto API for RC5
 */

/* Sets the key for the cipher. */

SILC_CIPHER_API_SET_KEY(rc5)
{
  SilcUInt32 k[8];

  SILC_GET_WORD_KEY(key, k, keylen);
  rc5_set_key((RC5Context *)context, k, keylen);

  return TRUE;
}

/* Returns the size of the cipher context. */

SILC_CIPHER_API_CONTEXT_LEN(rc5)
{
  return sizeof(RC5Context);
}

/* Encrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_ENCRYPT_CBC(rc5)
{
  SilcUInt32 tiv[4];
  int i;

  SILC_CBC_GET_IV(tiv, iv);

  SILC_CBC_ENC_PRE(tiv, src);
  rc5_encrypt((RC5Context *)context, tiv, tiv);
  SILC_CBC_ENC_POST(tiv, dst, src);

  for (i = 16; i < len; i += 16) {
    SILC_CBC_ENC_PRE(tiv, src);
    rc5_encrypt((RC5Context *)context, tiv, tiv);
    SILC_CBC_ENC_POST(tiv, dst, src);
  }

  SILC_CBC_PUT_IV(tiv, iv);

  return TRUE;
}

/* Decrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_DECRYPT_CBC(rc5)
{
  SilcUInt32 tmp[4], tmp2[4], tiv[4];
  int i;

  SILC_CBC_GET_IV(tiv, iv);

  SILC_CBC_DEC_PRE(tmp, src);
  rc5_decrypt((RC5Context *)context, tmp, tmp2);
  SILC_CBC_DEC_POST(tmp2, dst, src, tmp, tiv);

  for (i = 16; i < len; i += 16) {
    SILC_CBC_DEC_PRE(tmp, src);
    rc5_decrypt((RC5Context *)context, tmp, tmp2);
    SILC_CBC_DEC_POST(tmp2, dst, src, tmp, tiv);
  }

  SILC_CBC_PUT_IV(tiv, iv);

  return TRUE;
}

/* RC5 encryption */
#define RC5E(i, A, B)				\
		A = A ^ B;			\
		A = rotl(A, B) + S[i];		\
		B = B ^ A;			\
		B = rotl(B, A) + S[i + 1];

/* RC5 decryption */
#define RC5D(i, A, B)				\
		B = B - S[i + 1];		\
		B = rotr(B, A) ^ A;		\
		A = A - S[i];			\
		A = rotr(A, B) ^ B;

/* Sets RC5 key */

int rc5_set_key(RC5Context *ctx, const SilcUInt32 in_key[], int key_len)
{
	u32 i, j, k, A, B, L[c];
	u32 *out_key = ctx->out_key;

	if (key_len < b || key_len > (2 * b))
		return -1;

	/* init L */
	for (i = 0; i < key_len / w; i++)
		L[i] = in_key[i];

	/* init key array (S) */
	out_key[0] = 0xb7e15163;
	for (i = 1; i < t; i++)
		out_key[i] = out_key[i - 1] + 0x9e3779b9;

	/* mix L and key array (S) */
	A = B = 0;
	for (k = i = j = 0; k < (3 * t); k++) {
		A = rotl(out_key[i] + (A + B), 3);
		B += A;
		B = rotl(L[j] + B, B);
		out_key[i] = A;
		L[j] = B;
		i = (i + 1) % t;
		j = (j + 1) % c;
	}

	return 0;
}

/* Encrypts *one* block at a time. */

int rc5_encrypt(RC5Context *ctx, u32 *in, u32 *out)
{
	u32 A, B;
	u32 *S = ctx->out_key;

	A = in[0] + S[0];
	B = in[1] + S[1];

	RC5E(2, A, B); RC5E(4, A, B);
	RC5E(6, A, B); RC5E(8, A, B);
	RC5E(10, A, B); RC5E(12, A, B);
	RC5E(14, A, B); RC5E(16, A, B);
	RC5E(18, A, B); RC5E(20, A, B);
	RC5E(22, A, B); RC5E(24, A, B);
	RC5E(26, A, B); RC5E(28, A, B);
	RC5E(30, A, B); RC5E(32, A, B);

	out[0] = A;
	out[1] = B;

	return 0;
}

/* Decrypts *one* block at a time. */

int rc5_decrypt(RC5Context *ctx, u32 *in, u32 *out)
{
	u32 A, B;
	u32 *S = ctx->out_key;

	A = in[0];
	B = in[1];

	RC5D(32, A, B); RC5D(30, A, B);
	RC5D(28, A, B); RC5D(26, A, B);
	RC5D(24, A, B); RC5D(22, A, B);
	RC5D(20, A, B); RC5D(18, A, B);
	RC5D(16, A, B); RC5D(14, A, B);
	RC5D(12, A, B); RC5D(10, A, B);
	RC5D(8, A, B); RC5D(6, A, B);
	RC5D(4, A, B); RC5D(2, A, B);

	out[0] = A - S[0];
	out[1] = B - S[1];

	return 0;
}
