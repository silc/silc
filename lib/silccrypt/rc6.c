/* Modified for SILC. -Pekka */

/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         RC6 by Ron Rivest and RSA Labs                               */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* Timing data for RC6 (rc6.c)

128 bit key:
Key Setup:    1632 cycles
Encrypt:       270 cycles =    94.8 mbits/sec
Decrypt:       226 cycles =   113.3 mbits/sec
Mean:          248 cycles =   103.2 mbits/sec

192 bit key:
Key Setup:    1885 cycles
Encrypt:       267 cycles =    95.9 mbits/sec
Decrypt:       235 cycles =   108.9 mbits/sec
Mean:          251 cycles =   102.0 mbits/sec

256 bit key:
Key Setup:    1877 cycles
Encrypt:       270 cycles =    94.8 mbits/sec
Decrypt:       227 cycles =   112.8 mbits/sec
Mean:          249 cycles =   103.0 mbits/sec

*/

#include "silcincludes.h"
#include "rc6.h"

/* 
 * SILC Crypto API for RC6
 */

/* Sets the key for the cipher. */

SILC_CIPHER_API_SET_KEY(rc6)
{
  rc6_set_key((RC6Context *)context, (uint32 *)key, keylen);
  return 1;
}

/* Sets the string as a new key for the cipher. The string is first
   hashed and then used as a new key. */

SILC_CIPHER_API_SET_KEY_WITH_STRING(rc6)
{
  return 1;
}

/* Encrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_ENCRYPT_CBC(rc6)
{
  uint32 *in, *out, *tiv;
  uint32 tmp[4];
  int i;

  in = (uint32 *)src;
  out = (uint32 *)dst;
  tiv = (uint32 *)iv;

  tmp[0] = in[0] ^ tiv[0];
  tmp[1] = in[1] ^ tiv[1];
  tmp[2] = in[2] ^ tiv[2];
  tmp[3] = in[3] ^ tiv[3];
  rc6_encrypt((RC6Context *)context, tmp, out);
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp[0] = in[0] ^ out[0 - 4];
    tmp[1] = in[1] ^ out[1 - 4];
    tmp[2] = in[2] ^ out[2 - 4];
    tmp[3] = in[3] ^ out[3 - 4];
    rc6_encrypt((RC6Context *)context, tmp, out);
    in += 4;
    out += 4;
  }

  tiv[0] = out[0 - 4];
  tiv[1] = out[1 - 4];
  tiv[2] = out[2 - 4];
  tiv[3] = out[3 - 4];

  return TRUE;
}

/* Decrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_DECRYPT_CBC(rc6)
{
  uint32 *in, *out, *tiv;
  uint32 tmp[4], tmp2[4];
  int i;

  in = (uint32 *)src;
  out = (uint32 *)dst;
  tiv = (uint32 *)iv;

  tmp[0] = in[0];
  tmp[1] = in[1];
  tmp[2] = in[2];
  tmp[3] = in[3];
  rc6_decrypt((RC6Context *)context, in, out);
  out[0] ^= tiv[0];
  out[1] ^= tiv[1];
  out[2] ^= tiv[2];
  out[3] ^= tiv[3];
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp2[0] = tmp[0];
    tmp2[1] = tmp[1];
    tmp2[2] = tmp[2];
    tmp2[3] = tmp[3];
    tmp[0] = in[0];
    tmp[1] = in[1];
    tmp[2] = in[2];
    tmp[3] = in[3];
    rc6_decrypt((RC6Context *)context, in, out);
    out[0] ^= tmp2[0];
    out[1] ^= tmp2[1];
    out[2] ^= tmp2[2];
    out[3] ^= tmp2[3];
    in += 4;
    out += 4;
  }

  tiv[0] = tmp[0];
  tiv[1] = tmp[1];
  tiv[2] = tmp[2];
  tiv[3] = tmp[3];

  return TRUE;
}

/* Returns the size of the cipher context. */

SILC_CIPHER_API_CONTEXT_LEN(rc6)
{
  return sizeof(RC6Context);
}


#define f_rnd(i,a,b,c,d)                    \
        u = rotl(d * (d + d + 1), 5);       \
        t = rotl(b * (b + b + 1), 5);       \
        a = rotl(a ^ t, u) + l_key[i];      \
        c = rotl(c ^ u, t) + l_key[i + 1]

#define i_rnd(i,a,b,c,d)                    \
        u = rotl(d * (d + d + 1), 5);       \
        t = rotl(b * (b + b + 1), 5);       \
        c = rotr(c - l_key[i + 1], t) ^ u;  \
        a = rotr(a - l_key[i], u) ^ t

/* initialise the key schedule from the user supplied key   */

u4byte *rc6_set_key(RC6Context *ctx, 
		    const u4byte in_key[], const u4byte key_len)
{   
    u4byte  i, j, k, a, b, l[8], t;
    u4byte *l_key = ctx->l_key;

    l_key[0] = 0xb7e15163;

    for(k = 1; k < 44; ++k)
        
        l_key[k] = l_key[k - 1] + 0x9e3779b9;

    for(k = 0; k < key_len / 32; ++k)

        l[k] = in_key[k];

    t = (key_len / 32) - 1; // t = (key_len / 32);

    a = b = i = j = 0;

    for(k = 0; k < 132; ++k)
    {   a = rotl(l_key[i] + a + b, 3); b += a;
        b = rotl(l[j] + b, b);
        l_key[i] = a; l[j] = b;
        i = (i == 43 ? 0 : i + 1); // i = (i + 1) % 44;  
        j = (j == t ? 0 : j + 1);  // j = (j + 1) % t;
    }

    return l_key;
};

/* encrypt a block of text  */

void rc6_encrypt(RC6Context *ctx,
		 const u4byte in_blk[4], u4byte out_blk[4])
{   
    u4byte  a,b,c,d,t,u;
    u4byte *l_key = ctx->l_key;

    a = in_blk[0]; b = in_blk[1] + l_key[0];
    c = in_blk[2]; d = in_blk[3] + l_key[1];

    f_rnd( 2,a,b,c,d); f_rnd( 4,b,c,d,a);
    f_rnd( 6,c,d,a,b); f_rnd( 8,d,a,b,c);
    f_rnd(10,a,b,c,d); f_rnd(12,b,c,d,a);
    f_rnd(14,c,d,a,b); f_rnd(16,d,a,b,c);
    f_rnd(18,a,b,c,d); f_rnd(20,b,c,d,a);
    f_rnd(22,c,d,a,b); f_rnd(24,d,a,b,c);
    f_rnd(26,a,b,c,d); f_rnd(28,b,c,d,a);
    f_rnd(30,c,d,a,b); f_rnd(32,d,a,b,c);
    f_rnd(34,a,b,c,d); f_rnd(36,b,c,d,a);
    f_rnd(38,c,d,a,b); f_rnd(40,d,a,b,c);

    out_blk[0] = a + l_key[42]; out_blk[1] = b;
    out_blk[2] = c + l_key[43]; out_blk[3] = d;
};

/* decrypt a block of text  */

void rc6_decrypt(RC6Context *ctx,
		 const u4byte in_blk[4], u4byte out_blk[4])
{   
    u4byte  a,b,c,d,t,u;
    u4byte *l_key = ctx->l_key;

    d = in_blk[3]; c = in_blk[2] - l_key[43]; 
    b = in_blk[1]; a = in_blk[0] - l_key[42];

    i_rnd(40,d,a,b,c); i_rnd(38,c,d,a,b);
    i_rnd(36,b,c,d,a); i_rnd(34,a,b,c,d);
    i_rnd(32,d,a,b,c); i_rnd(30,c,d,a,b);
    i_rnd(28,b,c,d,a); i_rnd(26,a,b,c,d);
    i_rnd(24,d,a,b,c); i_rnd(22,c,d,a,b);
    i_rnd(20,b,c,d,a); i_rnd(18,a,b,c,d);
    i_rnd(16,d,a,b,c); i_rnd(14,c,d,a,b);
    i_rnd(12,b,c,d,a); i_rnd(10,a,b,c,d);
    i_rnd( 8,d,a,b,c); i_rnd( 6,c,d,a,b);
    i_rnd( 4,b,c,d,a); i_rnd( 2,a,b,c,d);

    out_blk[3] = d - l_key[1]; out_blk[2] = c; 
    out_blk[1] = b - l_key[0]; out_blk[0] = a; 
};
