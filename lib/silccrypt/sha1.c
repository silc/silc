/* Modified to work on various platforms. -Pekka */
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#include "silc.h"
#include "sha1_internal.h"
#include "sha1.h"

/* 
 * SILC Hash API for SHA1
 */

SILC_HASH_API_INIT(sha1)
{
  SHA1Init((SHA1_CTX *)context);
}

SILC_HASH_API_UPDATE(sha1)
{
  SHA1Update((SHA1_CTX *)context, (unsigned char *)data, len);
}

SILC_HASH_API_FINAL(sha1)
{
  SHA1Final(digest, (SHA1_CTX *)context);
}

SILC_HASH_API_TRANSFORM(sha1)
{
  SHA1Transform(state, buffer);
}

SILC_HASH_API_CONTEXT_LEN(sha1)
{
  return sizeof(SHA1_CTX);
}

void SHA1Init(SHA1_CTX* context)
{
  /* SHA1 initialization constants */
  context->state[0] = 0x67452301L;
  context->state[1] = 0xEFCDAB89L;
  context->state[2] = 0x98BADCFEL;
  context->state[3] = 0x10325476L;
  context->state[4] = 0xC3D2E1F0L;
  context->count[0] = context->count[1] = 0;
}

#define rol(x, nr) (((x) << ((SilcUInt32)(nr))) | ((x) >> (32 - (SilcUInt32)(nr))))

#define GET_WORD(cp) ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24	\
		    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)	\
		    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)	\
		    | ((SilcUInt32)(SilcUInt8)(cp)[3])

#define blk0(i) (W[i] = GET_WORD(data))
#define blk1(i) (W[i&15] = rol(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15],1))

#define f1(x,y,z) (z^(x&(y^z)))
#define f2(x,y,z) (x^y^z)
#define f3(x,y,z) ((x&y)|(z&(x|y)))
#define f4(x,y,z) (x^y^z)

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=f1(w,x,y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);data+=4;
#define R1(v,w,x,y,z,i) z+=f1(w,x,y)+blk1(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=f2(w,x,y)+blk1(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=f3(w,x,y)+blk1(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=f4(w,x,y)+blk1(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

void SHA1Transform(SilcUInt32 *state, const unsigned char *data)
{
  SilcUInt32 W[16];
  
  /* Copy context->state[] to working vars */
  SilcUInt32 a = state[0];
  SilcUInt32 b = state[1];
  SilcUInt32 c = state[2];
  SilcUInt32 d = state[3];
  SilcUInt32 e = state[4];
  
  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
  
  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  
  /* Wipe variables */
  a = b = c = d = e = 0;
  memset(W, 0, sizeof(W));
}

/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, unsigned char* data, SilcUInt32 len)
{
  SilcUInt32 i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
  context->count[1] += (len >> 29);
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64-j));
    SHA1Transform(context->state, context->buffer);
    for ( ; i + 63 < len; i += 64) {
      SHA1Transform(context->state, &data[i]);
    }
    j = 0;
  }
  else i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
  SilcUInt32 i, j;
  unsigned char finalcount[8];
  
  for (i = 0; i < 8; i++) {
    finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] 
				     >> ((3 - (i & 3)) * 8)) & 255);
  }
  SHA1Update(context, (unsigned char *)"\200", 1);
  while ((context->count[0] & 504) != 448) {
    SHA1Update(context, (unsigned char *)"\0", 1);
  }
  
  SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++) {
    digest[i] = (unsigned char)
      ((context->state[i>>2] >> ((3 - (i & 3)) * 8)) & 255);
  }
  
  /* Wipe variables */
  i = j = 0;
  memset(context->buffer, 0, 64);
  memset(context->state, 0, 20);
  memset(context->count, 0, 8);
  memset(finalcount, 0, 8);
  SHA1Transform(context->state, context->buffer);
}
