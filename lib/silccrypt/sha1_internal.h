/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/
/* Header portion split from main code for convenience (AYB 3/02/98) */

#ifndef SHA1_INTERNAL_H
#define SHA1_INTERNAL_H

/*
Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/* Context declaration */
typedef struct {
    SilcUInt32 state[5];
    SilcUInt32 count[2];
    unsigned char buffer[64];
} SHA1_CTX;

/* Function forward declerations */
void SHA1Transform(SilcUInt32 *state, const unsigned char *data);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, unsigned char* data, SilcUInt32 len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#endif
