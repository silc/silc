/* file ripped from noiz-0.5. -Pekka.  Public domain. */

#ifndef MD5_INTERNAL_H
#define MD5_INTERNAL_H

struct MD5Context {
  SilcUInt32 buf[4];
  SilcUInt32 bits[2];
  unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(SilcUInt32 buf[4], const unsigned char kbuf[64]);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#endif
