/* 
   PKCS #1 RSA wrapper.

   Heavily modified to work under SILC, code that is not needed in SILC has
   been removed for good, and some code was fixed and changed.

   For example, RSA_DecodeOneBlock was not used at all by Mozilla, however,
   I took this code in to use after doing some fixing.  Also, OAEP is removed
   totally for now.  I'm not sure whether OAEP could be used in the future
   with SILC but not for now.

   This file also implements partial SILC PKCS API for RSA with PKCS #1.
   It is partial because all the other functions but encrypt, decrypt,
   sign and verify are common.

   Note:

   The mandatory PKCS #1 implementation in SILC must be compliant to either
   PKCS #1 version 1.5 or PKCS #1 version 2 with the following notes:
   The signature encoding is always in same format as the encryption
   encoding regardles of the PKCS #1 version.  The signature with
   appendix (with hash algorithm OID in the data) must not be used
   in the SILC.  Rationale for this is that there is no binding between
   the PKCS #1 OIDs and the hash algorithms used in the SILC protocol.
   Hence, the encoding is always in PKCS #1 version 1.5 format.

   Any questions and comments regarding this modified version should be
   sent to priikone@poseidon.pspt.fi.

   References: ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc,
               ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1.asc,
	       and RFC 2437.

   Copyright notice: All code, including the SILC PKCS API code that is
   not part of the Mozilla code, falls under the same license found attached
   to this file, below.
*/

/*
 * PKCS#1 encoding and decoding functions.
 * This file is believed to contain no code licensed from other parties.
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 *
 * $Id$
 */

#include "silcincludes.h"

#define RSA_BLOCK_MIN_PAD_LEN		8
#define RSA_BLOCK_FIRST_OCTET		0x00
#define RSA_BLOCK_PRIVATE0_PAD_OCTET	0x00
#define RSA_BLOCK_PRIVATE_PAD_OCTET	0xff
#define RSA_BLOCK_AFTER_PAD_OCTET	0x00

/*
 * RSA block types
 *
 * The actual values are important -- they are fixed, *not* arbitrary.
 * The explicit value assignments are not needed (because C would give
 * us those same values anyway) but are included as a reminder...
 */
typedef enum {
    RSA_BlockPrivate0 = 0,	/* unused, really */
    RSA_BlockPrivate = 1,	/* pad for a private-key operation */
    RSA_BlockPublic = 2,	/* pad for a public-key operation */
    RSA_BlockTotal
} RSA_BlockType;

/*
 * Format one block of data for public/private key encryption using
 * the rules defined in PKCS #1.
 */
static unsigned char *
RSA_FormatOneBlock(unsigned modulusLen, RSA_BlockType blockType,
		   unsigned char *data, unsigned int data_len)
{
    unsigned char *block;
    unsigned char *bp;
    int padLen;
    int i;

    block = (unsigned char *) silc_malloc(modulusLen);
    if (block == NULL)
	return NULL;

    bp = block;

    /*
     * All RSA blocks start with two octets:
     *	0x00 || BlockType
     */
    *bp++ = RSA_BLOCK_FIRST_OCTET;
    *bp++ = (unsigned char) blockType;

    switch (blockType) {

      /*
       * Blocks intended for private-key operation.
       */
      case RSA_BlockPrivate0: /* essentially unused */
      case RSA_BlockPrivate:	 /* preferred method */
	/*
	 * 0x00 || BT || Pad || 0x00 || ActualData
	 *   1      1   padLen    1      data_len
	 * Pad is either all 0x00 or all 0xff bytes, depending on blockType.
	 */
	padLen = modulusLen - data_len - 3;
	assert(padLen >= RSA_BLOCK_MIN_PAD_LEN);
	memset(bp,
		   blockType == RSA_BlockPrivate0
			? RSA_BLOCK_PRIVATE0_PAD_OCTET
			: RSA_BLOCK_PRIVATE_PAD_OCTET,
		   padLen);
	bp += padLen;
	*bp++ = RSA_BLOCK_AFTER_PAD_OCTET;
	memcpy(bp, data, data_len);
	break;

      /*
       * Blocks intended for public-key operation.
       */
      case RSA_BlockPublic:

	/*
	 * 0x00 || BT || Pad || 0x00 || ActualData
	 *   1      1   padLen    1      data_len
	 * Pad is all non-zero random bytes.
	 */
	padLen = modulusLen - data_len - 3;
	assert(padLen >= RSA_BLOCK_MIN_PAD_LEN);
	for (i = 0; i < padLen; i++) {
	    /* Pad with non-zero random data. */
	    do {
		RNG_GenerateGlobalRandomBytes(bp + i, 1);
	    } while (bp[i] == RSA_BLOCK_AFTER_PAD_OCTET);
	}
	bp += padLen;
	*bp++ = RSA_BLOCK_AFTER_PAD_OCTET;
	memcpy(bp, data, data_len);

	break;

      default:
	assert(0);
	silc_free(block);
	return NULL;
    }

    return block;
}

static int
RSA_FormatBlock(unsigned char **result, unsigned int *result_len,
		unsigned modulusLen,
		RSA_BlockType blockType, unsigned char *data,
		unsigned int data_len)
{
    /*
     * XXX For now assume that the data length fits in a single
     * XXX encryption block; the ASSERTs below force this.
     * XXX To fix it, each case will have to loop over chunks whose
     * XXX lengths satisfy the assertions, until all data is handled.
     * XXX (Unless RSA has more to say about how to handle data
     * XXX which does not fit in a single encryption block?)
     * XXX And I do not know what the result is supposed to be,
     * XXX so the interface to this function may need to change
     * XXX to allow for returning multiple blocks, if they are
     * XXX not wanted simply concatenated one after the other.
     */

    switch (blockType) {
      case RSA_BlockPrivate0:
      case RSA_BlockPrivate:
      case RSA_BlockPublic:
	/*
	 * 0x00 || BT || Pad || 0x00 || ActualData
	 *
	 * The "3" below is the first octet + the second octet + the 0x00
	 * octet that always comes just before the ActualData.
	 */
	assert(data_len <= (modulusLen - (3 + RSA_BLOCK_MIN_PAD_LEN)));

	*result = RSA_FormatOneBlock(modulusLen, blockType, data);
	if (result == NULL) {
	    *result_len = 0;
	    return FALSE;
	}
	*result_len = modulusLen;

	break;

      default:
	*result = NULL;
	*result_len = 0;
	return FALSE;
    }

    return TRUE;
}

/*
 * Takes a formatted block and returns the data part.
 * (This is the inverse of RSA_FormatOneBlock().)
 * In some formats the start of the data is ambiguous;
 * if it is non-zero, expectedLen will disambiguate.
 *
 */
unsigned char *
RSA_DecodeOneBlock(unsigned char *data,
		   unsigned int modulusLen,
		   unsigned int expectedLen,
		   RSA_BlockType bt,
		   unsigned int *pResultLen)
{
    RSA_BlockType blockType;
    unsigned char *dp, *res;
    unsigned int i, len;

    dp = data;
    if (*dp++ != RSA_BLOCK_FIRST_OCTET) {
	return NULL;
    }

    blockType = (RSA_BlockType)*dp++;
    if (blockType != bt)
      return NULL;

    switch (blockType) {
      case RSA_BlockPrivate0:
	/* Ignored */
	res = (unsigned char *) silc_malloc(modulusLen);
	memcpy(res, data, modulusLen);
	break;

      case RSA_BlockPrivate:
	for (i = 0; i < modulusLen; i++) {
	    if (*dp++ != RSA_BLOCK_PRIVATE_PAD_OCTET)
		break;
	}
	if ((i == modulusLen) || (*dp != RSA_BLOCK_AFTER_PAD_OCTET)) {
	    return NULL;
	}
	dp++;
	len = modulusLen - (dp - data);
	res = (unsigned char *) silc_malloc(len);
	if (res == NULL) {
	    return NULL;
	}
	memcpy(res, dp, len);
	break;

      case RSA_BlockPublic:
	for (i = 0; i < modulusLen; i++) {
	    if (*dp++ == RSA_BLOCK_AFTER_PAD_OCTET)
		break;
	}
	if (i == modulusLen) {
	    return NULL;
	}
	dp++;
	len = modulusLen - (dp - data);
	res = (unsigned char *) silc_malloc(len);
	if (res == NULL) {
	    return NULL;
	}
	memcpy(res, dp, len);
	break;

      default:
	return NULL;
    }

    if (pResultLen)
      *pResultLen = len;
    return res;
}

/*
 * SILC PKCS API for PKCS #1
 *
 * Note all the other PKCS API functions are used from the rsa.c.
 * See the definitions in rsa.c and in silcpkcs.c.
 */

SILC_PKCS_API_ENCRYPT(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  int i, ret = TRUE;
  SilcInt mp_tmp;
  SilcInt mp_dst;
  unsigned char *padded;
  unsigned int padded_len;

  /* Pad data */
  if (!RSA_FormatBlock(&padded, &padded_len, key->bits / 8,
		       RSA_BlockPublic, src, src_len))
    return FALSE;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Data to MP */
  silc_mp_bin2mp(padded, padded_len, &mp_tmp);

  /* Encrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->e, &key->n);
  
  /* MP to data */
  if (!silc_mp_mp2bin_noalloc(&mp_dst, dst, key->bits / 8, dst_len))
    ret = FALSE;

  memset(padded, 0, padded_len);
  silc_free(padded);
  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return ret;
}

SILC_PKCS_API_DECRYPT(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcInt mp_tmp;
  SilcInt mp_dst;
  unsigned char *padded, *unpadded;
  unsigned int padded_len;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Data to MP */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Decrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);

  /* MP to data */
  padded = silc_mp_mp2bin(&mp_dst, &padded_len);

  /* Unpad data */
  unpadded = RSA_DecodeOneBlock(padded, padded_len, 0, 
				RSA_BlockPublic, &padded_len);
  if (!unpadded) {
    memset(padded, 0, padded_len);
    silc_free(padded);
    silc_mp_clear(&mp_tmp);
    silc_mp_clear(&mp_dst);
    return FALSE;
  }

  /* Copy to destination */
  memcpy(dst, unpadded, padded_len);
  *dst_len = padded_len;

  memset(padded, 0, padded_len);
  memset(unpadded, 0, padded_len);
  silc_free(padded);
  silc_free(unpadded);
  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_SIGN(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  int i, ret = TRUE;
  SilcInt mp_tmp;
  SilcInt mp_dst;
  unsigned char *padded;
  unsigned int padded_len;

  /* Pad data */
  if (!RSA_FormatBlock(&padded, &padded_len, key->bits / 8,
		       RSA_BlockPrivate, src, src_len))
    return FALSE;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Data to MP */
  silc_mp_bin2mp(padded, padded_len, &mp_tmp);

  /* Sign */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);
  
  /* MP to data */
  if (!silc_mp_mp2bin_noalloc(&mp_dst, dst, key->bits / 8, dst_len))
    ret = FALSE;

  memset(padded, 0, padded_len);
  silc_free(padded);
  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return ret;
}

SILC_PKCS_API_VERIFY(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  int i, ret = TRUE;
  SilcInt mp_tmp, mp_tmp2;
  SilcInt mp_dst;
  unsigned char *verify, unpadded;
  unsigned int verify_len;

  silc_mp_init_set_ui(&mp_tmp2, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Format the signature into MP int */
  silc_mp_bin2mp(signature, signature_len, &mp_tmp2);

  /* Verify */
  rsa_en_de_crypt(&mp_dst, &mp_tmp2, &key->e, &key->n);

  /* MP to data */
  verify = silc_mp_mp2bin(&mp_dst, &verify_len);

  /* Unpad data */
  unpadded = RSA_DecodeOneBlock(verify, verify_len, 0, 
				RSA_BlockPrivate, &verify_len);
  if (!unpadded) {
    memset(verify, 0, verify_len);
    silc_free(verify);
    silc_mp_clear(&mp_tmp2);
    silc_mp_clear(&mp_dst);
    return FALSE;
  }

  /* Compare */
  if (memcmp(data, unpadded, verify_len))
    ret = FALSE;

  memset(verify, 0, verify_len);
  memset(unpadded, 0, verify_len);
  silc_free(verify);
  silc_free(unpadded);
  silc_mp_clear(&mp_tmp2);
  silc_mp_clear(&mp_dst);

  return ret;
}
