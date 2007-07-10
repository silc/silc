/*

  silcasn1_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCASN1_I_H
#define SILCASN1_I_H

#ifndef SILCASN1_H
#error "Do not include this header directly"
#endif

/* ASN.1 context */
struct SilcAsn1Object {
  SilcStack orig_stack;		/* Stack given to silc_asn1_alloc */
  SilcStack stack1;		/* Stack for encoder */
  SilcStack stack2;		/* Internal stack for encoding/decoding */
  va_list ap;			/* List of ASN.1 types given as argument */
  unsigned int accumul  : 1;	/* Accumulate memory from stack for result */
  unsigned int switched  : 1;	/* Set when stack2 is set to stack1 */
};

/* The maximum depth for recursion in encoder and decoder. */
#define SILC_ASN1_RECURSION_DEPTH 512

/* Implementation specific special tags.  Range is 0x7000 - 0x7fff. */
#define SILC_ASN1_TAG_ANY           0x7000  /* SILC_ASN1_ANY given  */
#define SILC_ASN1_TAG_FUNC          0x7001  /* Callback encoder/decoder */
#define SILC_ASN1_TAG_OPTS          0x7002  /* SILC_ASN1_OPTS given */
#define SILC_ASN1_TAG_CHOICE        0x7003  /* SILC_ASN1_CHOICE given */
#define SILC_ASN1_TAG_SEQUENCE_OF   0x7004  /* SILC_ASN1_SEQUENCE_OF given */
#define SILC_ASN1_TAG_ANY_PRIMITIVE 0x7005  /* Pre-encoded primitive data */
#define SILC_ASN1_TAG_SHORT_INTEGER 0x7006  /* Short integer */

/* Helper macros for adding the arguments to encoder and decoder. */

/* The arguments to silc_asn1_encode and silc_asn1_decode are constructed
   as follows:

   The first argument for type is a 32 bit integer where first 15-bits are
   reserved for the type.  If the bit 16 is set then type and tag are same
   and next argument is NOT the tag number.  If bit 16 is not set then
   next argument is a 32 bit tag number.  This then also means that the type
   is either implicitly or explicitly tagged.  The second 16-bits of the
   first 32-bits argument is reserved for options.

   Any argument that follow the type and optional tag number argument are
   type specific arguments.

   The SILC_ASN1_Ux macros set the bit 16, since the type and tag are same,
   and also options are set to zero (0).

   The SILC_ASN1_Tx macros does not set bit 16, but separate tag argument is
   provided.  Options may or may not be zero, and they are put at the high
   16-bits part of the first 32-bit argument.
*/

#define SILC_ASN1_U0(type) \
  SILC_ASN1_TAG_ ## type | 0x8000
#define SILC_ASN1_U1(type, x) \
  SILC_ASN1_TAG_ ## type | 0x8000, (x)
#define SILC_ASN1_U2(type, x, xl) \
  SILC_ASN1_TAG_ ## type | 0x8000, (x), (xl)

#define SILC_ASN1_T0(type, o, t) \
  SILC_ASN1_TAG_ ## type | (o) << 16, (t)
#define SILC_ASN1_T1(type, o, t, x) \
  SILC_ASN1_TAG_ ## type | (o) << 16, (t), (x)
#define SILC_ASN1_T2(type, o, t, x, xl) \
  SILC_ASN1_TAG_ ## type | (o) << 16, (t), (x), (xl)

/* Macro to retreive type, options and tag.  The ret_type will include
   the actual type, ret_class the BER class from options, ret_opts the
   options (without the class), and ret_tag the tag. */
#define SILC_ASN1_ARGS(asn1, ret_type, ret_tag, ret_class, ret_opts)	\
  ret_type = va_arg(asn1->ap, SilcUInt32);				\
  ret_tag = ret_class = ret_opts = 0;					\
  if (ret_type != SILC_ASN1_END &&					\
      ret_type != SILC_ASN1_TAG_OPTS) {					\
    if (ret_type & 0x8000)						\
      ret_tag = (ret_type & 0xffff) & ~0x8000;				\
    else								\
      ret_tag = va_arg(asn1->ap, SilcUInt32);				\
    ret_class = ret_type >> 16 & 0xf;					\
    ret_opts = ret_type >> 16 & ~0xf;					\
    if (ret_class)							\
      ret_class--;							\
    ret_type = (ret_type & 0xffff) & ~0x8000;				\
  }

/* Internal functions */

#if defined(SILC_DEBUG)
/* Returns string representation of a tag */
const char *silc_asn1_tag_name(SilcAsn1Tag tag);
#endif /* SILC_DEBUG */

#ifdef SILC_DIST_INPLACE
/* Dumps the ASN.1 data block into standard output (stdout). */
SilcBool silc_asn1_dump(SilcAsn1 asn1, SilcBuffer src);
#endif /* SILC_DIST_INPLACE */

#endif /* SILCASN1_I_H */
