/*

  silcasn1_decode.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcasn1.h"
#include "silcber.h"

/************************** ASN.1 Decoder routines **************************/

/* Internal SEQUENCE OF and SET OF decoder.  This is used only when decoding
   these two special tags.  Other normal ASN.1 decoding is done in the
   silc_asn1_decoder function.  This parses the sequence of types and returns
   them as raw BER buffers in an array of SilcBuffers. */

static SilcBool silc_asn1_decoder_sof(SilcAsn1 asn1, SilcBuffer src)
{
  SilcBool ret = FALSE;
  SilcList types;
  SilcAsn1Tag type;
  SilcBuffer *retb;
  SilcUInt32 *retc;
  SilcAsn1Tag rtag;
  const unsigned char *rdata;
  SilcUInt32 rdata_len, len = 0;
  SilcBool found = FALSE, rindef;

  struct SilcAsn1SofStruct {
    SilcAsn1Tag type;
    struct SilcAsn1SofStruct *next;
  } *t = NULL;

  SILC_LOG_DEBUG(("Decoding sequence of types"));

  silc_list_init(types, struct SilcAsn1SofStruct, next);

  /* Take the return arguments */
  retb = va_arg(asn1->ap, SilcBuffer *);
  retc = va_arg(asn1->ap, SilcUInt32 *);
  *retb = NULL;
  *retc = 0;

  /* Get the sequence type(s).  If the type is CHOICE tag then the sequence
     may include multiple different types.  All types are considered
     separately.  If CHOICE is not given then only single type is expected. */
  type = va_arg(asn1->ap, SilcUInt32);
  assert(type != SILC_ASN1_END);

  if (type == SILC_ASN1_TAG_CHOICE) {
    /* The sequence may consist of the following types. */
    type = va_arg(asn1->ap, SilcUInt32);
    assert(type != SILC_ASN1_END);
    while (type != SILC_ASN1_END) {
      t = silc_smalloc(asn1->stack1, sizeof(*t));
      if (!t)
	goto out;
      t->type = type;
      silc_list_add(types, t);

      SILC_LOG_DEBUG(("Looking for %s [%d] from sequence of types",
		      silc_asn1_tag_name(type), type));

      type = va_arg(asn1->ap, SilcUInt32);
    }
  } else {
    /* The sequence consists of this type. */
    t = silc_smalloc(asn1->stack1, sizeof(*t));
    if (!t)
      goto out;
    t->type = type;
    silc_list_add(types, t);

    SILC_LOG_DEBUG(("Looking for %s [%d] from sequence of types",
		    silc_asn1_tag_name(type), type));
  }

  /* END marker for the sequence */
  type = va_arg(asn1->ap, SilcUInt32);
  assert(type == SILC_ASN1_END);

  /* Decode the SEQUENCE or SET */
  ret = silc_ber_decode(src, NULL, NULL, (SilcUInt32 *)&rtag, &rdata,
			&rdata_len, &rindef, &len);
  if (!ret) {
    SILC_LOG_DEBUG(("Error parsing BER block, malformed ASN.1 data"));
    goto out;
  }
  if (rtag != SILC_ASN1_TAG_SEQUENCE && rtag != SILC_ASN1_TAG_SET) {
    SILC_LOG_DEBUG(("Invalid sequence of/set of"));
    goto out;
  }
  silc_buffer_pull(src, len);

  while (silc_buffer_len(src)) {
    /* Decode the BER data. */
    ret = silc_ber_decode(src, NULL, NULL, (SilcUInt32 *)&rtag, &rdata,
			  &rdata_len, &rindef, &len);
    if (!ret) {
      SILC_LOG_DEBUG(("Error parsing BER block, malformed ASN.1 data"));
      goto out;
    }

    /* Now check the type(s) that it is supposed to be */
    found = FALSE;
    silc_list_start(types);
    while ((t = silc_list_get(types)) != SILC_LIST_END) {
      if (t->type != rtag)
	continue;

      *retb = silc_srealloc(asn1->stack1, sizeof(**retb) * (*retc), *retb,
			    sizeof(**retb) * (*retc + 1));
      if (*retb == NULL)
	goto out;

      SILC_LOG_DEBUG(("Decode %s [%d] from sequence of types",
		      silc_asn1_tag_name(rtag), rtag));

      /* Data is duplicated only if SILC_ASN1_ALLOC flag is set */
      if (!asn1->stack1)
	rdata = silc_memdup(rdata - len, rdata_len + len);
      else
	rdata = rdata - len;
      rdata_len += len;

      /* Save the data */
      silc_buffer_set(&(*retb)[*retc], (unsigned char *)rdata, rdata_len);
      (*retc)++;
      found = TRUE;
      break;
    }

    /* If type was not found we consider it the end of the sequence */
    if (found == FALSE)
      break;

    if (rdata_len)
      silc_buffer_pull(src, rdata_len);
  }

  SILC_LOG_DEBUG(("Decoded %d types", *retc));
  ret = TRUE;

 out:
  if (!asn1->stack1) {
    silc_list_start(types);
    while ((t = silc_list_get(types)) != SILC_LIST_END)
      silc_free(t);
  }

  return ret;
}

/* Macro for decoder to get argument for a type.  If OPTIONAL option is
   set then the argument is a pointer to the type pointer.  The `type'
   must be a non-pointer type, eg. int, SilcBufferStruct. */
#define SILC_ASN1_VAD(asn1, opts, type, name)			\
  type **name;							\
  if ((opts) & SILC_ASN1_OPTIONAL && !choice) {			\
    name = va_arg(asn1->ap, type **);				\
    if (!found) {						\
      if (name)							\
        *name = NULL;						\
      break;							\
    }								\
    if (name == NULL)						\
      break;							\
    *name = silc_scalloc(asn1->stack1, 1, sizeof(**name));     	\
    if (*name == NULL)						\
      break;							\
  } else {							\
    type *name ## tmp = va_arg(asn1->ap, type *);		\
    if (choice && found && !len)				\
      break;							\
    if (name ## tmp == NULL)					\
      break;							\
    name = &name ## tmp;					\
  }

/* Same as SILC_ASN1_VAD but for unsigned char and SilcUInt32 */
#define SILC_ASN1_VAD_UCHAR(asn1, opts, type, name, namelen)	\
  type **name = va_arg(asn1->ap, type **);			\
  SilcUInt32 *namelen = va_arg(asn1->ap, SilcUInt32 *);		\
  if (choice && found && !len)					\
    break;							\
  if (!found) {							\
    if (name)							\
      *name = NULL;						\
    break;							\
  }								\
  if (name == NULL)						\
    break;

/* Same as SILC_ASN1_VAD but for char only */
#define SILC_ASN1_VAD_CHAR(asn1, opts, type, name)	\
  type **name = va_arg(asn1->ap, type **);		\
  if (choice && found && !len)				\
    break;						\
  if (!found) {						\
    if (name)						\
      *name = NULL;					\
    break;						\
  }							\
  if (name == NULL)					\
    break;

#define SILC_ASN1_VA_FREE(opts, name)		\
  if ((opts) & SILC_ASN1_OPTIONAL)		\
    silc_free(*name);

/* Decodes string to UTF-8 string which is our internal representation
   of any string. */
#define SILC_ASN1_DECODE_STRING(enc, s, s_len)			\
  *s_len = silc_utf8_encoded_len(rdata, rdata_len, (enc));	\
  if (*s_len == 0) {						\
    SILC_LOG_DEBUG(("Malformed %d string value", (enc)));	\
    ret = FALSE;						\
    goto fail;							\
  }								\
  *s = silc_smalloc_ua(stack1, *s_len + 1);			\
  if (*s) {							\
    silc_utf8_encode(rdata, rdata_len, (enc), *s, *s_len);	\
    (*s)[*s_len] = '\0';					\
  }


/* Internal ASN.1 decoder.  The `type', `tag' and `opts' are the first
   arguments (either very first or first for recursion) for a type.
   The `depth' includes the current depth of recursion. */

static SilcBool
silc_asn1_decoder(SilcAsn1 asn1, SilcStack stack1, SilcAsn1Tag type,
		  SilcAsn1Tag tag, SilcBerClass ber_class,
		  SilcAsn1Options opts, SilcBuffer src, SilcUInt32 depth,
		  SilcBool primitive)
{
  unsigned char *ptr = src->data;
  SilcAsn1Tag rtype, rtag;
  SilcAsn1Options ropts;
  SilcBerClass rclass;
  SilcBerEncoding renc;
  SilcUInt32 len = 0;
  SilcBool ret, indef, rindef, found = FALSE, choice = FALSE;
  const unsigned char *rdata;
  SilcUInt32 rdata_len;
  int i;

#ifdef SILC_DEBUG
  char sp[SILC_ASN1_RECURSION_DEPTH + 1];
  memset(sp, 0, sizeof(sp));
  if (depth)
    memset(sp, 32, depth);
#endif /* SILC_DEBUG */

  if (depth >= SILC_ASN1_RECURSION_DEPTH) {
    SILC_LOG_DEBUG(("Maximum recursion depth reached"));
    return FALSE;
  }

  while (1) {

    /* If requested type is SEQUENCE OF or SET OF then we decode the sequence
       of types separately in an own decoder which returns array of buffers. */
    if (type == SILC_ASN1_TAG_SEQUENCE_OF) {
      /* Decode the sequence */
      if (!silc_asn1_decoder_sof(asn1, src)) {
	SILC_LOG_DEBUG(("Error decoding SEQUENCE OF"));
	ret = FALSE;
	goto fail;
      }

      /* Continue with rest of the decodings if any */
      SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
      if (type == SILC_ASN1_END) {
	ret = TRUE;
	goto ok;
      }
    }

    /* Get length encoding */
    indef = (opts & SILC_ASN1_INDEFINITE ? TRUE : FALSE);

    /* By default UNIVERSAL is implied unless the following conditions
       are met when CONTEXT will apply.  For SILC_ASN1_TAG_ANY_PRIMITIVE
       the class is changed only if flags dictate it. */
    if (ber_class == SILC_BER_CLASS_UNIVERSAL) {
      if (type == SILC_ASN1_TAG_ANY_PRIMITIVE) {
	if (opts & SILC_ASN1_IMPLICIT ||
	    opts & SILC_ASN1_EXPLICIT)
	  ber_class = SILC_BER_CLASS_CONTEXT;
      } else {
	if (tag != type ||
	    opts & SILC_ASN1_IMPLICIT ||
	    opts & SILC_ASN1_EXPLICIT)
	  ber_class = SILC_BER_CLASS_CONTEXT;
      }
    }

    /* Short integer is actually big integer in the BER data, so handle
       it correctly */
    if (type == SILC_ASN1_TAG_SHORT_INTEGER && type == tag)
      tag = SILC_ASN1_TAG_INTEGER;

    /* Now decode a BER encoded block from the source buffer.  It must be
       exactly the same user is expecting. */
    ret = silc_ber_decode(src, &rclass, &renc, (SilcUInt32 *)&rtag, &rdata,
			  &rdata_len, &rindef, &len);
    if (!ret) {
      SILC_LOG_DEBUG(("Error parsing BER block, malformed ASN.1 data"));
      return FALSE;
    }

    /* Now verify that the decoded BER is the one user wanted to get.  If
       requested type is OPTIONAL, then ignore all the sanity tests.  The
       while() loop is for re-considering OPTIONAL types without parsing
       new BER object.  For CHOICE (tag) all the choice considerations are
       also done within the while(). */
    while (1) {

      /* If type is CHOICE then at least one type must match before next
	 SILC_ASN1_END is reached.  The considerations act interally as
	 having OPTIONAL flag set, except that at the end one must have
	 been found. */
      if (type == SILC_ASN1_TAG_CHOICE) {
	choice = TRUE;
	SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
	opts |= SILC_ASN1_OPTIONAL;
	found = FALSE;
      }

#ifdef SILC_DEBUG
      SILC_LOG_DEBUG(
        ("%04d: %sDecode %s [%d] %s %s %s %s", depth, sp[0] ? sp : "",
	 silc_asn1_tag_name(type), rtag,
	 rclass == SILC_BER_CLASS_UNIVERSAL   ? "univ" :
	 rclass == SILC_BER_CLASS_APPLICATION ? "appl" :
	 rclass == SILC_BER_CLASS_CONTEXT     ? "cont" : "priv",
	 renc == SILC_BER_ENC_PRIMITIVE ? "primit" : "constr",
	 rindef ? "indef" : "defin",
	 choice ? "choice" : opts & SILC_ASN1_OPTIONAL ? "option" : ""));
#endif /* SILC_DEBUG */

      if (type != SILC_ASN1_TAG_ANY && tag != rtag) {
	if (!(opts & SILC_ASN1_OPTIONAL)) {
	  SILC_LOG_DEBUG(("Invalid ASN.1 tag %u, expected %u", rtag, tag));
	  return FALSE;
	}
	if (!choice)
	  found = FALSE;

      } else if (ber_class != rclass) {
	if (!(opts & SILC_ASN1_OPTIONAL)) {
	  SILC_LOG_DEBUG(("Invalid ASN.1 class %d, expected %d",
			  rclass, ber_class));
	  return FALSE;
	}
	if (!choice)
	  found = FALSE;

      } else if (!(opts & SILC_ASN1_EXPLICIT) && indef != rindef) {
	SILC_LOG_DEBUG(("Invalid ASN.1 length encoding %s, expected %s",
			rindef ? "indefinite" : "definite",
			indef ? "indefinite" : "definite"));
	return FALSE;

      } else if (rindef && renc == SILC_BER_ENC_PRIMITIVE) {
	SILC_LOG_DEBUG(("Invalid length encoding for primitive type"));
	return FALSE;

      } else {
	found = TRUE;
      }

      /* If tagging is explicit we have additional sequence we need to decode
	 before we decode the actual underlaying type. */
      if (opts & SILC_ASN1_EXPLICIT) {
	silc_buffer_pull(src, len);
	len = 0;

	primitive = (type != SILC_ASN1_TAG_SEQUENCE &&
		     type != SILC_ASN1_TAG_SET &&
		     type != SILC_ASN1_TAG_ANY);
	opts &= ~SILC_ASN1_EXPLICIT;

	ret = silc_asn1_decoder(asn1, stack1, type, type,
				SILC_BER_CLASS_UNIVERSAL, opts, src,
				depth + 1, primitive);
	if (!ret)
	  goto fail;
	if (primitive) {
	  primitive = FALSE;
	  goto cont;
	}
	goto ok;
      }

      /* Decode by the type user expects the data to be. */
      switch (type) {

      case SILC_ASN1_TAG_ANY:
	{
	  /* ANY is another ASN.1 node.  We return the raw BER buffer as
	     the node */
	  SILC_ASN1_VAD(asn1, opts, SilcBufferStruct, node);

	  *node = silc_buffer_srealloc_size(stack1, *node, len + rdata_len);
	  silc_buffer_put(*node, rdata - len, rdata_len + len);
	  break;
	}

      case SILC_ASN1_TAG_ANY_PRIMITIVE:
	{
	  /* ANY_PRIMITIVE returns the raw data blob of any primitive type. */
	  SILC_ASN1_VAD(asn1, opts, SilcBufferStruct, prim);

	  *prim = silc_buffer_srealloc_size(stack1, *prim, rdata_len);
	  silc_buffer_put(*prim, rdata, rdata_len);
	  break;
	}

      case SILC_ASN1_TAG_SEQUENCE:
      case SILC_ASN1_TAG_SET:
	{
	  /* SEQUENCE/SET is a sequence of types. */
	  silc_buffer_pull(src, len);
	  len = 0;

	  /* Get type, tag and options for the first argument in recursion */
	  SILC_ASN1_ARGS(asn1, rtype, rtag, rclass, ropts);

	  /* Decode the sequence recursively */
	  ret = silc_asn1_decoder(asn1, stack1, rtype, rtag, rclass,
				  ropts, src, depth + 1, FALSE);
	  if (!ret)
	    goto fail;
	  break;
	}

      case SILC_ASN1_TAG_INTEGER:
      case SILC_ASN1_TAG_ENUM:
	{
	  /* Integer/enum value. */
	  SilcMPInt z;
	  SILC_ASN1_VAD(asn1, opts, SilcMPInt, intval);

	  if (rdata_len < 1) {
	    SILC_LOG_DEBUG(("Malformed integer value"));
	    SILC_ASN1_VA_FREE(opts, intval);
	    ret = FALSE;
	    goto fail;
	  }

	  silc_mp_sinit(asn1->stack1, *intval);

	  /* Check whether the integer is positive or negative */
	  if (rdata[0] & 0x80) {
	    /* Negative integer stored in 1s complement.*/
	    for (i = 0; i < rdata_len; i++) {
	      silc_mp_mul_2exp(*intval, *intval, 8);
	      silc_mp_add_ui(*intval, *intval, ~rdata[i] & 0xff);
	    }

	    /* 2s complement and change sign */
	    silc_mp_init(&z);
	    silc_mp_set_ui(&z, 0);
	    silc_mp_add_ui(*intval, *intval, 1);
	    silc_mp_sub(*intval, &z, *intval);
	    silc_mp_uninit(&z);
	  } else {
	    /* Positive */
	    silc_mp_bin2mp((unsigned char *)rdata, rdata_len, *intval);
	  }

	  break;
	}

      case SILC_ASN1_TAG_SHORT_INTEGER:
	{
	  /* Short Integer */
	  SilcMPInt z;
	  SILC_ASN1_VAD(asn1, opts, SilcUInt32, intval);

	  if (rdata_len < 1) {
	    SILC_LOG_DEBUG(("Malformed integer value"));
	    SILC_ASN1_VA_FREE(opts, intval);
	    ret = FALSE;
	    goto fail;
	  }

	  silc_stack_push(asn1->stack1, NULL);
	  silc_mp_sinit(asn1->stack1, &z);
	  silc_mp_bin2mp((unsigned char *)rdata, rdata_len, &z);
	  *(*intval) = silc_mp_get_ui(&z);
	  silc_mp_uninit(&z);
	  silc_stack_pop(asn1->stack1);
	  break;
	}

      case SILC_ASN1_TAG_OID:
	{
	  /* Object identifier */
	  SilcBufferStruct tmpb;
	  char tmpstr[24];
	  SilcUInt32 oid;
	  SILC_ASN1_VAD_CHAR(asn1, opts, char, oidstr);

	  if (rdata_len < 1) {
	    SILC_LOG_DEBUG(("Malformed object identifier value"));
	    SILC_ASN1_VA_FREE(opts, oidstr);
	    ret = FALSE;
	    goto fail;
	  }

	  /* Set two OID values */
	  memset(&tmpb, 0, sizeof(tmpb));
	  memset(tmpstr, 0, sizeof(tmpstr));
	  snprintf(tmpstr, sizeof(tmpstr) - 1, "%lu.%lu",
		   (unsigned long)(rdata[0] & 0xff) / 40,
		   (unsigned long)(rdata[0] & 0xff) % 40);
	  silc_buffer_sstrformat(asn1->stack1, &tmpb, tmpstr, SILC_STR_END);

	  /* Set rest of the OID values, each octet having 7 bits of the
	     OID value with bit 8 set.  An octet not having bit 8 set
	     means end of that OID value. */
	  for (i = 1; i < rdata_len; i++) {
	    oid = 0;
	    while (rdata[i] & 0x80) {
	      oid <<= 7;
	      oid |= rdata[i++] & 0x7f;
	      if (i >= rdata_len) {
		SILC_LOG_DEBUG(("Malformed object identifier value"));
		break;
	      }
	    }
	    oid <<= 7;
	    oid |= rdata[i];

	    memset(tmpstr, 0, sizeof(tmpstr));
	    snprintf(tmpstr, sizeof(tmpstr) - 1, ".%lu", (unsigned long)oid);
	    silc_buffer_sstrformat(asn1->stack1, &tmpb, tmpstr, SILC_STR_END);
	  }
	  *oidstr = tmpb.head;

	  break;
	}

      case SILC_ASN1_TAG_BOOLEAN:
	{
	  /* Decode boolean (TRUE/FALSE) value */
	  SILC_ASN1_VAD(asn1, opts, SilcBool, val);

	  if (rdata_len != 1) {
	    SILC_LOG_DEBUG(("Malformed boolean value"));
	    SILC_ASN1_VA_FREE(opts, val);
	    ret = FALSE;
	    goto fail;
	  }

	  *(*val) = (rdata[0] == 0xff ? TRUE : FALSE);
	  break;
	}

      case SILC_ASN1_TAG_BIT_STRING:
	{
	  /* Bit string contains data with exact bit length of the data */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, d, d_len);

	  if (rdata_len < 2) {
	    SILC_LOG_DEBUG(("Malformed bit string value"));
	    SILC_ASN1_VA_FREE(opts, d);
	    ret = FALSE;
	    goto fail;
	  }

	  *d = silc_smemdup(stack1, rdata + 1, rdata_len - 1);
	  *d_len = (rdata_len - 1) * 8;
	  break;
	}

      case SILC_ASN1_TAG_NULL:
	{
	  /* Decode empty BER block */
	  if (rdata_len != 0) {
	    SILC_LOG_DEBUG(("Malformed null value"));
	    goto fail;
	  }
	  break;
	}

      case SILC_ASN1_TAG_UTC_TIME:
	{
	  /* Universal encoded time string */
	  SILC_ASN1_VAD(asn1, opts, SilcTimeStruct, t);

	  if (rdata_len < 1) {
	    SILC_LOG_DEBUG(("Malformed UTC time value"));
	    SILC_ASN1_VA_FREE(opts, t);
	    ret = FALSE;
	    goto fail;
	  }

	  /* Parse the time string */
	  if (!silc_time_universal(rdata, *t)) {
	    SILC_LOG_DEBUG(("Malformed UTC time value"));
	    ret = FALSE;
	    goto fail;
	  }

	  break;
	}

      case SILC_ASN1_TAG_GENERALIZED_TIME:
	{
	  /* Generalized encoded time string */
	  SILC_ASN1_VAD(asn1, opts, SilcTimeStruct, t);

	  if (rdata_len < 1) {
	    SILC_LOG_DEBUG(("Malformed generalized time value"));
	    SILC_ASN1_VA_FREE(opts, t);
	    ret = FALSE;
	    goto fail;
	  }

	  /* Parse the time string */
	  if (!silc_time_generalized(rdata, *t)) {
	    SILC_LOG_DEBUG(("Malformed generalized time value"));
	    SILC_ASN1_VA_FREE(opts, t);
	    ret = FALSE;
	    goto fail;
	  }

	  break;
	}

      case SILC_ASN1_TAG_UTF8_STRING:
	{
	  /* UTF-8 encoded string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);

	  if (!silc_utf8_valid(rdata, rdata_len)) {
	    SILC_LOG_DEBUG(("Malformed UTF-8 string value"));
	    SILC_ASN1_VA_FREE(opts, s);
	    ret = FALSE;
	    goto fail;
	  }

	  *s = silc_smemdup(stack1, rdata, rdata_len);
	  *s_len = rdata_len;
	  break;
	}

      case SILC_ASN1_TAG_OCTET_STRING:
	{
	  /* Octet string.  We take it as 8-bit ASCII */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_ASCII, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_NUMERIC_STRING:
	{
	  /* Numerical (digit) string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_NUMERICAL, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_PRINTABLE_STRING:
	{
	  /* Printable string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_PRINTABLE, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_TELETEX_STRING:
	{
	  /* Teletex (T61) string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_TELETEX, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_IA5_STRING:
	{
	  /* US ASCII string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_ASCII, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_VISIBLE_STRING:
	{
	  /* Visible string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_VISIBLE, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_UNIVERSAL_STRING:
	{
	  /* Universal (UCS-4) string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_UNIVERSAL, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_UNRESTRICTED_STRING:
      case SILC_ASN1_TAG_GENERAL_STRING:
	{
	  /* Handle now unrestricted and general as 8-bit ascii, which
	     probably isn't correct. */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_ASCII, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_BMP_STRING:
	{
	  /* BMP (UCS-2) string */
	  SILC_ASN1_VAD_UCHAR(asn1, opts, unsigned char, s, s_len);
	  SILC_ASN1_DECODE_STRING(SILC_STRING_BMP, s, s_len);
	  break;
	}

      case SILC_ASN1_TAG_ODE:
      case SILC_ASN1_TAG_ETI:
      case SILC_ASN1_TAG_REAL:
      case SILC_ASN1_TAG_EMBEDDED:
      case SILC_ASN1_TAG_ROI:
      case SILC_ASN1_TAG_VIDEOTEX_STRING:
      case SILC_ASN1_TAG_GRAPHIC_STRING:
	{
	  SILC_NOT_IMPLEMENTED("Unsupported ASN.1 tag");
	  ret = FALSE;
	  goto fail;
	  break;
	}

      default:
	SILC_LOG_DEBUG(("Invalid ASN.1 tag `%d'. Cannot decode ASN.1.",
			type));
	ret = FALSE;
	goto fail;
	break;
      }

    cont:
      /* Pull the current data from source which reveals next BER object */
      if (found && len + rdata_len)
	silc_buffer_pull(src, len + rdata_len);
      if (primitive) {
	ret = TRUE;
	goto ok;
      }

      /* Get next type, tag and options */
      rtype = type;
      SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
      if (type == SILC_ASN1_END) {
	if (choice) {
	  if (!found) {
	    /* No choices were found, error */
	    SILC_LOG_DEBUG(("Invalid ASN.1 choice: no choices present"));
	    ret = FALSE;
	    goto fail;
	  }

	  /* Take next type and new BER object, choices are over */
	  choice = FALSE;
	  SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
	  if (type == SILC_ASN1_END) {
	    ret = TRUE;
	    goto ok;
	  }
	  break;
	}

	/* SEQUENCE/SET end */
	ret = TRUE;
	goto ok;
      }

      if (choice) {
	/* Even if the choice was found we must go through rest of
	   the choices. */
	if (found && len) {
	  SILC_LOG_DEBUG(("Found choice %s type", silc_asn1_tag_name(rtype)));
	  rdata_len = len = 0;
	}
	opts |= SILC_ASN1_OPTIONAL;
	continue;
      }

      /* Optional type not present, check next one for match */
      if (!found)
	continue;

      break;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error decoding type %d (depth %d)", type, depth));

 ok:
  if (ptr)
    len = src->data - ptr;
  else
    len = src->data - src->head;
  silc_buffer_push(src, len);

  return ret;
}

SilcBool silc_asn1_decode(SilcAsn1 asn1, SilcBuffer src, ...)
{
  SilcAsn1Tag type, tag;
  SilcAsn1Options opts;
  SilcBerClass ber_class;
  SilcStackFrame frame1, frame2;
  SilcStack stack1 = NULL, stack2 = NULL;
  SilcBool ret;

  if (!asn1)
    return FALSE;

  va_start(asn1->ap, src);

  /* Get the first arguments and call the decoder. */
  SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
  if (!type) {
    va_end(asn1->ap);
    return FALSE;
  }

  /* Handle internal options for decoder. */
  if (type == SILC_ASN1_TAG_OPTS) {
    SilcUInt32 o = va_arg(asn1->ap, SilcUInt32);

    if (o & SILC_ASN1_ALLOC) {
      /* User wants to alloate everything.  Set the stacks to NULL so
	 that stack aware calls revert to normal allocation routines. */
      stack1 = asn1->stack1;
      stack2 = asn1->stack2;
      asn1->stack1 = NULL;
      asn1->stack2 = NULL;
    }

    if (o & SILC_ASN1_ACCUMUL) {
      /* If accumul flag is not set yet, then push the stacks. */
      if (!asn1->accumul) {
	silc_stack_push(asn1->stack1, NULL);
	silc_stack_push(asn1->stack2, NULL);
	asn1->accumul = 1;
      }
    }

    /* Take again the arguments */
    SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
  } else {
    /* No flags set, all flags will be reset. */

    /* If accumul flag is set now pop the stack so that all accumulated
       memory becomes free again. */
    if (asn1->accumul) {
      silc_stack_pop(asn1->stack1);
      silc_stack_pop(asn1->stack2);
      asn1->accumul = 0;
    }
  }

  /* Push stacks for normal allocation from stack */
  if (!asn1->accumul) {
    silc_stack_push(asn1->stack1, &frame1);
    silc_stack_push(asn1->stack2, &frame2);
  }

  /* Start decoding */
  ret = silc_asn1_decoder(asn1, asn1->stack1, type, tag, ber_class,
			  opts, src, 0, FALSE);

  /* Pop stacks to free normal allocations from stack. They remain valid
     for every second call to this function. */
  if (!asn1->accumul) {
    silc_stack_pop(asn1->stack1);
    silc_stack_pop(asn1->stack2);

    /* Switch the asn1->stack1 and asn1->stack2.  This way next call to
       this function does not invalidate these results.  Every second call
       invalidates the results of every second previous results. */
    if (asn1->stack1 && asn1->stack2) {
      stack1 = asn1->stack1;
      asn1->stack1 = asn1->stack2;
      asn1->stack2 = stack1;
    }
  }

  if (stack1 && stack2 && !asn1->stack1 && !asn1->stack2) {
    /* SILC_ASN1_ALLOC flag was set, restore the stacks. */
    asn1->stack1 = stack1;
    asn1->stack2 = stack2;
  }

  va_end(asn1->ap);

  return ret;
}
