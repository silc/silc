/*

  silcasn1_encode.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2005 Pekka Riikonen

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

/************************** ASN.1 Encoder routines **************************/

/* Encode string from UTF-8 string to other string encodings.  Encodes
   diretly to BER blob. */
#define SILC_ASN1_ENCODE_STRING(enc)					\
  unsigned char *s, *d = va_arg(asn1->ap, unsigned char *);		\
  SilcUInt32 s_len, d_len = va_arg(asn1->ap, SilcUInt32);		\
  if (!d)								\
    break;								\
  s_len = silc_utf8_decoded_len(d, d_len, (enc));			\
  if (s_len == 0) {							\
    SILC_LOG_DEBUG(("Malformed %d string value", (enc)));		\
    goto fail;								\
  }									\
  silc_stack_push(asn1->stack2, &frame);				\
  s = silc_smalloc_ua(stack2, s_len + 1);				\
  if (s) {								\
    silc_utf8_decode(d, d_len, (enc), s, s_len);			\
    s[s_len] = '\0';							\
  }									\
  len = silc_ber_encoded_len(tag, s_len, indef);			\
  dest = silc_buffer_srealloc_size(stack1, dest,			\
				   silc_buffer_truelen(dest) + len);	\
  ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,	\
			tag, s, s_len, indef);				\
  silc_stack_pop(asn1->stack2);						\
  if (!ret)								\
    goto fail;

/* The internal ASN.1 encoder.  The `type', `tag' and `opts' are the
   first arguments (either very first or first for recursion) for a type.
   The `depth' includes the current depth of recursion.  The `primitive'
   is TRUE if this encoder receives one primitive type as argument.  If
   it is a constructed type it must be FALSE value. */

static SilcBool
silc_asn1_encoder(SilcAsn1 asn1, SilcStack stack1, SilcStack stack2,
		  SilcAsn1Tag type, SilcAsn1Tag tag, SilcBerClass ber_class,
		  SilcAsn1Options opts, SilcBuffer dest, SilcUInt32 depth,
		  SilcBool primitive)
{
  unsigned char *ptr = dest->data;
  SilcAsn1Tag rtype, rtag;
  SilcAsn1Options ropts;
  SilcBerClass rclass;
  SilcUInt32 len = 0;
  SilcBool ret = FALSE, indef;
  SilcBufferStruct buf;
  SilcStackFrame frame;

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
    /* These options cannot be used in encoding */
    opts &= ~SILC_ASN1_OPTIONAL;

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

#ifdef SILC_DEBUG
    SILC_LOG_DEBUG(
      ("%04d: %sEncode %s [%d] %s %s %s %s", depth, sp[0] ? sp : "",
       silc_asn1_tag_name(type), tag,
       ber_class == SILC_BER_CLASS_UNIVERSAL   ? "univ" :
       ber_class == SILC_BER_CLASS_APPLICATION ? "appl" :
       ber_class == SILC_BER_CLASS_CONTEXT     ? "cont" : "priv",
       (type != SILC_ASN1_TAG_SEQUENCE && type != SILC_ASN1_TAG_SET) ?
       opts & SILC_ASN1_EXPLICIT ? "constr" :
       type == SILC_ASN1_TAG_ANY &&
       !(opts & SILC_ASN1_EXPLICIT) ? "constr" : "primit" : "constr",
       indef ? opts & SILC_ASN1_EXPLICIT ? "defin" : "indef" : "defin",
       opts & SILC_ASN1_IMPLICIT ? "implicit" :
       opts & SILC_ASN1_EXPLICIT ? "explicit" : ""));
#endif /* SILC_DEBUG */

    /* If tagging is explicit we add constructed type before the underlaying
       types.  The underlaying types are encoded recursively with this
       encoder. */
    if (opts & SILC_ASN1_EXPLICIT) {
      memset(&buf, 0, sizeof(buf));

      primitive = (type != SILC_ASN1_TAG_SEQUENCE &&
		   type != SILC_ASN1_TAG_SET);
      opts &= ~SILC_ASN1_EXPLICIT;

      silc_stack_push(stack2, &frame);
      ret = silc_asn1_encoder(asn1, stack2, stack1, type, type,
			      SILC_BER_CLASS_UNIVERSAL, opts,
			      &buf, depth + 1, primitive);
      silc_stack_pop(stack2);

      if (!ret) {
	SILC_LOG_DEBUG(("Error encoding explicit tag"));
	goto fail;
      }

      /* Encode the explicit tag */
      len = silc_ber_encoded_len(tag, silc_buffer_len(&buf), FALSE);
      dest = silc_buffer_srealloc_size(stack1, dest,
				       silc_buffer_truelen(dest) + len);
      ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_CONSTRUCTED,
			    tag, buf.data, silc_buffer_len(&buf), FALSE);
      if (!ret)
	goto fail;
      if (primitive) {
	primitive = FALSE;
	goto cont;
      }
      goto ok;
    }

    /* Encode by the type */
    switch (type) {

    case SILC_ASN1_TAG_ANY:
      {
	/* ANY is another ASN.1 node which is added to this tree */
	SilcBuffer node = va_arg(asn1->ap, SilcBuffer);
	if (!node)
	  break;

	/* Encode ASN.1 node into the tree. */
	if (opts & SILC_ASN1_IMPLICIT || type != tag) {
	  /* We are tagging implicitly so we need to change the identifier
	     of the underlaying type.  Only constructed type is allowed with
	     ANY when tagging implicitly. */
	  const unsigned char *d;
	  SilcUInt32 d_len;
	  SilcBerEncoding enc;

	  /* Get the underlaying data */
	  ret = silc_ber_decode(node, NULL, &enc, NULL, &d, &d_len,
				NULL, NULL);
	  if (!ret) {
	    SILC_LOG_DEBUG(("Error decoding underlaying node for ANY"));
	    goto fail;
	  }
	  assert(enc == SILC_BER_ENC_CONSTRUCTED);

	  /* Now encode with implicit tagging */
	  len = silc_ber_encoded_len(tag, d_len, FALSE);
	  dest = silc_buffer_srealloc_size(stack1, dest,
					   silc_buffer_truelen(dest) + len);
	  ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_CONSTRUCTED,
				tag, d, d_len, FALSE);
	  if (!ret)
	    goto fail;
	} else {
	  /* Copy the data directly into the tree. */
	  len = silc_buffer_len(node);
	  dest = silc_buffer_srealloc_size(stack1, dest,
					   silc_buffer_truelen(dest) + len);
	  if (!dest)
	    goto fail;
	  silc_buffer_put(dest, node->data, len);
	}
	break;
      }

    case SILC_ASN1_TAG_ANY_PRIMITIVE:
      {
	/* ANY_PRIMITIVE is any primitive in encoded format. */
	SilcBuffer prim = va_arg(asn1->ap, SilcBuffer);
	if (!prim)
	  break;

	/* Encode the primitive data */
	len = silc_ber_encoded_len(tag, silc_buffer_len(prim), FALSE);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, prim->data, silc_buffer_len(prim), FALSE);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_SEQUENCE:
    case SILC_ASN1_TAG_SET:
      {
	/* SEQUENCE/SET is a sequence of types. Sequences are opened and
	   encoded recursively by calling this same encoder. */
	memset(&buf, 0, sizeof(buf));

	/* Get type, tag and options for the first argument in recursion */
	SILC_ASN1_ARGS(asn1, rtype, rtag, rclass, ropts);

	silc_stack_push(stack2, &frame);
	ret = silc_asn1_encoder(asn1, stack2, stack1, rtype, rtag, rclass,
				ropts, &buf, depth + 1, FALSE);
	silc_stack_pop(stack2);
	if (!ret) {
	  SILC_LOG_DEBUG(("Error traversing a SEQUENCE/SET"));
	  goto fail;
	}

	/* Encode the sequence */
	len = silc_ber_encoded_len(tag, silc_buffer_len(&buf), indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_CONSTRUCTED,
			      tag, buf.data, silc_buffer_len(&buf), indef);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_INTEGER:
    case SILC_ASN1_TAG_ENUM:
      {
	/* Integer */
	SilcMPInt *mpint = va_arg(asn1->ap, SilcMPInt *);
	if (!mpint)
	  break;

	memset(&buf, 0, sizeof(buf));
	if (silc_mp_cmp_ui(mpint, 0) < 0) {
	  /* XXX TODO, negative integer.  Take 2s complement, then store
	     bytes in 1s complement */
	} else {
	  /* Positive */
	  len = silc_mp_sizeinbase(mpint, 2);
	  if (!(len & 7))
	    len = ((len + 7) / 8) + 1;
	  else
	    len = (len + 7) / 8;
	  silc_stack_push(stack2, &frame);
	  silc_buffer_srealloc_size(stack2, &buf,
				    silc_buffer_truelen(&buf) + len);
	  buf.data[0] = 0x00;
	  silc_mp_mp2bin_noalloc(mpint, buf.data, silc_buffer_len(&buf));
	}

	/* Encode the integer */
	len = silc_ber_encoded_len(tag, len, indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, buf.data, silc_buffer_len(&buf), FALSE);
	silc_stack_pop(stack2);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_OID:
      {
	/* Object identifier */
	char *cp, *oidstr = va_arg(asn1->ap, char *);
	SilcUInt32 words[24], oid, mask;
	int i, c = -1;
	if (!oidstr)
	  break;

	/* Get OID words from the string */
	cp = strchr(oidstr, '.');
	while (cp) {
	  c = sscanf(oidstr, "%lu", (unsigned long *)&oid);
	  if (c < 1) {
	    SILC_LOG_DEBUG(("Malformed OID string"));
	    goto fail;
	  }
	  if (c + 1 > sizeof(words) / sizeof(words[0]))
	    goto fail;
	  words[c++] = oid;
	  oidstr = cp + 1;
	  cp = strchr(oidstr, '.');
	}
	if (c < 2) {
	  SILC_LOG_DEBUG(("Malfromed OID string"));
	  goto fail;
	}

	/* Get OID data length */
	for (i = 2, len = 1; i < c; i++) {
	  if (words[i]) {
	    for (oid = words[i]; oid; oid >>= 7)
	      len++;
	    continue;
	  }
	  len++;
	}

	/* Encode the OID */
	memset(&buf, 0, sizeof(buf));
	silc_stack_push(stack2, &frame);
	silc_buffer_srealloc_size(stack2, &buf,
				  silc_buffer_truelen(&buf) + len);
	buf.data[0] = words[0] * 40 + words[1];
	for (i = 2, len = 1; i < c; i++) {
	  oid = words[i];
	  if (oid) {
	    c = len;
	    mask = 0;
	    while (oid) {
	      buf.data[len++] = (oid & 0x7f) | mask;
	      oid >>= 7;
	      mask |= 0x80;
	    }
	    mask = len - 1;
	    while (c < mask) {
	      oid = buf.data[c];
	      buf.data[c] = buf.data[mask];
	      buf.data[mask] = oid;
	      c++;
	      mask--;
	    }

	    continue;
	  }
	  buf.data[len++] = 0x00;
	}

	len = silc_ber_encoded_len(tag, len, indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, buf.data, silc_buffer_len(&buf), FALSE);
	silc_stack_pop(stack2);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_BOOLEAN:
      {
	/* Encodes boolean (TRUE/FALSE) value */
	unsigned char val[1];
	val[0] = (va_arg(asn1->ap, SilcUInt32) ? 0xff : 0x00);

	assert(indef == FALSE);
	len = silc_ber_encoded_len(tag, 1, FALSE);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, val, 1, FALSE);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_BIT_STRING:
      {
	/* Encode the data as is, with the bit padding. d_len is in bits. */
	unsigned char *d = va_arg(asn1->ap, unsigned char *);
	SilcUInt32 d_len = va_arg(asn1->ap, SilcUInt32);
	unsigned char pad[1];
	if (!d)
	  break;

	pad[0] = (8 - (d_len & 7)) & 7;
	d_len = ((d_len + 7) / 8) + 1;

	memset(&buf, 0, sizeof(buf));
	silc_stack_push(stack2, &frame);
	silc_buffer_srealloc_size(stack2, &buf,
				  silc_buffer_truelen(&buf) + d_len);
	silc_buffer_put(&buf, pad, 1);
	silc_buffer_pull(&buf, 1);
	silc_buffer_put(&buf, d, d_len - 1);
	silc_buffer_push(&buf, 1);

	len = silc_ber_encoded_len(tag, silc_buffer_len(&buf), indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, buf.data, silc_buffer_len(&buf), indef);
	silc_stack_pop(stack2);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_NULL:
      {
	/* Encode empty BER block */
	assert(indef == FALSE);
	len = silc_ber_encoded_len(tag, 0, FALSE);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, NULL, 0, FALSE);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_UTC_TIME:
      {
	/* Universal encoded time string */
	SilcTime timeval = va_arg(asn1->ap, SilcTime);
	char timestr[32];
	if (!timeval)
	  break;

	if (!silc_time_universal_string(timeval, timestr, sizeof(timestr))) {
	  SILC_LOG_DEBUG(("Could not encode universal time string"));
	  goto fail;
	}

	len = silc_ber_encoded_len(tag, strlen(timestr), indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, timestr, strlen(timestr), indef);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_GENERALIZED_TIME:
      {
	/* Generalized encoded time string */
	SilcTime timeval = va_arg(asn1->ap, SilcTime);
	char timestr[32];
	if (!timeval)
	  break;

	if (!silc_time_generalized_string(timeval, timestr, sizeof(timestr))) {
	  SILC_LOG_DEBUG(("Could not encode generalized time string"));
	  goto fail;
	}

	len = silc_ber_encoded_len(tag, strlen(timestr), indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, timestr, strlen(timestr), indef);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_UTF8_STRING:
      {
	/* UTF-8 string */
	unsigned char *d = va_arg(asn1->ap, unsigned char *);
	SilcUInt32 d_len = va_arg(asn1->ap, SilcUInt32);
	if (!d)
	  break;

	/* By default all strings that get here should already be UTF-8 */
	if (!silc_utf8_valid(d, d_len)) {
	  SILC_LOG_DEBUG(("Malformed UTF-8 string"));
	  goto fail;
	}

	len = silc_ber_encoded_len(tag, d_len, indef);
	dest = silc_buffer_srealloc_size(stack1, dest,
					 silc_buffer_truelen(dest) + len);
	ret = silc_ber_encode(dest, ber_class, SILC_BER_ENC_PRIMITIVE,
			      tag, d, d_len, indef);
	if (!ret)
	  goto fail;
	break;
      }

    case SILC_ASN1_TAG_OCTET_STRING:
      {
	/* Octet string.  We put it in as 8-bit ASCII */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_ASCII);
	break;
      }

    case SILC_ASN1_TAG_NUMERIC_STRING:
      {
	/* Numerical (digit) string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_NUMERICAL);
	break;
      }

    case SILC_ASN1_TAG_PRINTABLE_STRING:
      {
	/* Printable string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_PRINTABLE);
	break;
      }

    case SILC_ASN1_TAG_TELETEX_STRING:
      {
	/* Teletex (T61) string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_TELETEX);
	break;
      }

    case SILC_ASN1_TAG_IA5_STRING:
      {
	/* US ASCII string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_ASCII);
	break;
      }

    case SILC_ASN1_TAG_VISIBLE_STRING:
      {
	/* Visible string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_VISIBLE);
	break;
      }

    case SILC_ASN1_TAG_UNIVERSAL_STRING:
      {
	/* Universal (UCS-4) string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_UNIVERSAL);
	break;
      }

    case SILC_ASN1_TAG_UNRESTRICTED_STRING:
    case SILC_ASN1_TAG_GENERAL_STRING:
      {
	/* Handle now unrestricted and general as 8-bit ascii, which
	   probably isn't correct. */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_ASCII);
	break;
      }

    case SILC_ASN1_TAG_BMP_STRING:
      {
	/* BMP (UCS-2) string */
	SILC_ASN1_ENCODE_STRING(SILC_STRING_UNIVERSAL);
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
      SILC_LOG_DEBUG(("Invalid ASN.1 tag `%d'. Cannot encode ASN.1.", type));
      ret = FALSE;
      goto fail;
      break;
    }

  cont:
    if (len)
      silc_buffer_pull(dest, len);
    if (primitive) {
      ret = TRUE;
      goto ok;
    }

    /* Get next type, tag and options */
    SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
    if (type == SILC_ASN1_END) {
      ret = TRUE;
      goto ok;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error encoding type %d (depth %d)", type, depth));

 ok:
  if (ptr)
    len = dest->data - ptr;
  else
    len = dest->data - dest->head;
  silc_buffer_push(dest, len);

  return ret;
}

SilcBool silc_asn1_encode(SilcAsn1 asn1, SilcBuffer dest, ...)
{
  SilcAsn1Tag type, tag;
  SilcAsn1Options opts;
  SilcBerClass ber_class;
  SilcStackFrame frame1, frame2;
  SilcStack stack1 = NULL;
  SilcBool ret;

  if (!asn1)
    return FALSE;

  va_start(asn1->ap, dest);

  /* Get the first arguments and call the encoder. */
  SILC_ASN1_ARGS(asn1, type, tag, ber_class, opts);
  if (!type) {
    va_end(asn1->ap);
    asn1->ap = NULL;
    return FALSE;
  }

  /* Handle internal options for encoder. */
  if (type == SILC_ASN1_TAG_OPTS) {
    SilcUInt32 o = va_arg(asn1->ap, SilcUInt32);

    if (o & SILC_ASN1_ALLOC) {
      /* User wants to alloate everything.  Set the stack to NULL so
	 that stack aware calls revert to normal allocation routines. */
      stack1 = asn1->stack1;
      asn1->stack1 = NULL;
    }

    if (o & SILC_ASN1_ACCUMUL) {
      /* If accumul flag is not set yet, then push the stack. */
      if (!asn1->accumul) {
	silc_stack_push(asn1->stack1, NULL);
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
      asn1->accumul = 0;
    }
  }

  /* Push the stack for normal allocation from stack. */
  if (!asn1->accumul)
    silc_stack_push(asn1->stack1, &frame1);

  /* Start encoding */
  silc_stack_push(asn1->stack2, &frame2);
  ret = silc_asn1_encoder(asn1, asn1->stack1, asn1->stack2,
			  type, tag, ber_class, opts, dest, 0, FALSE);
  silc_stack_pop(asn1->stack2);

  /* Pop the stack to free normal allocations from stack. */
  if (!asn1->accumul)
    silc_stack_pop(asn1->stack1);

  /* If SILC_ASN1_ALLOC flag was set, restore the stack. */
  if (stack1 && !asn1->stack1)
    asn1->stack1 = stack1;

  va_end(asn1->ap);
  asn1->ap = NULL;

  return ret;
}
