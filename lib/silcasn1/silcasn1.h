/*

  silcasn1.h

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

/****h* silcasn1/ASN.1 Interface
 *
 * DESCRIPTION
 *
 * Efficient Abstract Syntax Notation One (ASN.1) implementation.  This
 * interface provides simple and efficient ASN.1 encoder and decoder.
 * The encoder directly encodes BER encoded data blocks from variable
 * argument list of ASN.1 types.  Multiple trees can be encoded at once
 * and multiple nodes can be encoded into the tree at once.  By default
 * encoder does not allocate any memory during encoding but a pre-allocated
 * SilcStack is used as memory.
 *
 * The decoder directly decodes BER encoded data blocks into the correct
 * types dictated by the variable argument list of ASN.1 types.  By
 * default decoder does not allocate any memory during decoding but a
 * pre-allocated SilcStack is used as memory.
 *
 * The encoding and decoding interface is simple.  silc_asn1_encode is used
 * to encode and silc_asn1_decode to decode.  The actual ASN.1 is defined
 * as variable argument list to the function.  Various macros can be used
 * to encode and decode different ASN.1 types.  All types may also be used
 * to encode and decode with various options (such as implicit and explicit
 * tagging and defining specific class option).
 *
 * The implementation supports all the common ASN.1 types.  This
 * implementation does not support advanced ASN.1 features like macros.
 *
 * References: ITU-T X.680 - X.693
 * http://www.itu.int/ITU-T/studygroups/com17/languages/
 *
 ***/

#ifndef SILCASN1_H
#define SILCASN1_H

/****s* silcasn1/SilcASN1API/SilcAsn1
 *
 * NAME
 *
 *    typedef struct SilcAsn1Object *SilcAsn1;
 *
 * DESCRIPTION
 *
 *    This context is the actual ASN.1 encoder/decoder and is allocated
 *    by silc_asn1_alloc and given as argument to all silc_asn1_*
 *    functions.  It is freed by the silc_asn1_free function.  It is
 *    also possible to use pre-allocated ASN.1 context by using the
 *    SilcAsn1Struct instead of SilcAsn1.
 *
 ***/
typedef struct SilcAsn1Object *SilcAsn1;

/****s* silcasn1/SilcASN1API/SilcAsn1Struct
 *
 * NAME
 *
 *    typedef struct SilcAsn1Object SilcAsn1Struct;
 *
 * DESCRIPTION
 *
 *    This context is the actual ASN.1 encoder/decoder and can be
 *    used as pre-allocated ASN.1 context instead of SilcAsn1 context.
 *    This context is initialized with silc_asn1_init and uninitialized
 *    with silc_asn1_uninit.
 *
 ***/
typedef struct SilcAsn1Object SilcAsn1Struct;

/****d* silcasn1/SilcASN1API/SilcAsn1Options
 *
 * NAME
 *
 *    typedef enum { ... } SilcAsn1Options;
 *
 * DESCRIPTION
 *
 *    Options for ASN.1 encoder and decoder.  The ASN.1 options can be
 *    given to the SILC_ASN1_*_T macros and/or SILC_ASN1_OPTS macro.
 *
 * NOTES
 *
 *    The SILC_ASN1_ALLOC and SILC_ASN1_ACCUMUL flags can be given only
 *    with SILC_ASN1_OPTS macro.  Other options can be given with various
 *    SILC_ASN1_*_T macros.
 *
 * EXAMPLE
 *
 *    // Encodes boolean value with explicit tag and private class, and
 *    // the result is allocated into `dest'.
 *    silc_asn1_encode(asn1, &dest,
 *                     SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
 *                     SILC_ASN1_BOOLEAN_T(SILC_ASN1_PRIVATE |
 *                                         SILC_ASN1_EXPLICIT, 100, boolval),
 *                     SILC_ASN1_END);
 *
 *
 *    // Decode optional value, with SILC_ASN1_OPTIONAL the type must be
 *    // a pointer so that NULL can be returned if the type is not present.
 *    SilcBool *val;
 *
 *    silc_asn1_decode(asn1, src,
 *                     SILC_ASN1_OPTS(SILC_ASN1_OPTIONAL),
 *                     SILC_ASN1_BOOLEAN(&val),
 *                     SILC_ASN1_END);
 *
 *    // If val == NULL, the optional value was not present
 *    if (val == NULL)
 *      error;
 *
 * SOURCE
 */
typedef enum {
  /* Default. If only this is set then defaults are implied. */
  SILC_ASN1_DEFAULT      = 0x0000,

  /* Class options.  User does not need to set these unless specificly
     wanted to do so.  If SILC_ASN1_DEFAULT is set the SILC_ASN1_CONTEXT is
     implied if any of the tag options are set.  Otherwise SILC_ASN1_UNIVERSAL
     is implied. Only one of these can bet set at once. */
  SILC_ASN1_UNIVERSAL    = 0x0001,       /* Universal class (default) */
  SILC_ASN1_APP          = 0x0002,	 /* Application specific class */
  SILC_ASN1_CONTEXT      = 0x0003,	 /* Context specific class */
  SILC_ASN1_PRIVATE      = 0x0004,	 /* Private class */

  /* Tag options (bitmask) */
  SILC_ASN1_IMPLICIT     = 0x0010,       /* Tag is implicit (default) */
  SILC_ASN1_EXPLICIT     = 0x0020,	 /* Tag is explicit */
  SILC_ASN1_DEFINITE     = 0x0040,       /* Length is definite (default) */
  SILC_ASN1_INDEFINITE   = 0x0080,	 /* Length is indefinite */

  /* Decoding options (bitmask) */
  SILC_ASN1_OPTIONAL     = 0x0100,	 /* Zero or more may be found.  The
					    argument must be pointer to the
					    type pointer so that NULL can be
					    returned if type is not found. */

  /* ASN.1 encoder/decoder options (bitmask).  These can be given
     only with SILC_ASN1_OPTS macro at the start of encoding/decoding. */
  SILC_ASN1_ALLOC        = 0x0400,       /* Dynamically allocate results,
					    or if stack was given to
					    silc_asn1_alloc, they are allocated
					    and consumed from the stack. */
  SILC_ASN1_ACCUMUL      = 0x0800,       /* Accumulate memory for results,
					    next call to silc_asn1_decode
					    will not cancel old results. */
} SilcAsn1Options;
/***/

/****d* silcasn1/SilcASN1API/SilcAsn1Tag
 *
 * NAME
 *
 *    typedef enum { ... } SilcAsn1Tag;
 *
 * DESCRIPTION
 *
 *    Universal ASN.1 tags.  Usually these tags are given automatically
 *    to the silc_asn1_encode and silc_asn1_decode by using the various
 *    macros (such as SILC_ASN1_BOOLEAN).  Some macros may take the tag
 *    as additional argument.
 *
 * SOURCE
 */
typedef enum {
  SILC_ASN1_TAG_BOOLEAN               = 1,  /* SILC_ASN1_BOOLEAN */
  SILC_ASN1_TAG_INTEGER               = 2,  /* SILC_ASN1_INT */
  SILC_ASN1_TAG_BIT_STRING            = 3,  /* SILC_ASN1_BIT_STRING */
  SILC_ASN1_TAG_OCTET_STRING          = 4,  /* SILC_ASN1_OCTET_STRING */
  SILC_ASN1_TAG_NULL                  = 5,  /* SILC_ASN1_NULL */
  SILC_ASN1_TAG_OID                   = 6,  /* SILC_ASN1_OID */
  SILC_ASN1_TAG_ODE                   = 7,  /* not supported */
  SILC_ASN1_TAG_ETI                   = 8,  /* not supported */
  SILC_ASN1_TAG_REAL                  = 9,  /* not supported */
  SILC_ASN1_TAG_ENUM                  = 10, /* SILC_ASN1_ENUM */
  SILC_ASN1_TAG_EMBEDDED              = 11, /* not supported */
  SILC_ASN1_TAG_UTF8_STRING           = 12, /* SILC_ASN1_UTF8_STRING */
  SILC_ASN1_TAG_ROI                   = 13, /* not supported */
  SILC_ASN1_TAG_SEQUENCE              = 16, /* SILC_ASN1_SEQUENCE */
  SILC_ASN1_TAG_SET                   = 17, /* SILC_ASN1_SET */
  SILC_ASN1_TAG_NUMERIC_STRING        = 18, /* SILC_ASN1_NUMERIC_STRING */
  SILC_ASN1_TAG_PRINTABLE_STRING      = 19, /* SILC_ASN1_PRINTABLE_STRING */
  SILC_ASN1_TAG_TELETEX_STRING        = 20, /* SILC_ASN1_TELETEX_STRING */
  SILC_ASN1_TAG_VIDEOTEX_STRING       = 21, /* not supported */
  SILC_ASN1_TAG_IA5_STRING            = 22, /* SILC_ASN1_IA5_STRING */
  SILC_ASN1_TAG_UTC_TIME              = 23, /* SILC_ASN1_UTC_TIME */
  SILC_ASN1_TAG_GENERALIZED_TIME      = 24, /* SILC_ASN1_GENERAL_STRING */
  SILC_ASN1_TAG_GRAPHIC_STRING        = 25, /* not supported */
  SILC_ASN1_TAG_VISIBLE_STRING        = 26, /* SILC_ASN1_VISIBLE_STRING */
  SILC_ASN1_TAG_GENERAL_STRING        = 27, /* SILC_ASN1_GENERAL_STRING */
  SILC_ASN1_TAG_UNIVERSAL_STRING      = 28, /* SILC_ASN1_UNIVERSAL_STRING */
  SILC_ASN1_TAG_UNRESTRICTED_STRING   = 29, /* SILC_ASN1_UNRESTRICTED_STRING */
  SILC_ASN1_TAG_BMP_STRING            = 30, /* SILC_ASN1_BMP_STRING */
} SilcAsn1Tag;
/***/

#include "silcasn1_i.h"

/****f* silcasn1/SilcASN1API/silc_asn1_alloc
 *
 * SYNOPSIS
 *
 *    SilcAsn1 silc_asn1_alloc(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Allocates and initializes ASN.1 encoder/decoder and returns SilcAsn1
 *    context or NULL on error.  This context can be used with both
 *    silc_asn1_encode and silc_asn1_decode functions.  If `stack' is non-NULL
 *    all memory will be allocated from `stack'.
 *
 *    Usually SilcAsn1 is allocated when encoder or decoder is needed,
 *    however it is also possible to allocate long-lasting SilcAsn1 and
 *    use that every time ASN.1 routines are needed.  Application could
 *    for example allocate one SilcAsn1 and use that for all ASN.1 encoding
 *    and decoding.
 *
 *    When this context is freed with silc_asn1_free all memory will be
 *    freed, and all encoded ASN.1 buffers becomes invalid.  Also all
 *    data that is returned by silc_asn1_encode and silc_asn1_decode function
 *    becomes invalid, unless SILC_ASN1_ALLOC flag is used, in which case the
 *    memory is allocated from `stack' and the `stack' is consumed.
 *
 ***/
SilcAsn1 silc_asn1_alloc(SilcStack stack);

/****f* silcasn1/SilcASN1API/silc_asn1_free
 *
 * SYNOPSIS
 *
 *    void silc_asn1_free(SilcAsn1 asn1);
 *
 * DESCRIPTION
 *
 *    Frees the SilcAsn1 context and all allocated memory.  All encoded
 *    buffers and all decoded buffers with this context becomes invalid
 *    after this call.
 *
 ***/
void silc_asn1_free(SilcAsn1 asn1);

/****f* silcasn1/SilcASN1API/silc_asn1_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_asn1_init(SilcAsn1 asn1, SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Initializes a pre-allocated SilcAsn1 context.  This call is
 *    equivalent to silc_asn1_alloc except that this takes the pre-allocated
 *    context as argument.
 *
 * EXAMPLE
 *
 *    SilcAsn1Struct asn1;
 *    if (!silc_asn1_init(&asn1, NULL))
 *      error;
 *
 ***/
SilcBool silc_asn1_init(SilcAsn1 asn1, SilcStack stack);

/****f* silcasn1/SilcASN1API/silc_asn1_uninit
 *
 * SYNOPSIS
 *
 *    void silc_asn1_uninit(SilcAsn1 asn1);
 *
 * DESCRIPTION
 *
 *    Uninitializes a pre-allocated SilcAsn1 context.  Use this function
 *    instead of silc_asn1_free if you used silc_asn1_init.
 *
 ***/
void silc_asn1_uninit(SilcAsn1 asn1);

/****f* silcasn1/SilcASN1API/silc_asn1_encode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_asn1_encode(SilcAsn1 asn1, SilcBuffer dest, ...);
 *
 * DESCRIPTION
 *
 *    Encodes ASN.1 encoded buffer into `dest', from variable argument
 *    list of ASN.1 types.  The variable argument list forms the ASN.1
 *    trees and nodes that are encoded into the `dest'.  By default, the
 *    memory for `dest' is allocated from the `asn1', and the buffer becomes
 *    invalid either by calling silc_asn1_free, silc_asn1_uninit, or when
 *    silc_asn1_encode is called for the next time.
 *
 *    If the SILC_ASN1_OPTS macro with SILC_ASN1_ALLOC option is given then
 *    the `dest' is dynamically allocated and caller must free it by itself.
 *    If the `stack' was given to silc_asn1_alloc, the SILC_ASN1_ALLOC will
 *    allocate from that stack and consume the stack.  Alternatively if
 *    SILC_ASN1_ACCUMUL is given then memory is accumulated from `asn1' for
 *    `dest' and it is freed only when silc_asn1_free or silc_asn1_uninit
 *    is called.  Next call to silc_asn1_encode will not cancel the previous
 *    result, but will accumulate more memory for new result.
 *
 *    The variable argument list is constructed by using various
 *    macros, for example SILC_ASN1_SEQUENCE, etc.  The variable argument
 *    list must always be ended with SILC_ASN1_END type.
 *
 *    If encoding is successful this returns TRUE, FALSE on error.
 *
 * EXAMPLE
 *
 *    silc_asn1_encode(asn1, buf,
 *                     SILC_ASN1_SEQUENCE,
 *                       SILC_ASN1_BOOLEAN(bool_val),
 *                       SILC_ASN1_OCTET_STRING(string, string_len),
 *                       SILC_ASN1_SEQUENCE_T(0, 2),
 *                         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 100, foo),
 *                       SILC_ASN1_END,
 *                       SILC_ASN1_OCTET_STRING_T(0, 1, string2, string2_len),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 *    Creates ASN.1 tree that looks something like:
 *
 *    buf ::= SEQUENCE {
 *      bool_val      BOOLEAN,
 *      string        OCTET-STRING,
 *               [2]  SEQUENCE {
 *                      foo   [100] EXPLICIT BOOLEAN }
 *      string2  [1]  OCTET-STRING }
 *
 ***/
SilcBool silc_asn1_encode(SilcAsn1 asn1, SilcBuffer dest, ...);

/****f* silcasn1/SilcASN1API/silc_asn1_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_asn1_decode(SilcAsn1 asn1, SilcBuffer src, ...);
 *
 * DESCRIPTION
 *
 *    Decodes the ASN.1 encoded buffer `src' by the ASN.1 types sent
 *    as argument.  The ASN.1 types sent as argument must be found from
 *    the `src' for this function to decode successfully.
 *
 *    The memory allocated for the results are allocated from `asn1' and
 *    they become invalid if `asn1' becomes invalid.  Next (second) call
 *    to this function does NOT invalidate the previous results.  However,
 *    third call to this function does invalidate the results of the first
 *    call but not second.  On the other hand, fourth call invalidates
 *    the results of the second call but not third, fifth call invalidates
 *    the results of the third call but not fourth, and so on.  This allows
 *    efficient decoding, when silc_asn1_decode must be called multiple times
 *    to decode all data, without new memory allocations.  However, caller
 *    must be cautios and understand that the every second call invalidates
 *    the results of every second previous results.
 *
 *    If the SILC_ASN1_OPTS macro with SILC_ASN1_ALLOC option is given then
 *    all results are dynamically allocated and caller must free them by
 *    itself. If the `stack' was given to silc_asn1_alloc, the SILC_ASN1_ALLOC
 *    will allocate from that stack and consume the stack.  Alternatively if
 *    SILC_ASN1_ACCUMUL is given then memory is accumulated from `asn1' for
 *    results and they are freed only when the silc_asn1_free or
 *    silc_asn1_uninit is called.  Next calls to the silc_asn1_decode will
 *    NOT invalidate the old results, but will accumulate more memory for new
 *    results.  If the SILC_ASN1_OPTS is not given at all then the default
 *    allocation method (decribed above) applies.
 *
 *    If caller needs to store the results even after `asn1' becomes invalid
 *    then call must either use SILC_ASN1_ALLOC option or duplicate the
 *    results by itself.
 *
 * EXAMPLE
 *
 *    SilcBool bool_val, foo;
 *    unsigned char *string, string2;
 *    SilcUInt32 string_len, string2_len;
 *
 *    silc_asn1_decode(asn1, tree,
 *                     SILC_ASN1_SEQUENCE,
 *                       SILC_ASN1_BOOLEAN(&bool_val),
 *                       SILC_ASN1_OCTET_STRING(&string, &string_len),
 *                       SILC_ASN1_SEQUENCE_T(0, 2),
 *                         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 100, &foo),
 *                       SILC_ASN1_END,
 *                       SILC_ASN1_OCTET_STRING_T(0, 1, &str2, &str2_len),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
SilcBool silc_asn1_decode(SilcAsn1 asn1, SilcBuffer src, ...);

/****f* silcasn1/SilcASN1API/SILC_ASN1_OPTS
 *
 * SYNOPSIS
 *
 *    SILC_ASN1_OPTS(opts)
 *
 * DESCRIPTION
 *
 *    The `opts' is SilcAsn1Options.  This macro can be used to set
 *    options for silc_asn1_encode and silc_asn1_decode functions.
 *
 * NOTES
 *
 *    Only the SILC_ASN1_ALLOC and SILC_ASN1_ACCUMUL flags may be
 *    set with this macro.
 *
 *    This macro must be the first macro in the variable argument list
 *    in the function.
 *
 * EXAMPLE
 *
 *    silc_asn1_decode(asn1, tree,
 *                     SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
 *                     SILC_ASN1_SEQUENCE,
 *                       SILC_ASN1_BOOLEAN(&bool_val),
 *                       SILC_ASN1_OCTET_STRING(&string, &string_len),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_OPTS(opts) SILC_ASN1_TAG_OPTS, (opts)

/****f* silcasn1/SilcASN1API/SILC_ASN1_ANY
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_ANY(buffer)
 *    SILC_ASN1_ANY_T(opts, tag, buffer)
 *
 *    Decoding:
 *    SILC_ASN1_ANY(&buffer)
 *    SILC_ASN1_ANY_T(opts, tag, buffer)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode another ASN.1 node.  The buffer type
 *    is SilcBuffer.  This macro can be used for example to split large
 *    tree into multiple nodes, and then decoding the nodes separately from
 *    the buffers.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * EXAMPLE
 *
 *    // Encode node of two boolean values
 *    silc_asn1_encode(asn1, node,
 *                     SILC_ASN1_BOOLEAN(val1),
 *                     SILC_ASN1_BOOLEAN(val2),
 *                     SILC_ASN1_END);
 *
 *    // Encode tree with the node
 *    silc_asn1_encode(asn1, tree,
 *                     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
 *                       SILC_ASN1_ANY(node),
 *                       SILC_ASN1_BOOLEAN(boolval),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_ANY(x) SILC_ASN1_U1(ANY, x)
#define SILC_ASN1_ANY_T(o, t, x) SILC_ASN1_T1(ANY, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_ANY_PRIMITIVE
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_ANY_PRIMITIVE(tag, buffer)
 *    SILC_ASN1_ANY_PRIMITIVE_T(opts, tag, buffer)
 *
 *    Decoding:
 *    SILC_ASN1_ANY_PRIMITIVE(tag, &buffer)
 *    SILC_ASN1_ANY_PRIMITIVE_T(opts, tag, buffer)
 *
 * DESCRIPTION
 *
 *    Special macro used to encode pre-encoded primitive data blob.  The data
 *    can be any primitive type that is already encoded in correct format.
 *    The caller is responsible of making sure the data is formatted
 *    correctly.  When decoding this returns the raw data blob and the caller
 *    must know of what type and format it is.  The buffer type is SilcBuffer.
 *
 *    This macro can be used in cases when the data to be encoded is already
 *    in encoded format, and it only needs to be added to ASN.1 tree.  The
 *    SILC_ASN1_ANY cannot be used with primitives when tagging implicitly,
 *    in these cases this macro can be used.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * EXAMPLE
 *
 *    // Get MP integer in encoded format
 *    mpbuf = mp_get_octet_string(mp);
 *
 *    // Encode the MP integer data to the tree
 *    silc_asn1_encode(asn1, tree,
 *                     SILC_ASN1_ANY_PRIMITIVE(SILC_ASN1_TAG_INTEGER, mpbuf),
 *                     SILC_ASN1_END);
 *
 *    // Decode the MP integer data from the tree
 *    silc_asn1_decode(asn1, tree,
 *                     SILC_ASN1_ANY_PRIMITIVE(SILC_ASN1_TAG_INTEGER, &buffer),
 *                     SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_ANY_PRIMITIVE(t, x) SILC_ASN1_T1(ANY_PRIMITIVE, 0, t, x)
#define SILC_ASN1_ANY_PRIMITIVE_T(o, t, x) SILC_ASN1_T1(ANY_PRIMITIVE, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_SEQUENCE
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_SEQUENCE
 *    SILC_ASN1_SEQUENCE_T(opts, tag)
 *
 *    Decoding:
 *    SILC_ASN1_SEQUENCE
 *    SILC_ASN1_SEQUENCE_T(opts, tag)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode sequence.  The sequence must be
 *    terminated with SILC_ASN1_END.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * EXAMPLE
 *
 *    silc_asn1_encode(asn1, tree,
 *                     SILC_ASN1_SEQUENCE,
 *                       SILC_ASN1_ANY(node),
 *                       SILC_ASN1_BOOLEAN(boolval),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_SEQUENCE SILC_ASN1_U0(SEQUENCE)
#define SILC_ASN1_SEQUENCE_T(o, t) SILC_ASN1_T0(SEQUENCE, o, t)

/****f* silcasn1/SilcASN1API/SILC_ASN1_SET
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_SET
 *    SILC_ASN1_SET_T(opts, tag)
 *
 *    Decoding:
 *    SILC_ASN1_SET
 *    SILC_ASN1_SET_T(opts, tag)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode set.  The set must be terminated
 *    with SILC_ASN1_END.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * EXAMPLE
 *
 *    silc_asn1_encode(asn1, tree,
 *                     SILC_ASN1_SET_T(SILC_ASN1_EXPLICIT, 0),
 *                       SILC_ASN1_BOOLEAN(boolval),
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_SET SILC_ASN1_U0(SET)
#define SILC_ASN1_SET_T(o, t) SILC_ASN1_T0(SET, o, t)

/****f* silcasn1/SilcASN1API/SILC_ASN1_SEQUENCE_OF
 *
 * SYNOPSIS
 *
 *    Decoding:
 *    SILC_ASN1_SEQUENCE_OF(bufarray, numbufs)
 *
 * DESCRIPTION
 *
 *    Macro used to decode sequence of specified type.  This returns
 *    an array of SilcBuffers and number of buffers in the array.  The
 *    SILC_ASN1_CHOICE macro may also be used with this macro.
 *
 * NOTES
 *
 *    This macro must be used either with SILC_ASN1_ALLOC or SILC_ASN1_ACCUMUL
 *    flags.  Do not use this macro without flags.
 *
 * EXAMPLE
 *
 *     SilcBuffer bufs;
 *     SilcUInt32 count;
 *
 *     // Decode sequence of sequences.  Each returned buffer in the array
 *     // is a sequence.
 *     silc_asn1_decode(asn1, exts,
 *                      SILC_ASN1_OPTS(SILC_ASN1_ACCUMUL),
 *                      SILC_ASN1_SEQUENCE_OF(&bufs, &count),
 *                        SILC_ASN1_TAG_SEQUENCE,
 *                      SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_SEQUENCE_OF(x, c) SILC_ASN1_U2(SEQUENCE_OF, x, c)

/****f* silcasn1/SilcASN1API/SILC_ASN1_SET_OF
 *
 * SYNOPSIS
 *
 *    Decoding:
 *    SILC_ASN1_SET_OF(bufarray, numbufs)
 *
 * DESCRIPTION
 *
 *    Macro used to decode set of specified type.  This returns
 *    an array of SilcBuffers and number of buffers in the array.  The
 *    SILC_ASN1_CHOICE macro may also be used with this macro.
 *
 * NOTES
 *
 *    This macro must be used either with SILC_ASN1_ALLOC or SILC_ASN1_ACCUMUL
 *    flags.  Do not use this macro without flags.
 *
 * EXAMPLE
 *
 *     // Decode set of sequences.  Each returned buffer in the array
 *     // is a sequence.
 *     silc_asn1_decode(asn1, exts,
 *                      SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
 *                      SILC_ASN1_SET_OF(&bufs, &count),
 *                        SILC_ASN1_TAG_SEQUENCE,
 *                      SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_SET_OF(x, c) SILC_ASN1_U2(SEQUENCE_OF, x, c)

/****f* silcasn1/SilcASN1API/SILC_ASN1_CHOICE
 *
 * SYNOPSIS
 *
 *    Decoding:
 *    SILC_ASN1_CHOICE(&chosen)
 *
 * DESCRIPTION
 *
 *    Macro used to specify choices in decoding.  The choice list must
 *    be terminated with SILC_ASN1_END.  There is no limit how many choices
 *    can be specified in the list.  The `chosen' is SilcUInt32 and its
 *    value tells which of the choice was found.  First choice in the list
 *    has value 1, second value 2, and so on.
 *
 * EXAMPLE
 *
 *    // Decode timeval that is either UTC or generalized time
 *    silc_asn1_decode(asn1, tree,
 *                     SILC_ASN1_SEQUENCE,
 *                       SILC_ASN1_CHOICE(&chosen),
 *                         SILC_ASN1_UTC_TIME(&timeval),
 *                         SILC_ASN1_GEN_TIME(&timeval),
 *                       SILC_ASN1_END,
 *                     SILC_ASN1_END, SILC_ASN1_END);
 *
 ***/
#define SILC_ASN1_CHOICE(x) SILC_ASN1_U1(CHOICE, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_BOOLEAN
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_BOOLEAN(boolval)
 *    SILC_ASN1_BOOLEAN_T(opts, tag, boolval)
 *
 *    Decoding:
 *    SILC_ASN1_BOOLEAN(&boolval)
 *    SILC_ASN1_BOOLEAN_T(opts, tag, &boolval)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode boolean value.  The boolean type
 *    is SilcBool.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_BOOLEAN(x) SILC_ASN1_U1(BOOLEAN, x)
#define SILC_ASN1_BOOLEAN_T(o, t, x) SILC_ASN1_T1(BOOLEAN, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_INT
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_INT(integer)
 *    SILC_ASN1_INT_T(opts, tag, &integer)
 *
 *    Decoding:
 *    SILC_ASN1_INT(&integer)
 *    SILC_ASN1_INT_T(opts, tag, &integer);
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode multiple precision integer.  The
 *    integer type is SilcMPInt.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_INT(x) SILC_ASN1_U1(INTEGER, x)
#define SILC_ASN1_INT_T(o, t, x) SILC_ASN1_T1(INTEGER, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_SHORT_INT
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_SHORT_INT(integer)
 *    SILC_ASN1_SHORT_INT_T(opts, tag, &integer)
 *
 *    Decoding:
 *    SILC_ASN1_SHORT_INT(&integer)
 *    SILC_ASN1_SHORT_INT_T(opts, tag, &integer);
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode short integer (32 bits).  The
 *    integer type is SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_SHORT_INT(x) SILC_ASN1_U1(SHORT_INTEGER, x)
#define SILC_ASN1_SHORT_INT_T(o, t, x) SILC_ASN1_T1(SHORT_INTEGER, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_ENUM
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_ENUM(enum)
 *    SILC_ASN1_ENUM_T(opts, tag, &enum)
 *
 *    Decoding:
 *    SILC_ASN1_ENUM(&enum)
 *    SILC_ASN1_ENUM_T(opts, tag, &enum);
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode enumeration value.  The enumeration
 *    type is SilcMPInt.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_ENUM(x) SILC_ASN1_U1(ENUM, x)
#define SILC_ASN1_ENUM_T(o, t, x) SILC_ASN1_T1(ENUM, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_BIT_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_BIT_STRING(str, str_len)
 *    SILC_ASN1_BIT_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_BIT_STRING(&str, &str_len)
 *    SILC_ASN1_BIT_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode bit string.  The string length in
 *    encoding must be in bits (bytes * 8).  The decoded length is in
 *    bits as well.  The string type is unsigned char and string length
 *    SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_BIT_STRING(x, xl) SILC_ASN1_U2(BIT_STRING, x, xl)
#define SILC_ASN1_BIT_STRING_T(o, t, x, xl) SILC_ASN1_T2(BIT_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_NULL
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_NULL
 *    SILC_ASN1_NULL_T(opts, tag, set)
 *
 *    Decoding:
 *    SILC_ASN1_NULL
 *    SILC_ASN1_NULL_T(opts, tag, &set)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode null value.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.  In encoding
 *    `set' is SilcBool and if it is TRUE the NULL value will be encoded.  If
 *    it is FALSE the SILC_ASN1_NULL will be ignored.  In decoding the `set'
 *    is SilcBool and if it is TRUE the NULL value was present.  This can be
 *    used to verify whether NULL was present if it is SILC_ASN1_OPTIONAL.
 *
 ***/
#define SILC_ASN1_NULL(x) SILC_ASN1_U1(NULL, x)
#define SILC_ASN1_NULL_T(o, t, x) SILC_ASN1_T1(NULL, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_OID
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_OID(oid)
 *    SILC_ASN1_OID_T(opts, tag, oid)
 *
 *    Decoding:
 *    SILC_ASN1_OID(&oid)
 *    SILC_ASN1_OID_T(opts, tag, &oid)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode OID string.  The OID string type
 *    is NULL terminated char.  Its length can be determinted with strlen().
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_OID(x) SILC_ASN1_U1(OID, x)
#define SILC_ASN1_OID_T(o, t, x) SILC_ASN1_UT(OID, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_OCTET_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_OCTET_STRING(str, str_len)
 *    SILC_ASN1_OCTET_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_OCTET_STRING(&str, &str_len)
 *    SILC_ASN1_OCTET_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode octet string.  The string type is
 *    unsigned char and string length SilcUInt32.  Octet string is
 *    considered to be 8-bit unsigned binary data.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_OCTET_STRING(x, xl) SILC_ASN1_U2(OCTET_STRING, x, xl)
#define SILC_ASN1_OCTET_STRING_T(o, t, x, xl) SILC_ASN1_T2(OCTET_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_UTF8_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_UTF8_STRING(str, str_len)
 *    SILC_ASN1_UTF8_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_UTF8_STRING(&str, &str_len)
 *    SILC_ASN1_UTF8_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode UTF-8 string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The data is also encoded to
 *    or decoded from UTF-8.
 *
 ***/
#define SILC_ASN1_UTF8_STRING(x, xl) SILC_ASN1_U2(UTF8_STRING, x, xl)
#define SILC_ASN1_UTF8_STRING_T(o, t, x, xl) SILC_ASN1_T2(UTF8_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_NUMERIC_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_NUMERIC_STRING(str, str_len)
 *    SILC_ASN1_NUMERIC_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_NUMERIC_STRING(&str, &str_len)
 *    SILC_ASN1_NUMERIC_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode numerical string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from numerical.
 *
 ***/
#define SILC_ASN1_NUMERIC_STRING(x, xl) SILC_ASN1_U2(NUMERIC_STRING, x, xl)
#define SILC_ASN1_NUMERIC_STRING_T(o, t, x, xl) SILC_ASN1_T2(NUMERIC_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_PRINTABLE_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_PRINTABLE_STRING(str, str_len)
 *    SILC_ASN1_PRINTABLE_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_PRINTABLE_STRING(&str, &str_len)
 *    SILC_ASN1_PRINTABLE_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode printable string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from printable.
 *
 ***/
#define SILC_ASN1_PRINTABLE_STRING(x, xl) SILC_ASN1_U2(PRINTABLE_STRING, x, xl)
#define SILC_ASN1_PRINTABLE_STRING_T(o, t, x, xl) SILC_ASN1_T2(PRINTABLE_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_TELETEX_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_TELETEX_STRING(str, str_len)
 *    SILC_ASN1_TELETEX_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_TELETEX_STRING(&str, &str_len)
 *    SILC_ASN1_TELETEX_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode teletex (T61) string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from teletex (T61).
 *
 ***/
#define SILC_ASN1_TELETEX_STRING(x, xl) SILC_ASN1_U2(TELETEX_STRING, x, xl)
#define SILC_ASN1_TELETEX_STRING_T(o, t, x, xl) SILC_ASN1_T2(TELETEX_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_IA5_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_IA5_STRING(str, str_len)
 *    SILC_ASN1_IA5_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_IA5_STRING(&str, &str_len)
 *    SILC_ASN1_IA5_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode US ASCII (IA5) string.  The string type
 *    is unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from US ASCII (IA5).
 *
 ***/
#define SILC_ASN1_IA5_STRING(x, xl) SILC_ASN1_U2(IA5_STRING, x, xl)
#define SILC_ASN1_IA5_STRING_T(o, t, x, xl) SILC_ASN1_T2(IA5_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_VISIBLE_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_VISIBLE_STRING(str, str_len)
 *    SILC_ASN1_VISIBLE_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_VISIBLE_STRING(&str, &str_len)
 *    SILC_ASN1_VISIBLE_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode visible string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from visible.
 *
 ***/
#define SILC_ASN1_VISIBLE_STRING(x, xl) SILC_ASN1_U2(VISIBLE_STRING, x, xl)
#define SILC_ASN1_VISIBLE_STRING_T(o, t, x, xl) SILC_ASN1_T2(VISIBLE_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_UNIVERSAL_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_UNIVERSAL_STRING(str, str_len)
 *    SILC_ASN1_UNIVERSAL_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_UNIVERSAL_STRING(&str, &str_len)
 *    SILC_ASN1_UNIVERSAL_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode universal (UCS-4) string.  The string
 *    type is unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from universal (UCS-4).
 *
 ***/
#define SILC_ASN1_UNIVERSAL_STRING(x, xl) SILC_ASN1_U2(UNIVERSAL_STRING, x, xl)
#define SILC_ASN1_UNIVERSAL_STRING_T(o, t, x, xl) SILC_ASN1_T2(UNIVERSAL_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_BMP_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_BMP_STRING(str, str_len)
 *    SILC_ASN1_BMP_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_BMP_STRING(&str, &str_len)
 *    SILC_ASN1_BMP_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode BMP (UCS-2) string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from BMP (UCS-2)
 *
 ***/
#define SILC_ASN1_BMP_STRING(x, xl) SILC_ASN1_U2(BMP_STRING, x, xl)
#define SILC_ASN1_BMP_STRING_T(o, t, x, xl) SILC_ASN1_T2(BMP_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_UNRESTRICTED_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_UNRESTRICTED_STRING(str, str_len)
 *    SILC_ASN1_UNRESTRICTED_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_UNRESTRICTED_STRING(&str, &str_len)
 *    SILC_ASN1_UNRESTRICTED_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode unrestricted string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from unrestricted.  NOTE: this implementation use 8-bit ASCII.
 *
 ***/
#define SILC_ASN1_UNRESTRICTED_STRING(x, xl) SILC_ASN1_U2(UNRESTRICTED_STRING, x, xl)
#define SILC_ASN1_UNRESTRICTED_STRING_T(o, t, x, xl) SILC_ASN1_T2(UNRESTRICTED_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_GENERAL_STRING
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_GENERAL_STRING(str, str_len)
 *    SILC_ASN1_GENERAL_STRING_T(opts, tag, str, str_len)
 *
 *    Decoding:
 *    SILC_ASN1_GENERAL_STRING(&str, &str_len)
 *    SILC_ASN1_GENERAL_STRING_T(opts, tag, &str, &str_len)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode general string.  The string type is
 *    unsigned char and string length SilcUInt32.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 * NOTES
 *
 *    The string must be in UTF-8 encoding when encoding.  The decoded
 *    string will be in UTF-8 encoding.  The actual data is encoded to
 *    or decoded from general.  NOTE: this implementation use 8-bit ASCII.
 *
 ***/
#define SILC_ASN1_GENERAL_STRING(x, xl) SILC_ASN1_U2(GENERAL_STRING, x, xl)
#define SILC_ASN1_GENERAL_STRING_T(o, t, x, xl) SILC_ASN1_T2(GENERAL_STRING, o, t, x, xl)

/****f* silcasn1/SilcASN1API/SILC_ASN1_UTC_TIME
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_UTC_TIME(timeval)
 *    SILC_ASN1_UTC_TIME_T(opts, tag, timeval)
 *
 *    Decoding:
 *    SILC_ASN1_UTC_TIME(&str, &timeval)
 *    SILC_ASN1_UTC_TIME_T(opts, tag, timeval)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode universal (UTC) time value.  The
 *    time value type is SilcTime.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_UTC_TIME(x) SILC_ASN1_U1(UTC_TIME, x)
#define SILC_ASN1_UTC_TIME_T(o, t, x) SILC_ASN1_T1(UTC_TIME, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_GEN_TIME
 *
 * SYNOPSIS
 *
 *    Encoding:
 *    SILC_ASN1_GEN_TIME(timeval)
 *    SILC_ASN1_GEN_TIME_T(opts, tag, timeval)
 *
 *    Decoding:
 *    SILC_ASN1_GEN_TIME(&str, &timeval)
 *    SILC_ASN1_GEN_TIME_T(opts, tag, timeval)
 *
 * DESCRIPTION
 *
 *    Macro used to encode or decode generalized time value.  The
 *    time value type is SilcTime.
 *
 *    The `opts' is SilcAsn1Options.  The `tag' is a tag number.
 *
 ***/
#define SILC_ASN1_GEN_TIME(x) SILC_ASN1_U1(GENERALIZED_TIME, x)
#define SILC_ASN1_GEN_TIME_T(o, t, x) SILC_ASN1_T1(GENERALIZED_TIME, o, t, x)

/****f* silcasn1/SilcASN1API/SILC_ASN1_END
 *
 * SYNOPSIS
 *
 *    SILC_ASN1_END
 *
 * DESCRIPTION
 *
 *    The SILC_ASN1_END is used to terminate the variable argument list in
 *    silc_asn1_encode and silc_asn1_decode functions.  It is also used to
 *    terminate SILC_ASN1_SEQUENCE, SILC_ASN1_SEQUENCE_T, SILC_ASN1_SET,
 *    SILC_ASN1_SET_T, SILC_ASN1_SEQUENCE_OF, SILC_ASN1_SET_OF and
 *    SILC_ASN1_CHOICE macros.
 *
 ***/
#define SILC_ASN1_END 0

#endif /* SILCASN1_H */
