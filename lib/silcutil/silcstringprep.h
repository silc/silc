/*

  silcstringprep.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Stringprep
 *
 * DESCRIPTION
 *
 * Interface for the stringprep (RFC3454) standard, that is used to prepare
 * strings for internationalization.  The interface can be used to prepare
 * strings according to various stringprep profiles.  The profiles defines
 * what characters the strings may contain, what characters are prohibited
 * and how the strings are prepared.
 *
 ***/

#ifndef SILCSTRINGPREP_H
#define SILCSTRINGPREP_H

/****d* silcutil/SilcStringprep/SilcStringprepStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcStringprepStatus;
 *
 * DESCRIPTION
 *
 *    Status and errors returned by silc_stringprep.
 *
 * SOURCE
 */
typedef enum {
  SILC_STRINGPREP_OK,		          /* Preparation success */
  SILC_STRINGPREP_ERR_UNASSIGNED,         /* Contains unassigned characters */
  SILC_STRINGPREP_ERR_PROHIBITED,	  /* Contains prohibited characters */
  SILC_STRINGPREP_ERR_BIDI_PROHIBITED,	  /* BIDI contains prohibited chars */
  SILC_STRINGPREP_ERR_BIDI_RAL_WITH_L,	  /* BIDI has both R/AL and L */
  SILC_STRINGPREP_ERR_BIDI_RAL,		  /* BIDI has R/AL but not as leading
					     and/or trailing character. */
  SILC_STRINGPREP_ERR_OUT_OF_MEMORY,	  /* System out of memory */
  SILC_STRINGPREP_ERR_ENCODING,		  /* Character encoding error */
  SILC_STRINGPREP_ERR_UNSUP_ENCODING,     /* Unsupported character encoding  */
  SILC_STRINGPREP_ERR_UNSUP_PROFILE,	  /* Unsupported profile */
  SILC_STRINGPREP_ERR,			  /* Unknown error */
} SilcStringprepStatus;
/***/

/****d* silcutil/SilcStringprep/SilcStringprepFlags
 *
 * NAME
 *
 *    typedef enum { ... } SilcStringprepFlags;
 *
 * DESCRIPTION
 *
 *    Flags that change how the strings are prepared with silc_stringprep.
 *
 * SOURCE
 */
typedef enum {
  SILC_STRINGPREP_NONE               = 0x00,  /* No flags */
  SILC_STRINGPREP_ALLOW_UNASSIGNED   = 0x01,  /* Allow unassigned characters
						 without returning error. */
} SilcStringprepFlags;
/***/

/* Profiles */
#define SILC_IDENTIFIER_PREP "silc-identifier-prep"
#define SILC_IDENTIFIERC_PREP "silc-identifierc-prep"
#define SILC_CASEFOLD_PREP "silc-casefold-prep"

/****f* silcutil/SilcStringprep/silc_stringprep
 *
 * SYNOPSIS
 *
 *    SilcStringprepStatus
 *    silc_stringprep(const unsigned char *bin, SilcUInt32 bin_len,
 *                    SilcStringEncoding bin_encoding,
 *                    const char *profile_name,
 *                    SilcStringprepFlags flags,
 *                    unsigned char **out, SilcUInt32 *out_len,
 *                    SilcStringEncoding out_encoding);
 *
 * DESCRIPTION
 *
 *    Prepares the input string 'bin' of length 'bin_len' of encoding
 *    'bin_encoding' according to the stringrep profile 'profile_name'.
 *    Returns the prepared and allocated string into 'out'.  The 'out_len'
 *    indicates the length of the prepared string.  This returns the
 *    SilcStringprepStatus which indicates the status of the preparation.
 *    For example, if the input string contains prohibited characters
 *    (according to the used profile) this function will return error.
 *    The 'flags' however can be used to modify the behavior of this
 *    function.  Caller must free the returned 'out' string.
 *
 *    The output string will be encoded into the character encoding
 *    defined by the 'out_encoding'.  This allows caller to have for
 *    example the input string as locale specific string and output string
 *    as UTF-8 encoded string.
 *
 *    If the 'out' is NULL this function merely performs the preparation
 *    process, but does not return anything.  In this case this function
 *    could be used to for example verify that an input string that ought
 *    to have been prepared correctly was done so.
 *
 *    Available profile names:
 *
 *      SILC_IDENTIFIER_PREP            Prepares SILC identifier strings
 *      SILC_IDENTIFIERC_PREP           Casefolds identifier strings
 *      SILC_CASEFOLD_PREP              Casefolding and normalizing
 *
 ***/
SilcStringprepStatus
silc_stringprep(const unsigned char *bin, SilcUInt32 bin_len,
		SilcStringEncoding bin_encoding,
		const char *profile_name,
		SilcStringprepFlags flags,
		unsigned char **out, SilcUInt32 *out_len,
		SilcStringEncoding out_encoding);

#endif /* SILCSTRINGPREP_H */
