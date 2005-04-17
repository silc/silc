/*

  silcstringprep.c

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

#include "silcincludes.h"
#include "silcstringprep.h"
#include <stringprep.h>

/* We use GNU Libidn which has stringprep to do the magic.  Only bad thing
   is that its interface is idiotic.  We have our own API here in case
   we'll implement it ourselves later. */

/* Prohibited characters as defined by the protocol in Appendix C */
const Stringprep_table_element silc_appendix_c[] =
{
  {0x000021}, {0x00002A}, {0x00002C}, {0x00003F}, {0x000040},
  {0}
};

/* Prohibited characters as defined by the protocol in Appendix D */
const Stringprep_table_element silc_appendix_d[] =
{
  {0x0000A2, 0x0000A9},
  {0x0000AC}, {0x0000AE}, {0x0000AF}, {0x0000B0}, {0x0000B1}, {0x0000B4},
  {0x0000B6}, {0x0000B8}, {0x0000D7}, {0x0000F7},
  {0x0002C2, 0x0002C5}, {0x0002D2, 0x0002FF},
  {0x000374}, {0x000375}, {0x000384}, {0x000385}, {0x0003F6}, {0x000482},
  {0x00060E}, {0x00060F}, {0x0006E9}, {0x0006FD}, {0x0006FE}, {0x0009F2},
  {0x0009F3}, {0x0009FA}, {0x000AF1}, {0x000B70},
  {0x000BF3, 0x000BFA}, {0x000E3F},
  {0x000F01, 0x000F03}, {0x000F13, 0x000F17}, {0x000F1A, 0x000F1F},
  {0x000F34}, {0x000F36}, {0x000F38}, {0x000FBE}, {0x000FBF},
  {0x000FC0, 0x000FC5}, {0x000FC7, 0x000FCF}, {0x0017DB}, {0x001940},
  {0x0019E0, 0x0019FF}, {0x001FBD}, {0x001FBF, 0x001FC1},
  {0x001FCD, 0x001FCF}, {0x001FDD, 0x001FDF}, {0x001FED, 0x001FEF},
  {0x001FFD}, {0x001FFE}, {0x002044}, {0x002052}, {0x00207A, 0x00207C},
  {0x00208A, 0x00208C}, {0x0020A0, 0x0020B1}, {0x002100, 0x00214F},
  {0x002150, 0x00218F}, {0x002190, 0x0021FF}, {0x002200, 0x0022FF},
  {0x002300, 0x0023FF}, {0x002400, 0x00243F}, {0x002440, 0x00245F},
  {0x002460, 0x0024FF}, {0x002500, 0x00257F}, {0x002580, 0x00259F},
  {0x0025A0, 0x0025FF}, {0x002600, 0x0026FF}, {0x002700, 0x0027BF},
  {0x0027C0, 0x0027EF}, {0x0027F0, 0x0027FF}, {0x002800, 0x0028FF},
  {0x002900, 0x00297F}, {0x002980, 0x0029FF}, {0x002A00, 0x002AFF},
  {0x002B00, 0x002BFF}, {0x002E9A}, {0x002EF4, 0x002EFF},
  {0x002FF0, 0x002FFF}, {0x00303B, 0x00303D}, {0x003040},
  {0x003095, 0x003098}, {0x00309F, 0x0030A0}, {0x0030FF, 0x003104},
  {0x00312D, 0x003130}, {0x00318F}, {0x0031B8, 0x0031FF},
  {0x00321D, 0x00321F}, {0x003244, 0x00325F}, {0x00327C, 0x00327E},
  {0x0032B1, 0x0032BF}, {0x0032CC, 0x0032CF}, {0x0032FF},
  {0x003377, 0x00337A}, {0x0033DE, 0x0033DF}, {0x0033FF},
  {0x004DB6, 0x004DFF},
  {0x009FA6, 0x009FFF}, {0x00A48D, 0x00A48F}, {0x00A4A2, 0x00A4A3},
  {0x00A4B4}, {0x00A4C1}, {0x00A4C5}, {0x00A4C7, 0x00ABFF},
  {0x00D7A4, 0x00D7FF}, {0x00FA2E, 0x00FAFF}, {0x00FFE0, 0x00FFEE},
  {0x00FFFC}, {0x010000, 0x01007F}, {0x010080, 0x0100FF},
  {0x010100, 0x01013F}, {0x01D000, 0x01D0FF}, {0x01D100, 0x01D1FF},
  {0x01D300, 0x01D35F}, {0x01D400, 0x01D7FF},
  {0x0E0100, 0x0E01EF},
  {0}
};

/* Default SILC Identifier String profile defined by the protocol */
const Stringprep_profile stringprep_silc_identifier_prep[] =
{
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_1},
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_2},
  {STRINGPREP_NFKC, 0, 0},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_1_1},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_1_2},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_2_1},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_2_2},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_3},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_4},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_5},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_6},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_7},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_8},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_9},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_9},
  {STRINGPREP_PROHIBIT_TABLE, 0, silc_appendix_c},
  {STRINGPREP_PROHIBIT_TABLE, 0, silc_appendix_d},
  {STRINGPREP_UNASSIGNED_TABLE, 0, stringprep_rfc3454_A_1},
  {0}
};

/* Default channel name string profile defined by the protocol */
const Stringprep_profile stringprep_silc_identifier_ch_prep[] =
{
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_1},
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_2},
  {STRINGPREP_NFKC, 0, 0},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_1_1},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_1_2},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_2_1},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_2_2},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_3},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_4},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_5},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_6},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_7},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_8},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_9},
  {STRINGPREP_PROHIBIT_TABLE, 0, stringprep_rfc3454_C_9},
  {STRINGPREP_PROHIBIT_TABLE, 0, silc_appendix_d},
  {STRINGPREP_UNASSIGNED_TABLE, 0, stringprep_rfc3454_A_1},
  {0}
};

/* Identifier string case folding and normalizing */
const Stringprep_profile stringprep_silc_identifierc_prep[] =
{
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_1},
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_2},
  {STRINGPREP_NFKC, 0, 0},
  {0}
};

/* Case folding and normalizing */
const Stringprep_profile stringprep_silc_casefold_prep[] =
{
  {STRINGPREP_MAP_TABLE, 0, stringprep_rfc3454_B_2},
  {STRINGPREP_NFKC, 0, 0},
  {0}
};


/* Prepares string according to the profile */

SilcStringprepStatus
silc_stringprep(const unsigned char *bin, SilcUInt32 bin_len,
		SilcStringEncoding bin_encoding,
		const char *profile_name,
		SilcStringprepFlags flags,
		unsigned char **out, SilcUInt32 *out_len,
		SilcStringEncoding out_encoding)
{
  Stringprep_profile_flags f = 0;
  const Stringprep_profile *profile;
  unsigned char *utf8s;
  SilcUInt32 utf8s_len;
  int ret;

  SILC_LOG_DEBUG(("Preparing string"));

  if (!bin || !bin_len || !profile_name)
    return SILC_STRINGPREP_ERR;

  /* Convert string to UTF-8 */
  utf8s_len = silc_utf8_encoded_len(bin, bin_len, bin_encoding);
  if (!utf8s_len)
    return SILC_STRINGPREP_ERR_ENCODING;
  utf8s = silc_calloc(utf8s_len + 1, sizeof(*utf8s));
  if (!utf8s)
    return SILC_STRINGPREP_ERR_OUT_OF_MEMORY;
  silc_utf8_encode(bin, bin_len, bin_encoding, utf8s, utf8s_len);

  /* Check profile. */
  if (!strcmp(profile_name, SILC_IDENTIFIER_PREP))
    profile = stringprep_silc_identifier_prep;
  else if (!strcmp(profile_name, SILC_IDENTIFIER_CH_PREP))
    profile = stringprep_silc_identifier_ch_prep;
  else if (!strcmp(profile_name, SILC_IDENTIFIERC_PREP))
    profile = stringprep_silc_identifierc_prep;
  else if (!strcmp(profile_name, SILC_CASEFOLD_PREP))
    profile = stringprep_silc_casefold_prep;
  else
    return SILC_STRINGPREP_ERR_UNSUP_PROFILE;

  /* Translate flags */
  if (!(flags & SILC_STRINGPREP_ALLOW_UNASSIGNED))
    f |= STRINGPREP_NO_UNASSIGNED;

  /* Prepare */
  ret = stringprep((char *)utf8s, utf8s_len + 1, f, profile);
  SILC_LOG_DEBUG(("stringprep() return %d", ret));

  /* Since the stringprep() doesn't allocate returned buffer, and
     stringprep_profile() doesn't do it correctly, we can't know how
     much space we must have for the conversion.  Allocate more if it
     fails, and try again. */
  if (ret == STRINGPREP_TOO_SMALL_BUFFER) {
    utf8s = silc_realloc(utf8s, sizeof(*utf8s) * (utf8s_len * 2));
    if (!utf8s)
      return SILC_STRINGPREP_ERR_OUT_OF_MEMORY;
    memset(utf8s + utf8s_len, 0, utf8s_len);
    ret = stringprep((char *)utf8s, utf8s_len * 2, f, profile);
    SILC_LOG_DEBUG(("stringprep() return %d", ret));
  }

  switch (ret) {
  case STRINGPREP_OK:
    ret = SILC_STRINGPREP_OK;
    break;

  case STRINGPREP_CONTAINS_UNASSIGNED:
    ret = SILC_STRINGPREP_ERR_UNASSIGNED;
    break;

  case STRINGPREP_CONTAINS_PROHIBITED:
    ret = SILC_STRINGPREP_ERR_PROHIBITED;
    break;

  case STRINGPREP_BIDI_BOTH_L_AND_RAL:
    ret = SILC_STRINGPREP_ERR_BIDI_RAL_WITH_L;
    break;

  case STRINGPREP_BIDI_LEADTRAIL_NOT_RAL:
    ret = SILC_STRINGPREP_ERR_BIDI_RAL;
    break;

  case STRINGPREP_BIDI_CONTAINS_PROHIBITED:
    ret = SILC_STRINGPREP_ERR_BIDI_PROHIBITED;
    break;

  case STRINGPREP_UNKNOWN_PROFILE:
    ret = SILC_STRINGPREP_ERR_UNSUP_PROFILE;
    break;

  case STRINGPREP_MALLOC_ERROR:
    ret = SILC_STRINGPREP_ERR_OUT_OF_MEMORY;
    break;

  default:
    ret = SILC_STRINGPREP_ERR;
    break;
  }

  /* Convert to desired output character encoding */
  if (ret == SILC_STRINGPREP_OK) {
    if (out && out_len) {
      if (out_encoding != SILC_STRING_UTF8) {
	*out_len = silc_utf8_decoded_len(utf8s, strlen(utf8s), out_encoding);
	if (*out_len) {
	  *out = silc_calloc(*out_len + 1, sizeof(**out));
	  if (*out) {
	    silc_utf8_decode(utf8s, strlen(utf8s), out_encoding, *out,
			     *out_len);
	  } else {
	    ret = SILC_STRINGPREP_ERR_OUT_OF_MEMORY;
	  }
	} else {
	  ret = SILC_STRINGPREP_ERR_ENCODING;
	}
      } else {
	*out_len = strlen(utf8s);
	*out = silc_memdup(utf8s, *out_len);
      }
    }
  }

  silc_free(utf8s);

  return (SilcStringprepStatus)ret;
}
