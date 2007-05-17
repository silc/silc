/*

  silcvcard.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcvcard/SILC VCard
 *
 * DESCRIPTION
 *
 * Implementation of the VCard 3.0 standard (RFC 2426) that can be used
 * with Requested Attributes (in WHOIS command) to deliver personal
 * information.  All fields are not supported since some of the
 * information are not needed in context of SILC.  If such VCard is
 * received this implementation ignores the unsupported fields.
 *
 ***/

#ifndef SILCVCARD_H
#define SILCVCARD_H

/****s* silcvcard/SilcVCard/SilcVCard
 *
 * NAME
 *
 *    typedef struct { ... } SilcVCardStruct, *SilcVCard;
 *
 * DESCRIPTION
 *
 *    This structure is the VCard.  This holds the contents of the
 *    card.  When a card is parsed it is parsed into this structure.
 *    When creating a new card application fills this structure and
 *    the library encodes the card from it.  Free the allocated
 *    structure with silc_vcard_free function.
 *
 * SOURCE
 */
typedef struct SilcVCardObject {
  char *full_name;	    /* full name, X.520 common name */
  char *family_name;	    /* last name, string */
  char *first_name;	    /* first name, string */
  char *middle_names;	    /* other names, string (comma sep.) */
  char *prefix;		    /* honorifix prefix (Mr., Mrs.), string */
  char *suffix;		    /* honorifix suffix (MD), string (comma sep.) */
  char *nickname;	    /* string (comma sep. if more than one) */
  char *bday;		    /* birth day, UTC date string */
  char *title;		    /* job title X.520, string */
  char *role;		    /* job role X.520, string */
  char *org_name;	    /* organization name, string */
  char *org_unit;	    /* organization unit, string */
  char *categories;	    /* application category, string */
  char *catclass;	    /* class (public, private, confidental), string */
  char *url;		    /* home page, URI string */
  char *label;		    /* formatted address label, string (same
			       format as for 'addr' but comma sep.) */

  struct addr {
    char *type;		    /* address type, string
			       (intl, dom, home, work, pref, postal, parcel) */
    char *pbox;		    /* post office box, string */
    char *ext_addr;	    /* extended address, string */
    char *street_addr;	    /* street address, string */
    char *city;		    /* city, string */
    char *state;	    /* state/province, string */
    char *code;		    /* postal code, string */
    char *country;	    /* country name, string */
  } *addrs;
  SilcUInt8 num_addrs;	    /* number of addresses */

  struct tel {
    char *type;		    /* telephone number type, string
			       (msg, voice, home, work, pref, bbs, modem, car,
			       cell, video, pager, isdn, fax) */
    char *telnum;	    /* single telephone number, string */
  } *tels;
  SilcUInt8 num_tels;

  struct email {
    char *type;		    /* email type, string (internet, pref, x400) */
    char *address;	    /* single email address, string */
  } *emails;
  SilcUInt8 num_emails;

  char *note;		    /* a note, string */
  char *rev;		    /* revision of card, UTC date string */

  SilcBool dynamic;		    /* TRUE when dynamically allocated */
} SilcVCardStruct, *SilcVCard;
/***/

/****f* silcvcard/SilcVCard/silc_vcard_encode
 *
 * SYNOPSIS
 *
 *    char *silc_vcard_encode(SilcVCard vcard, SilcUInt32 *vcard_len);
 *
 * DESCRIPTION
 *
 *    Encodes VCard from the SilcVCard structure indicated by `vcard'
 *    which the caller must fill before calling this function.  This
 *    function encodes the card and returns allocated buffer and
 *    its length into `vcard_len'.  The caller must free the returned
 *    buffer.  Returns NULL on error.
 *
 ***/
unsigned char *silc_vcard_encode(SilcVCard vcard, SilcUInt32 *vcard_len);

/****f* silcvcard/SilcVCard/silc_vcard_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_vcard_decode(const unsigned char *data,
 *                               SilcUInt32 data_len, SilcVCard vcard);
 *
 * DESCRIPTION
 *
 *    Decodes VCard from the buffer `vcard' of length of `vcard_len' bytes
 *    and returns the parsed card into `vcard' structure.  The caller must
 *    pre-allocate the structure.  Returns TRUE if the `vcard' is valid
 *    vcard and was successfully parsed or FALSE on error.  The structure
 *    is freed with silc_vcard_free function when it is not needed anymore.
 *
 ***/
SilcBool silc_vcard_decode(const unsigned char *data, SilcUInt32 data_len,
			   SilcVCard vcard);

/****f* silcvcard/SilcVCard/silc_vcard_alloc
 *
 * SYNOPSIS
 *
 *    SilcVCard silc_vcard_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocate a SilcVCard context which must be freed with the
 *    silc_vcard_free function.
 *
 ***/
SilcVCard silc_vcard_alloc(void);

/****f* silcvcard/SilcVCard/silc_vcard_free
 *
 * SYNOPSIS
 *
 *    void silc_vcard_free(SilcVCard vcard);
 *
 * DESCRIPTION
 *
 *    Free VCard structure and all data in it.
 *
 ***/
void silc_vcard_free(SilcVCard vcard);

/****f* silcvcard/SilcVCard/silc_vcard_fprintf
 *
 * SYNOPSIS
 *
 *    void silc_vcard_fprintf(SilcVCard vcard, FILE *stream);
 *
 * DESCRIPTION
 *
 *    Prints the contents of the `vcard' into file stream `stream' in
 *    the correct VCard format.
 *
 ***/
void silc_vcard_fprintf(SilcVCard vcard, FILE *stream);

#endif /* SILCVCARD_H */
