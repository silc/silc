/*

  silcvcard.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/* Implementation of the VCard (RFC 2426) */

#include "silcincludes.h"

#define VCARD_HEADER "BEGIN:VCARD\n"
#define VCARD_VERSION "VERSION:3.0\n"
#define VCARD_FOOTER "END:VCARD\n"

/* Encode VCard */

unsigned char *silc_vcard_encode(SilcVCard vcard, SilcUInt32 *vcard_len)
{
  SilcBufferStruct buffer;
  int i;

  if (!vcard->full_name || !vcard->family_name || !vcard->first_name)
    return NULL;

  memset(&buffer, 0, sizeof(buffer));
  silc_buffer_strformat(
       &buffer,
       VCARD_HEADER,
       VCARD_VERSION,
       "FN:", vcard->full_name, "\n",
       "N:", vcard->family_name, ";", vcard->first_name, ";",
       vcard->middle_names, ";", vcard->prefix, ";", vcard->suffix, "\n",
       SILC_STR_END);

  if (vcard->nickname)
    silc_buffer_strformat(&buffer,
			  "NICKNAME:", vcard->nickname, "\n",
			  SILC_STR_END);
  if (vcard->bday)
    silc_buffer_strformat(&buffer,
			  "BDAY:", vcard->bday, "\n",
			  SILC_STR_END);
  if (vcard->title)
    silc_buffer_strformat(&buffer,
			  "TITLE:", vcard->title, "\n",
			  SILC_STR_END);
  if (vcard->role)
    silc_buffer_strformat(&buffer,
			  "ROLE:", vcard->role, "\n",
			  SILC_STR_END);
  if (vcard->org_name)
    silc_buffer_strformat(&buffer,
			  "ORG:", vcard->org_name, ";", vcard->org_unit, "\n",
			  SILC_STR_END);
  if (vcard->categories)
    silc_buffer_strformat(&buffer,
			  "CATEGORIES:", vcard->categories, "\n",
			  SILC_STR_END);
  if (vcard->catclass)
    silc_buffer_strformat(&buffer,
			  "CLASS:", vcard->catclass, "\n",
			  SILC_STR_END);
  if (vcard->url)
    silc_buffer_strformat(&buffer,
			  "URL:", vcard->url, "\n",
			  SILC_STR_END);
  if (vcard->label)
    silc_buffer_strformat(&buffer,
			  "LABEL;", vcard->url, "\n",
			  SILC_STR_END);
  for (i = 0; i < vcard->num_addrs; i++) {
    silc_buffer_strformat(&buffer,
			  "ADR;TYPE=",
			  vcard->addrs[i].type, ":",
			  vcard->addrs[i].pbox, ";",
			  vcard->addrs[i].ext_addr, ";",
			  vcard->addrs[i].street_addr, ";",
			  vcard->addrs[i].city, ";",
			  vcard->addrs[i].state, ";",
			  vcard->addrs[i].code, ";",
			  vcard->addrs[i].country, "\n",
			  SILC_STR_END);
  }
  for (i = 0; i < vcard->num_tels; i++) {
    silc_buffer_strformat(&buffer,
			  "TEL;TYPE=",
			  vcard->tels[i].type, ":",
			  vcard->tels[i].telnum, "\n",
			  SILC_STR_END);
  }
  for (i = 0; i < vcard->num_emails; i++) {
    silc_buffer_strformat(&buffer,
			  "EMAIL;TYPE=",
			  vcard->emails[i].type, ":",
			  vcard->emails[i].address, "\n",
			  SILC_STR_END);
  }
  if (vcard->note)
    silc_buffer_strformat(&buffer,
			  "NOTE:", vcard->note, "\n",
			  SILC_STR_END);
  if (vcard->rev)
    silc_buffer_strformat(&buffer,
			  "REV:", vcard->rev, "\n",
			  SILC_STR_END);

  silc_buffer_strformat(&buffer, VCARD_FOOTER, SILC_STR_END);

  if (vcard_len)
    *vcard_len = buffer.truelen;

  return buffer.head;
}

/* Take one token */
#define VCARD_TOKEN(x)				\
  if (!(x)) {					\
    (x) = silc_memdup(val + off, i - off);	\
    off = i + 1;				\
    continue;					\
  }

/* Take on TYPE= token and prepare for next token, accept the
   type also without TYPE= as it is possible */
#define VCARD_TYPETOKEN(x)					\
  if (!(x)) {							\
    int tmpi = 0;						\
    if (!strncasecmp(val + off, "TYPE=", 5))			\
      tmpi = 5;							\
    (x) = silc_memdup(val + off + tmpi, i - off - tmpi - 1);	\
    tmpi = off + tmpi + strlen((x)) + 1;			\
    off = i;							\
    i = tmpi;							\
  }

/* Take last token */
#define VCARD_LASTTOKEN(x)			\
  if (!(x)) {					\
    if (off < len)				\
      (x) = silc_memdup(val + off, len - off);	\
  }						\

/* Get one (single) field */
#define VCARD_FIELD(val, c, x)				\
do {							\
  if (!strncasecmp(val, (c), strlen((c)))) {		\
    int tmpl = strlen((c));				\
    if ((x))						\
      break;						\
    if (len - tmpl > 0)					\
      (x) = silc_memdup(val + tmpl, len - tmpl);	\
    goto next;						\
  }							\
} while(0)

/* Decode VCard */

bool silc_vcard_decode(const unsigned char *data, SilcUInt32 data_len,
		       SilcVCard vcard)
{
  unsigned char *val;
  bool has_begin = FALSE, has_end = FALSE;
  int len, i, off = 0;
  
  val = (unsigned char *)data;
  while (val) {
    len = 0;
    for (i = (val - data); i < data_len; i++) {
      if (data[i] == '\0' || data[i] == '\n') {
	len = i - (val - data);
	break;
      }
    }
    if (!len || len > data_len - (val - data))
      break;

    /* Check for mandatory header and footer */
    if (!strncasecmp(val, VCARD_HEADER, strlen(VCARD_HEADER))) {
      has_begin = TRUE;
      goto next;
    }
    if (!strncasecmp(val, VCARD_FOOTER, strlen(VCARD_FOOTER))) {
      has_end = TRUE;
      goto next;
    }

    /* Get single fields */
    VCARD_FIELD(val, "FN:", vcard->full_name);
    VCARD_FIELD(val, "NICKNAME:", vcard->nickname);
    VCARD_FIELD(val, "BDAY:", vcard->bday);
    VCARD_FIELD(val, "TITLE:", vcard->title);
    VCARD_FIELD(val, "ROLE:", vcard->role);
    VCARD_FIELD(val, "CATEGORIES:", vcard->categories);
    VCARD_FIELD(val, "CLASS:", vcard->catclass);
    VCARD_FIELD(val, "URL:", vcard->url);
    VCARD_FIELD(val, "LABEL;", vcard->label);
    VCARD_FIELD(val, "NOTE:", vcard->note);
    VCARD_FIELD(val, "REV:", vcard->rev);

    /* Get multi-column fields */

    if (!strncasecmp(val, "N:", 2)) {
      if (vcard->family_name)
	break;
      if (len - 2) {
	off = 2;
	for (i = off; i < len; i++)
	  if (val[i] == ';') {
	    VCARD_TOKEN(vcard->family_name);
	    VCARD_TOKEN(vcard->first_name);
	    VCARD_TOKEN(vcard->middle_names);
	    VCARD_TOKEN(vcard->prefix);
	  }
	if (!vcard->family_name && !vcard->first_name) {
	  VCARD_LASTTOKEN(vcard->family_name);
	  off += (len - off);
	}
	if (!vcard->first_name) {
	  VCARD_LASTTOKEN(vcard->first_name);
	} else {
	  VCARD_LASTTOKEN(vcard->suffix);
	}
      }
      goto next;
    }

    if (!strncasecmp(val, "ORG:", 4)) {
      if (vcard->org_name)
	continue;
      if (len - 4) {
	off = 4;
	for (i = off; i < len; i++) {
	  if (val[i] == ';') {
	    VCARD_TOKEN(vcard->org_name);
	    break;
	  }
	}
	/* It's possible to have ORG without last ';', so check for it */
	if (!vcard->org_name) {
	  VCARD_LASTTOKEN(vcard->org_name);
	} else {
	  VCARD_LASTTOKEN(vcard->org_unit);
	}
      }
      goto next;
    }

    if (!strncasecmp(val, "ADR;", 4)) {
      vcard->addrs = silc_realloc(vcard->addrs, sizeof(*vcard->addrs) *
				  (vcard->num_addrs + 1));
      memset(&vcard->addrs[vcard->num_addrs], 0, sizeof(*vcard->addrs));
      if (len - 4) {
	off = 4;
	for (i = off; i < len; i++)
	  if (val[i] == ';') {
	    VCARD_TYPETOKEN(vcard->addrs[vcard->num_addrs].type);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].pbox);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].ext_addr);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].street_addr);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].city);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].state);
	    VCARD_TOKEN(vcard->addrs[vcard->num_addrs].code);
	  }
	VCARD_LASTTOKEN(vcard->addrs[vcard->num_addrs].country);
      }
      vcard->num_addrs++;
      goto next;
    }

    if (!strncasecmp(val, "TEL;", 4)) {
      vcard->tels = silc_realloc(vcard->tels, sizeof(*vcard->tels) *
				 (vcard->num_tels + 1));
      memset(&vcard->tels[vcard->num_tels], 0, sizeof(*vcard->tels));
      if (len - 4) {
	off = 4;
	for (i = off; i < len; i++)
	  if (val[i] == ':') {
	    i++;
	    VCARD_TYPETOKEN(vcard->tels[vcard->num_tels].type);
	    break;
	  }
	VCARD_LASTTOKEN(vcard->tels[vcard->num_tels].telnum);
      }
      vcard->num_tels++;
      goto next;
    }

    if (!strncasecmp(val, "EMAIL;", 6)) {
      vcard->emails = silc_realloc(vcard->emails, sizeof(*vcard->emails) *
				   (vcard->num_emails + 1));
      memset(&vcard->emails[vcard->num_emails], 0, sizeof(*vcard->emails));
      if (len - 6) {
	off = 6;
	for (i = off; i < len; i++)
	  if (val[i] == ':') {
	    i++;
	    VCARD_TYPETOKEN(vcard->emails[vcard->num_emails].type);
	    break;
	  }
	VCARD_LASTTOKEN(vcard->emails[vcard->num_emails].address);
      }
      vcard->num_emails++;
      goto next;
    }

  next:
    val = strchr(val, '\n');
    if (!val)
      break;
    val++;
    if (!val || !(*val))
      break;
  }

  if (!has_begin || !has_end || !vcard->full_name) {
    silc_vcard_free(vcard);
    return FALSE;
  }

  return TRUE;
}

/* Allocate vcard context */

SilcVCard silc_vcard_alloc(void)
{
  SilcVCard vcard = silc_calloc(1, sizeof(*vcard));
  if (!vcard)
    return NULL;
  vcard->dynamic = TRUE;
  return vcard;
}

/* Free the vcard structure */

void silc_vcard_free(SilcVCard vcard)
{
  int i;

  silc_free(vcard->full_name);
  silc_free(vcard->family_name);
  silc_free(vcard->first_name);
  silc_free(vcard->middle_names);
  silc_free(vcard->prefix);
  silc_free(vcard->suffix);
  silc_free(vcard->nickname);
  silc_free(vcard->bday);
  silc_free(vcard->title);
  silc_free(vcard->role);
  silc_free(vcard->org_name);
  silc_free(vcard->org_unit);
  silc_free(vcard->categories);
  silc_free(vcard->catclass);
  silc_free(vcard->url);
  silc_free(vcard->label);
  for (i = 0; i < vcard->num_addrs; i++) {
    silc_free(vcard->addrs[i].type);
    silc_free(vcard->addrs[i].pbox);
    silc_free(vcard->addrs[i].ext_addr);
    silc_free(vcard->addrs[i].street_addr);
    silc_free(vcard->addrs[i].city);
    silc_free(vcard->addrs[i].state);
    silc_free(vcard->addrs[i].code);
    silc_free(vcard->addrs[i].country);
  }
  silc_free(vcard->addrs);
  for (i = 0; i < vcard->num_tels; i++) {
    silc_free(vcard->tels[i].type);
    silc_free(vcard->tels[i].telnum);
  }
  silc_free(vcard->tels);
  for (i = 0; i < vcard->num_emails; i++) {
    silc_free(vcard->emails[i].type);
    silc_free(vcard->emails[i].address);
  }
  silc_free(vcard->emails);
  silc_free(vcard->note);
  silc_free(vcard->rev);
  if (!vcard->dynamic)
    memset(vcard, 0, sizeof(*vcard));

  if (vcard->dynamic) {
    memset(vcard, 0, sizeof(*vcard));
    silc_free(vcard);
  }
}

/* Print card to file stream */

void silc_vcard_fprintf(SilcVCard vcard, FILE *stream)
{
  int i;
  fprintf(stream, "%s", VCARD_HEADER);
  fprintf(stream, "%s", VCARD_VERSION);
  if (vcard->full_name)
    fprintf(stream, "FN:%s\n", vcard->full_name);
  if (vcard->family_name)
    fprintf(stream, "N:%s;%s;%s;%s;%s\n",
	    vcard->family_name,
	    vcard->first_name ? vcard->first_name : "",
	    vcard->middle_names ? vcard->middle_names : "",
	    vcard->prefix ? vcard->prefix : "",
	    vcard->suffix ? vcard->suffix : "");
  if (vcard->nickname)
    fprintf(stream, "NICKNAME:%s\n", vcard->nickname);
  if (vcard->bday)
    fprintf(stream, "BDAY:%s\n", vcard->bday);
  if (vcard->title)
    fprintf(stream, "TITLE:%s\n", vcard->title);
  if (vcard->role)
    fprintf(stream, "ROLE:%s\n", vcard->role);
  if (vcard->org_name)
    fprintf(stream, "ORG:%s;%s\n", vcard->org_name,
	    vcard->org_unit ? vcard->org_unit : "");
  if (vcard->categories)
    fprintf(stream, "CATEGORIES:%s\n", vcard->categories);
  if (vcard->catclass)
    fprintf(stream, "CLASS:%s\n", vcard->catclass);
  if (vcard->url)
    fprintf(stream, "URL:%s\n", vcard->url);
  if (vcard->label)
    fprintf(stream, "LABEL;%s\n", vcard->label);
  for (i = 0; i < vcard->num_addrs; i++) {
    fprintf(stream, "ADR;TYPE=%s:%s;%s;%s;%s;%s;%s;%s\n",
	    vcard->addrs[i].type,
	    vcard->addrs[i].pbox ? vcard->addrs[i].pbox : "",
	    vcard->addrs[i].ext_addr ? vcard->addrs[i].ext_addr : "",
	    vcard->addrs[i].street_addr ? vcard->addrs[i].street_addr : "",
	    vcard->addrs[i].city ? vcard->addrs[i].city : "",
	    vcard->addrs[i].state ? vcard->addrs[i].state : "",
	    vcard->addrs[i].code ? vcard->addrs[i].code : "",
	    vcard->addrs[i].country ? vcard->addrs[i].country : "");
  }
  for (i = 0; i < vcard->num_tels; i++) {
    fprintf(stream, "TEL;TYPE=%s:%s\n",
	    vcard->tels[i].type,
	    vcard->tels[i].telnum ? vcard->tels[i].telnum : "");
  }
  for (i = 0; i < vcard->num_emails; i++) {
    fprintf(stream, "EMAIL;TYPE=%s:%s\n",
	    vcard->emails[i].type,
	    vcard->emails[i].address ? vcard->emails[i].address : "");
  }
  if (vcard->note)
    fprintf(stream, "NOTE:%s\n", vcard->note);
  if (vcard->rev)
    fprintf(stream, "REV:%s\n", vcard->rev);
  fprintf(stream, "%s", VCARD_FOOTER);
  fflush(stream);
}
