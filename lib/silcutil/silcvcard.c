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
#define VCARD_FOOTER "END:VCARD"

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
  if (vcard->class)
    silc_buffer_strformat(&buffer,
			  "CLASS:", vcard->class, "\n",
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
			  vcard->tels[i].tel, "\n",
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

/* Take on TYPE= token and prepare for next token */
#define VCARD_TYPETOKEN(x)				\
  if (!(x)) {						\
    int tmpi;						\
    (x) = silc_memdup(val + off + 5, i - off - 5 - 1);	\
    tmpi = off + 5 + strlen((x)) + 1;			\
    off = i;						\
    i = tmpi;						\
  }

/* Take last token */
#define VCARD_LASTTOKEN(x)			\
  if (!(x)) {					\
    if (off < len)				\
      (x) = silc_memdup(val + off, len - off);	\
  }						\

/* Decode VCard */

bool silc_vcard_decode(const unsigned char *data, SilcUInt32 data_len,
		       SilcVCard vcard)
{
  unsigned char *val;
  bool has_begin = FALSE, has_end = FALSE;
  int len, i, off = 0;
  
  val = (unsigned char *)data;
  while (val) {
    if (!strchr(val, '\n'))
      break;
    len = strchr(val, '\n') - (char *)val;
    if (len > data_len - (val - data))
      break;

    if (!strncasecmp(val, VCARD_HEADER, strlen(VCARD_HEADER))) {
      has_begin = TRUE;
    } else if (!strncasecmp(val, "FN:", 3)) {
      if (vcard->full_name)
	break;
      if (len - 3)
	vcard->full_name = silc_memdup(val + 3, len - 3);
    } else if (!strncasecmp(val, "N:", 2)) {
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
	VCARD_LASTTOKEN(vcard->suffix);
      }
    } else if (!strncasecmp(val, "NICKNAME:", 9)) {
      if (vcard->nickname)
	continue;
      if (len - 9)
	vcard->nickname = silc_memdup(val + 9, len - 9);
    } else if (!strncasecmp(val, "BDAY:", 5)) {
      if (vcard->bday)
	continue;
      if (len - 5)
	vcard->bday = silc_memdup(val + 5, len - 5);
    } else if (!strncasecmp(val, "TITLE:", 6)) {
      if (vcard->title)
	continue;
      if (len - 6)
	vcard->title = silc_memdup(val + 6, len - 6);
    } else if (!strncasecmp(val, "ROLE:", 5)) {
      if (vcard->role)
	continue;
      if (len - 5)
	vcard->role = silc_memdup(val + 5, len - 5);
    } else if (!strncasecmp(val, "ORG:", 4)) {
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
    } else if (!strncasecmp(val, "CATEGORIES:", 11)) {
      if (vcard->categories)
	continue;
      if (len - 11)
	vcard->categories = silc_memdup(val + 11, len - 11);
    } else if (!strncasecmp(val, "CLASS:", 6)) {
      if (vcard->class)
	continue;
      if (len - 6)
	vcard->class = silc_memdup(val + 6, len - 6);
    } else if (!strncasecmp(val, "URL:", 4)) {
      if (vcard->url)
	continue;
      if (len - 4)
	vcard->url = silc_memdup(val + 4, len - 4);
    } else if (!strncasecmp(val, "LABEL;", 6)) {
      if (vcard->label)
	continue;
      if (len - 6)
	vcard->label = silc_memdup(val + 6, len - 6);
    } else if (!strncasecmp(val, "ADR;", 4)) {
      vcard->addrs = silc_realloc(vcard->addrs, sizeof(*vcard->addrs) *
				  (vcard->num_addrs + 1));
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
    } else if (!strncasecmp(val, "TEL;", 4)) {
      vcard->tels = silc_realloc(vcard->tels, sizeof(*vcard->tels) *
				 (vcard->num_tels + 1));
      if (len - 4) {
	off = 4;
	for (i = off; i < len; i++)
	  if (val[i] == ':') {
	    i++;
	    VCARD_TYPETOKEN(vcard->tels[vcard->num_tels].type);
	    break;
	  }
	VCARD_LASTTOKEN(vcard->tels[vcard->num_tels].tel);
      }
      vcard->num_tels++;
    } else if (!strncasecmp(val, "EMAIL;", 6)) {
      vcard->emails = silc_realloc(vcard->emails, sizeof(*vcard->emails) *
				   (vcard->num_emails + 1));
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
    } else if (!strncasecmp(val, "NOTE:", 5)) {
      if (vcard->note)
	continue;
      if (len - 5)
	vcard->note = silc_memdup(val + 5, len - 5);
    } else if (!strncasecmp(val, "REV:", 4)) {
      if (vcard->rev)
	continue;
      if (len - 4)
	vcard->rev = silc_memdup(val + 4, len - 4);
    } else if (!strncasecmp(val, VCARD_FOOTER, strlen(VCARD_FOOTER))) {
      has_end = TRUE;
      break;
    }

    val = strchr(val, '\n');
    if (!val || !(*val))
      break;
    val++;
    if (!val || !(*val))
      break;
  }

  if (!has_begin || !has_end) {
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
  silc_free(vcard->class);
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
    silc_free(vcard->tels[i].tel);
  }
  silc_free(vcard->tels);
  for (i = 0; i < vcard->num_emails; i++) {
    silc_free(vcard->emails[i].type);
    silc_free(vcard->emails[i].address);
  }
  silc_free(vcard->emails);
  silc_free(vcard->note);
  silc_free(vcard->rev);

  if (vcard->dynamic) {
    memset(vcard, 'F', sizeof(*vcard));
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
  if (vcard->class)
    fprintf(stream, "CLASS:%s\n", vcard->class);
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
	    vcard->tels[i].tel ? vcard->tels[i].tel : "");
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
