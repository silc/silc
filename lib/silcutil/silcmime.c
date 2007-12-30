/*

  silcmime.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/************************** Types and definitions ***************************/

/* MIME fragment ID context */
typedef struct {
  char *id;
  SilcInt64 starttime;
} SilcMimeFragmentIdStruct, *SilcMimeFragmentId;

/************************ Static utility functions **************************/

/* MIME fields destructor */

static void silc_mime_field_dest(void *key, void *context, void *user_context)
{
  silc_free(key);
  silc_free(context);
}

/* Assembler fragment destructor */

static void silc_mime_assembler_dest(void *key, void *context,
				     void *user_context)
{
  SilcMimeFragmentId id = key;

  silc_free(id->id);
  silc_free(id);

  /* Free all fragments */
  silc_hash_table_free(context);
}

/* Assembler partial MIME fragmentn destructor */

static void silc_mime_assemble_dest(void *key, void *context,
				    void *user_context)
{
  silc_mime_free(context);
}

/* MIME fragment ID hashing */

static SilcUInt32 silc_mime_hash_id(void *key, void *user_context)
{
  SilcMimeFragmentId id = key;
  return silc_hash_string_case(id->id, user_context);
}

/* MIME fragment ID comparing */

static SilcBool silc_mime_id_compare(void *key1, void *key2,
				     void *user_context)
{
  SilcMimeFragmentId id1 = key1, id2 = key2;
  return silc_hash_string_case_compare(id1->id, id2->id, user_context);
}


/******************************* Public API *********************************/

/* Allocate MIME context */

SilcMime silc_mime_alloc(void)
{
  SilcMime mime;

  mime = silc_calloc(1, sizeof(*mime));
  if (!mime)
    return NULL;

  mime->fields = silc_hash_table_alloc(NULL, 0, silc_hash_string_case, mime,
				       silc_hash_string_case_compare, mime,
				       silc_mime_field_dest, mime, TRUE);
  if (!mime->fields) {
    silc_mime_free(mime);
    return NULL;
  }

  return mime;
}

/* Free MIME context */

void silc_mime_free(SilcMime mime)
{
  SilcMime m;

  if (mime->fields)
    silc_hash_table_free(mime->fields);

  if (mime->multiparts) {
    silc_dlist_start(mime->multiparts);
    while ((m = silc_dlist_get(mime->multiparts)) != SILC_LIST_END)
      silc_mime_free(m);
    silc_dlist_uninit(mime->multiparts);
  }
  silc_free(mime->boundary);
  silc_free(mime->multitype);
  silc_free(mime->data);
  silc_free(mime);
}

/* Allocate MIME assembler */

SilcMimeAssembler silc_mime_assembler_alloc(void)
{
  SilcMimeAssembler assembler;

  assembler = silc_calloc(1, sizeof(*assembler));
  if (!assembler)
    return NULL;

  assembler->fragments =
    silc_hash_table_alloc(NULL, 0, silc_mime_hash_id, NULL,
			  silc_mime_id_compare, NULL,
			  silc_mime_assembler_dest, assembler, TRUE);
  if (!assembler->fragments) {
    silc_mime_assembler_free(assembler);
    return NULL;
  }

  return assembler;
}

/* Free MIME assembler */

void silc_mime_assembler_free(SilcMimeAssembler assembler)
{
  silc_hash_table_free(assembler->fragments);
  silc_free(assembler);
}

/* Purge assembler from old unfinished fragments */

void silc_mime_assembler_purge(SilcMimeAssembler assembler,
			       SilcUInt32 purge_minutes)
{
  SilcMimeFragmentId id;
  SilcHashTableList htl;
  SilcInt64 curtime = silc_time();
  SilcUInt32 timeout = purge_minutes ? purge_minutes * 60 : 5 * 60;

  SILC_LOG_DEBUG(("Purge MIME assembler"));

  silc_hash_table_list(assembler->fragments, &htl);
  while (silc_hash_table_get(&htl, (void *)&id, NULL)) {
    if (curtime - id->starttime <= timeout)
      continue;

    SILC_LOG_DEBUG(("Purge partial MIME id %s", id->id));

    /* Purge */
    silc_hash_table_del(assembler->fragments, id);
  }
  silc_hash_table_list_reset(&htl);
}

/* Decode MIME message */

SilcMime silc_mime_decode(SilcMime mime, const unsigned char *data,
			  SilcUInt32 data_len)
{
  SilcMime m = NULL;
  int i, k;
  char *tmp, *field, *value, *line;

  SILC_LOG_DEBUG(("Parsing MIME message"));

  if (!data) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  if (!mime) {
    mime = silc_mime_alloc();
    if (!mime)
      return NULL;
    m = mime;
  }

  /* Parse the fields */
  line = tmp = (char *)data;
  for (i = 0; i < data_len; i++) {
    /* Get field line */
    if (data_len - i >= 2 && tmp[i] == '\r' && tmp[i + 1] == '\n') {
      /* Get field */
      field = strchr(line, ':');
      if (!field) {
	silc_set_errno(SILC_ERR_BAD_ENCODING);
	goto err;
      }
      field = silc_memdup(line, field - line);
      if (!field)
	goto err;

      /* Get value. Remove whitespaces too. */
      value = strchr(line, ':');
      if ((tmp + i) - value < 2) {
	silc_set_errno(SILC_ERR_OVERFLOW);
	goto err;
      }
      value++;
      for (k = 0; k < (tmp + i) - value; k++) {
	if (value[k] == '\r') {
	  silc_set_errno(SILC_ERR_BAD_ENCODING);
	  goto err;
        }
	if (value[k] != ' ' && value[k] != '\t')
	  break;
      }
      value += k;
      if ((tmp + i) - value < 1) {
	silc_set_errno(SILC_ERR_OVERFLOW);
	goto err;
      }
      value = silc_memdup(value, (tmp + i) - value);
      if (!value)
	goto err;

      SILC_LOG_DEBUG(("Header '%s' '%s'", field, value));

      /* Add field and value */
      silc_mime_add_field(mime, field, value);
      silc_free(field);
      silc_free(value);

      /* Mark start of next line */
      line = (tmp + i) + 2;
      i += 2;

      /* Break if this is last header */
      if (data_len - i >= 2 &&
	  tmp[i] == '\r' && tmp[i + 1] == '\n') {
	i += 2;
	break;
      }
    }
  }

  /* Parse multiparts if present */
  field = (char *)silc_mime_get_field(mime, "Content-Type");
  if (field && strstr(field, "multipart")) {
    char b[1024];
    SilcMime p;
    unsigned int len;

    mime->multiparts = silc_dlist_init();
    if (!mime->multiparts)
      goto err;

    /* Get multipart type */
    value = strchr(field, '/');
    if (!value) {
      silc_set_errno(SILC_ERR_BAD_ENCODING);
      goto err;
    }
    value++;
    if (strchr(field, '"'))
      value++;
    if (!strchr(field, ';')) {
      silc_set_errno(SILC_ERR_BAD_ENCODING);
      goto err;
    }
    memset(b, 0, sizeof(b));
    len = (unsigned int)(strchr(field, ';') - value);
    if (len > sizeof(b) - 1) {
      silc_set_errno(SILC_ERR_OVERFLOW);
      goto err;
    }
    strncpy(b, value, len);
    if (strchr(b, '"'))
      *strchr(b, '"') = '\0';
    mime->multitype = silc_memdup(b, strlen(b));

    /* Get boundary */
    value = strrchr(field, '=');
    if (value && strlen(value) > 1) {
      value++;

      SILC_LOG_DEBUG(("Boundary '%s'", value));

      memset(b, 0, sizeof(b));
      line = silc_strdup(value);
      if (strrchr(line, '"')) {
	*strrchr(line, '"') = '\0';
	silc_snprintf(b, sizeof(b) - 1, "--%s", line + 1);
	mime->boundary = silc_strdup(line + 1);
      } else {
	silc_snprintf(b, sizeof(b) - 1, "--%s", line);
	mime->boundary = silc_strdup(line);
      }
      silc_free(line);

      for (i = i; i < data_len; i++) {
	/* Get boundary data */
	if (data_len - i >= strlen(b) &&
	    tmp[i] == '-' && tmp[i + 1] == '-') {
	  if (memcmp(tmp + i, b, strlen(b)))
	    continue;

	  i += strlen(b);

	  if (data_len - i >= 4 &&
	      tmp[i    ] == '\r' && tmp[i + 1] == '\n' &&
	      tmp[i + 2] == '\r' && tmp[i + 3] == '\n')
	    i += 4;
	  else if (data_len - i >= 2 &&
		   tmp[i] == '\r' && tmp[i + 1] == '\n')
	    i += 2;
	  else if (data_len - i >= 2 &&
		   tmp[i] == '-' && tmp[i + 1] == '-')
	    break;

	  line = tmp + i;

	  /* Find end of boundary */
	  for (k = i; k < data_len; k++)
	    if (data_len - k >= strlen(b) &&
		tmp[k] == '-' && tmp[k + 1] == '-')
	      if (!memcmp(tmp + k, b, strlen(b)))
		break;
	  if (k >= data_len) {
	    silc_set_errno(SILC_ERR_OVERFLOW);
	    goto err;
	  }

	  /* Remove preceding CRLF */
	  k -= 2;

	  /* Parse the part */
	  p = silc_mime_decode(NULL, line, k - i);
	  if (!p)
	    goto err;

	  silc_dlist_add(mime->multiparts, p);
	  i += (k - i);
	}
      }
    }
  } else {
    /* Get data area.  If we are at the end and we have fields present
       there is no data area present, but, if fields are not present we
       only have data area. */
    if (i >= data_len && !silc_hash_table_count(mime->fields))
      i = 0;
    SILC_LOG_DEBUG(("Data len %d", data_len - i));
    if (data_len - i)
      silc_mime_add_data(mime, tmp + i, data_len - i);
  }

  return mime;

 err:
  if (m)
    silc_mime_free(m);
  return NULL;
}

/* Encode MIME message */

unsigned char *silc_mime_encode(SilcMime mime, SilcUInt32 *encoded_len)
{
  SilcMime part;
  SilcHashTableList htl;
  SilcBufferStruct buf;
  SilcBuffer buffer;
  char *field, *value, tmp[1024], tmp2[4];
  unsigned char *ret;
  int i;

  SILC_LOG_DEBUG(("Encoding MIME message"));

  if (!mime)
    return NULL;

  memset(&buf, 0, sizeof(buf));

  /* Encode the headers. Order doesn't matter */
  i = 0;
  silc_hash_table_list(mime->fields, &htl);
  while (silc_hash_table_get(&htl, (void *)&field, (void *)&value)) {
    memset(tmp, 0, sizeof(tmp));
    SILC_LOG_DEBUG(("Header %s: %s", field, value));
    silc_snprintf(tmp, sizeof(tmp) - 1, "%s: %s\r\n", field, value);
    silc_buffer_strformat(&buf, tmp, SILC_STRFMT_END);
    i++;
  }
  silc_hash_table_list_reset(&htl);
  if (i)
    silc_buffer_strformat(&buf, "\r\n", SILC_STRFMT_END);

  /* Assemble the whole buffer */
  buffer = silc_buffer_alloc_size(mime->data_len + silc_buffer_len(&buf));
  if (!buffer)
    return NULL;

  /* Add headers */
  if (silc_buffer_len(&buf)) {
    silc_buffer_put(buffer, buf.head, silc_buffer_len(&buf));
    silc_buffer_pull(buffer, silc_buffer_len(&buf));
    silc_buffer_purge(&buf);
  }

  /* Add data */
  if (mime->data) {
    SILC_LOG_DEBUG(("Data len %d", mime->data_len));
    silc_buffer_put(buffer, mime->data, mime->data_len);
  }

  /* Add multiparts */
  if (mime->multiparts) {
    SILC_LOG_DEBUG(("Encoding multiparts"));

    silc_dlist_start(mime->multiparts);
    i = 0;
    while ((part = silc_dlist_get(mime->multiparts)) != SILC_LIST_END) {
      unsigned char *pd;
      SilcUInt32 pd_len;

      /* Recursive encoding */
      pd = silc_mime_encode(part, &pd_len);
      if (!pd)
	return NULL;

      memset(tmp, 0, sizeof(tmp));
      memset(tmp2, 0, sizeof(tmp2));

      /* If fields are not present, add extra CRLF */
      if (!silc_hash_table_count(part->fields))
	silc_snprintf(tmp2, sizeof(tmp2) - 1, "\r\n");
      silc_snprintf(tmp, sizeof(tmp) - 1, "%s--%s\r\n%s",
	       i != 0 ? "\r\n" : "", mime->boundary, tmp2);
      i = 1;

      buffer = silc_buffer_realloc(buffer, silc_buffer_truelen(buffer) +
				   pd_len + strlen(tmp));
      if (!buffer)
	return NULL;
      silc_buffer_put_tail(buffer, tmp, strlen(tmp));
      silc_buffer_pull_tail(buffer, strlen(tmp));
      silc_buffer_put_tail(buffer, pd, pd_len);
      silc_buffer_pull_tail(buffer, pd_len);
      silc_free(pd);
    }

    memset(tmp, 0, sizeof(tmp));
    silc_snprintf(tmp, sizeof(tmp) - 1, "\r\n--%s--\r\n", mime->boundary);
    buffer = silc_buffer_realloc(buffer, silc_buffer_truelen(buffer) +
				 strlen(tmp));
    if (!buffer)
      return NULL;
    silc_buffer_put_tail(buffer, tmp, strlen(tmp));
    silc_buffer_pull_tail(buffer, strlen(tmp));
  }

  ret = silc_buffer_steal(buffer, encoded_len);
  silc_buffer_free(buffer);

  return ret;
}

/* Assembles MIME message from partial MIME messages */

SilcMime silc_mime_assemble(SilcMimeAssembler assembler, SilcMime partial)
{
  char *type, *id = NULL, *tmp;
  SilcMimeFragmentIdStruct *fragid, query;
  SilcHashTable f;
  SilcMime p, complete;
  int i, number, total = -1;
  const unsigned char *data;
  SilcUInt32 data_len;
  SilcBuffer compbuf = NULL;

  SILC_LOG_DEBUG(("Assembling MIME fragments"));

  if (!assembler || !partial) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    goto err;
  }

  type = (char *)silc_mime_get_field(partial, "Content-Type");
  if (!type) {
    silc_set_errno(SILC_ERR_BAD_ENCODING);
    goto err;
  }

  /* Get ID */
  tmp = strstr(type, "id=");
  if (!tmp) {
    silc_set_errno(SILC_ERR_BAD_ENCODING);
    goto err;
  }
  if (strlen(tmp) <= 4) {
    silc_set_errno(SILC_ERR_OVERFLOW);
    goto err;
  }
  tmp += 3;
  if (*tmp == '"')
    tmp++;
  id = silc_strdup(tmp);
  if (strchr(id, ';'))
    *strchr(id, ';') = '\0';
  if (strrchr(id, '"'))
    *strrchr(id, '"') = '\0';

  SILC_LOG_DEBUG(("Fragment ID %s", id));

  /* Get fragment number */
  tmp = strstr(type, "number=");
  if (!tmp) {
    silc_set_errno(SILC_ERR_BAD_ENCODING);
    goto err;
  }
  tmp = strchr(tmp, '=');
  if (strlen(tmp) < 2) {
    silc_set_errno(SILC_ERR_OVERFLOW);
    goto err;
  }
  tmp++;
  if (strchr(tmp, ';')) {
    tmp = silc_strdup(tmp);
    *strchr(tmp, ';') = '\0';
    number = atoi(tmp);
    silc_free(tmp);
  } else {
    number = atoi(tmp);
  }

  SILC_LOG_DEBUG(("Fragment number %d", number));

  /* Find fragments with this ID. */
  query.id = id;
  if (!silc_hash_table_find(assembler->fragments, (void *)&query,
			    NULL, (void *)&f)) {
    /* This is new fragment to new message.  Add to hash table and return. */
    f = silc_hash_table_alloc(NULL, 0, silc_hash_uint, NULL, NULL, NULL,
			      silc_mime_assemble_dest, NULL, TRUE);
    if (!f)
      goto err;

    fragid = silc_calloc(1, sizeof(*fragid));
    if (!fragid)
      goto err;
    fragid->id = id;
    fragid->starttime = silc_time();

    silc_hash_table_add(f, SILC_32_TO_PTR(number), partial);
    silc_hash_table_add(assembler->fragments, fragid, f);
    return NULL;
  }

  /* Try to get total number */
  tmp = strstr(type, "total=");
  if (tmp) {
    tmp = strchr(tmp, '=');
    if (strlen(tmp) < 2) {
      silc_set_errno(SILC_ERR_OVERFLOW);
      goto err;
    }
    tmp++;
    if (strchr(tmp, ';')) {
      tmp = silc_strdup(tmp);
      *strchr(tmp, ';') = '\0';
      total = atoi(tmp);
      silc_free(tmp);
    } else {
      total = atoi(tmp);
    }

    SILC_LOG_DEBUG(("Fragment total %d", total));
  }

  /* If more fragments to come, add to hash table */
  if (number != total) {
    silc_hash_table_add(f, SILC_32_TO_PTR(number), partial);
    silc_free(id);
    return NULL;
  }

  silc_hash_table_add(f, SILC_32_TO_PTR(number), partial);

  /* Verify that we really have all the fragments */
  if (silc_hash_table_count(f) < total) {
    silc_free(id);
    return NULL;
  }

  /* Assemble the complete MIME message now. We get them in order from
     the hash table. */
  for (i = 1; i <= total; i++) {
    if (!silc_hash_table_find(f, SILC_32_TO_PTR(i), NULL, (void *)&p))
      goto err;

    /* The fragment is in the data portion of the partial message */
    data = silc_mime_get_data(p, &data_len);
    if (!data) {
      silc_set_errno(SILC_ERR_BAD_ENCODING);
      goto err;
    }

    /* Assemble */
    if (!compbuf) {
      compbuf = silc_buffer_alloc_size(data_len);
      if (!compbuf)
	goto err;
      silc_buffer_put(compbuf, data, data_len);
    } else {
      compbuf = silc_buffer_realloc(compbuf, silc_buffer_truelen(compbuf) +
				    data_len);
      if (!compbuf)
	goto err;
      silc_buffer_put_tail(compbuf, data, data_len);
      silc_buffer_pull_tail(compbuf, data_len);
    }
  }

  /* Now parse the complete MIME message and deliver it */
  complete = silc_mime_decode(NULL, (const unsigned char *)compbuf->head,
			      silc_buffer_truelen(compbuf));
  if (!complete)
    goto err;

  /* Delete the hash table entry. Destructors will free memory */
  silc_hash_table_del(assembler->fragments, (void *)&query);
  silc_free(id);
  silc_buffer_free(compbuf);

  return complete;

 err:
  silc_free(id);
  if (compbuf)
    silc_buffer_free(compbuf);
  silc_mime_free(partial);
  return NULL;
}

/* Encodes partial MIME messages */

SilcDList silc_mime_encode_partial(SilcMime mime, int max_size)
{
  unsigned char *buf, *tmp;
  SilcUInt32 buf_len, len, tmp_len, off;
  SilcDList list;
  SilcBuffer buffer;
  SilcMime partial;
  char type[128], id[64];
  int num;

  SILC_LOG_DEBUG(("Fragmenting MIME message"));

  /* Encode as normal */
  buf = silc_mime_encode(mime, &buf_len);
  if (!buf)
    return NULL;

  list = silc_dlist_init();

  /* Fragment if it is too large */
  if (buf_len > max_size) {
    memset(id, 0, sizeof(id));
    memset(type, 0, sizeof(type));
    gethostname(type, sizeof(type) - 1);
    srand((time(NULL) + buf_len) ^ rand());
    silc_snprintf(id, sizeof(id) - 1, "%X%X%X%s",
	     (unsigned int)rand(), (unsigned int)time(NULL),
	     (unsigned int)buf_len, type);

    SILC_LOG_DEBUG(("Fragment ID %s", id));

    partial = silc_mime_alloc();
    if (!partial)
      return NULL;

    silc_mime_add_field(partial, "MIME-Version", "1.0");
    memset(type, 0, sizeof(type));
    silc_snprintf(type, sizeof(type) - 1,
	     "message/partial; id=\"%s\"; number=1", id);
    silc_mime_add_field(partial, "Content-Type", type);
    silc_mime_add_data(partial, buf, max_size);

    tmp = silc_mime_encode(partial, &tmp_len);
    if (!tmp)
      return NULL;
    silc_mime_free(partial);

    /* Add to list */
    buffer = silc_buffer_alloc_size(tmp_len);
    if (!buffer)
      return NULL;
    silc_buffer_put(buffer, tmp, tmp_len);
    silc_dlist_add(list, buffer);
    silc_free(tmp);

    len = buf_len - max_size;
    off = max_size;
    num = 2;
    while (len > 0) {
      partial = silc_mime_alloc();
      if (!partial)
	return NULL;

      memset(type, 0, sizeof(type));
      silc_mime_add_field(partial, "MIME-Version", "1.0");

      if (len > max_size) {
	silc_snprintf(type, sizeof(type) - 1,
		 "message/partial; id=\"%s\"; number=%d",
		 id, num++);
	silc_mime_add_data(partial, buf + off, max_size);
	off += max_size;
	len -= max_size;
      } else {
	silc_snprintf(type, sizeof(type) - 1,
		 "message/partial; id=\"%s\"; number=%d; total=%d",
		 id, num, num);
	silc_mime_add_data(partial, buf + off, len);
	len = 0;
      }

      silc_mime_add_field(partial, "Content-Type", type);

      tmp = silc_mime_encode(partial, &tmp_len);
      if (!tmp)
	return NULL;
      silc_mime_free(partial);

      /* Add to list */
      buffer = silc_buffer_alloc_size(tmp_len);
      if (!buffer)
	return NULL;
      silc_buffer_put(buffer, tmp, tmp_len);
      silc_dlist_add(list, buffer);
      silc_free(tmp);
    }
  } else {
    /* No need to fragment */
    buffer = silc_buffer_alloc_size(buf_len);
    if (!buffer)
      return NULL;
    silc_buffer_put(buffer, buf, buf_len);
    silc_dlist_add(list, buffer);
  }

  silc_free(buf);

  return list;
}

/* Free partial MIME list */

void silc_mime_partial_free(SilcDList partials)
{
  SilcBuffer buf;

  if (!partials)
    return;

  silc_dlist_start(partials);
  while ((buf = silc_dlist_get(partials)) != SILC_LIST_END)
    silc_buffer_free(buf);
  silc_dlist_uninit(partials);
}

/* Add field */

void silc_mime_add_field(SilcMime mime, const char *field, const char *value)
{
  if (!mime || !field || !value)
    return;

  silc_hash_table_add(mime->fields, silc_strdup(field), silc_strdup(value));
}

/* Get field */

const char *silc_mime_get_field(SilcMime mime, const char *field)
{
  char *value;

  if (!mime || !field)
    return NULL;

  if (!silc_hash_table_find(mime->fields, (void *)field,
			    NULL, (void *)&value))
    return NULL;

  return (const char *)value;
}

/* Add data */

void silc_mime_add_data(SilcMime mime, const unsigned char *data,
			SilcUInt32 data_len)
{
  if (!mime || !data)
    return;

  if (mime->data)
    silc_free(mime->data);

  mime->data = silc_memdup(data, data_len);
  mime->data_len = data_len;
}

/* Get data */

const unsigned char *silc_mime_get_data(SilcMime mime, SilcUInt32 *data_len)
{
  if (!mime)
    return NULL;

  if (data_len)
    *data_len = mime->data_len;

  return mime->data;
}

/* Steal data */

unsigned char *silc_mime_steal_data(SilcMime mime, SilcUInt32 *data_len)
{
  unsigned char *data;

  if (!mime)
    return NULL;

  if (data_len)
    *data_len = mime->data_len;

  data = mime->data;

  mime->data = NULL;
  mime->data_len = 0;

  return data;
}

/* Returns TRUE if partial message */

SilcBool silc_mime_is_partial(SilcMime mime)
{
  const char *type = silc_mime_get_field(mime, "Content-Type");
  if (!type)
    return FALSE;

  if (!strstr(type, "message/partial"))
    return FALSE;

  return TRUE;
}

/* Set as multipart message */

void silc_mime_set_multipart(SilcMime mime, const char *type,
			     const char *boundary)
{
  char tmp[1024];

  if (!mime || !type || !boundary)
    return;

  memset(tmp, 0, sizeof(tmp));
  silc_snprintf(tmp, sizeof(tmp) - 1, "multipart/%s; boundary=%s", type, boundary);
  silc_mime_add_field(mime, "Content-Type", tmp);
  silc_free(mime->boundary);
  mime->boundary = silc_strdup(boundary);

  if (mime->multiparts)
    return;
  mime->multiparts = silc_dlist_init();
}

/* Add multipart */

SilcBool silc_mime_add_multipart(SilcMime mime, SilcMime part)
{
  if (!mime || !mime->multiparts || !part) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return FALSE;
  }

  silc_dlist_add(mime->multiparts, part);
  return TRUE;
}

/* Return TRUE if has multiparts */

SilcBool silc_mime_is_multipart(SilcMime mime)
{
  if (!mime) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return FALSE;
  }

  return mime->multiparts != NULL;
}

/* Returns multiparts */

SilcDList silc_mime_get_multiparts(SilcMime mime, const char **type)
{
  if (!mime) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  if (type)
    *type = (const char *)mime->multitype;

  return mime->multiparts;
}
