/*

  silcmime.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
#include "silcmime.h"

struct SilcMimeStruct {
  SilcHashTable fields;
  unsigned char *data;
  SilcUInt32 data_len;
  SilcDList multiparts;
  char *boundary;
};

struct SilcMimeAssemblerStruct {
  SilcMimeComplete complete;
  void *complete_context;
  SilcHashTable fragments;
};

static void silc_mime_field_dest(void *key, void *context, void *user_context)
{
  silc_free(key);
  silc_free(context);
}

SilcMime silc_mime_alloc(void)
{
  SilcMime mime;

  mime = silc_calloc(1, sizeof(*mime));
  if (!mime)
    return NULL;

  mime->fields = silc_hash_table_alloc(0, silc_hash_string, mime,
							    silc_hash_string_compare, mime,
							    silc_mime_field_dest, mime, TRUE);
  if (!mime->fields) {
    silc_mime_free(mime);
    return NULL;
  }

  return mime;
}

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
  silc_free(mime);
}

static void silc_mime_assembler_dest(void *key, void *context,
							  void *user_context)
{
  silc_free(key);
  silc_hash_table_free(context);
}

SilcMimeAssembler silc_mime_assembler_alloc(SilcMimeComplete complete,
								    void *complete_context)
{
  SilcMimeAssembler assembler;

  assembler = silc_calloc(1, sizeof(*assembler));
  if (!assembler)
    return NULL;

  assembler->complete = complete;
  assembler->complete_context = complete_context;
  assembler->fragments =
    silc_hash_table_alloc(0, silc_hash_string, NULL,
					 silc_hash_string_compare, NULL,
					 silc_mime_assembler_dest, assembler, TRUE);
  if (!assembler->fragments) {
    silc_mime_assembler_free(assembler);
    return NULL;
  }

  return assembler;
}

void silc_mime_assembler_free(SilcMimeAssembler assembler)
{
  silc_hash_table_free(assembler->fragments);
  silc_free(assembler);
}

SilcMime silc_mime_decode(const unsigned char *data, SilcUInt32 data_len)
{
  SilcMime mime;
  int i, k;
  char *tmp, *field, *value, *line;

  SILC_LOG_DEBUG(("Parsing MIME message"));

  if (!data)
    return NULL;

  mime = silc_mime_alloc();
  if (!mime)
    return NULL;

  /* Parse the fields */
  line = tmp = (char *)data;
  for (i = 0; i < data_len; i++) {
    /* Get field line */
    if (data_len - i >= 2 && tmp[i] == '\r' && tmp[i + 1] == '\n') {
	 /* Get field */
	 field = strchr(line, ':');
	 if (!field)
	   goto err;
	 field = silc_memdup(line, field - line);
	 if (!field)
	   goto err;

	 /* Get value. Remove whitespaces too. */
	 value = strchr(line, ':');
	 if ((tmp + i) - value < 2)
	   goto err;
	 value++;
	 for (k = 0; k < (tmp + i) - value; k++) {
	   if (value[k] == '\r')
		goto err;
	   if (value[k] != ' ' && value[k] != '\t')
		break;
	 }
	 value += k;
	 if ((tmp + i) - value < 1)
	   goto err;
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

    mime->multiparts = silc_dlist_init();
    if (!mime->multiparts)
	 goto err;

    /* Get boundary */
    value = strrchr(field, '=');
    if (value && strlen(value) > 1) {
	 value++;

	 SILC_LOG_DEBUG(("Boundary '%s'", value));

	 memset(b, 0, sizeof(b));
	 line = strdup(value);
	 if (strrchr(line, '"')) {
	   *strrchr(line, '"') = '\0';
	   snprintf(b, sizeof(b) - 1, "--%s", line + 1);
	   mime->boundary = strdup(line + 1);
	 } else {
	   snprintf(b, sizeof(b) - 1, "--%s", line);
	   mime->boundary = strdup(line);
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
		if (k >= data_len)
		  goto err;

		/* Remove preceding CRLF */
		k -= 2;

		/* Parse the part */
		p = silc_mime_decode(line, k - i);
		if (!p)
		  goto err;

		silc_dlist_add(mime->multiparts, p);
		i += (k - i);
	   }
	 }
    }
  } else {
    /* Get data area */
    if (i >= data_len)
	 i = 0;
    SILC_LOG_DEBUG(("Data len %d", data_len - i));
    silc_mime_add_data(mime, tmp + i, data_len - i);
  }

  return mime;

 err:
  silc_mime_free(mime);
  return NULL;
}

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
  while (silc_hash_table_get(&htl, (void **)&field, (void **)&value)) {
    memset(tmp, 0, sizeof(tmp));
    SILC_LOG_DEBUG(("Header %s: %s", field, value));
    snprintf(tmp, sizeof(tmp) - 1, "%s: %s\r\n", field, value);
    silc_buffer_strformat(&buf, tmp, SILC_STRFMT_END);
    i++;
  }
  silc_hash_table_list_reset(&htl);
  if (i)
    silc_buffer_strformat(&buf, "\r\n", SILC_STRFMT_END);

  /* Assemble the whole buffer */
  buffer = silc_buffer_alloc_size(mime->data_len + buf.len);
  if (!buffer)
    return NULL;

  /* Add headers */
  if (buf.len) {
    silc_buffer_put(buffer, buf.head, buf.len);
    silc_buffer_pull(buffer, buf.len);
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
	 if (i == 0) {
	   /* If fields are not present, add extra CRLF */
	   if (!silc_hash_table_count(part->fields))
		snprintf(tmp2, sizeof(tmp2) - 1, "\r\n");
	   snprintf(tmp, sizeof(tmp) - 1, "--%s\r\n%s", mime->boundary, tmp2);
	   i = 1;
	 } else {
	   /* If fields are not present, add extra CRLF */
	   if (!silc_hash_table_count(part->fields))
		snprintf(tmp2, sizeof(tmp2) - 1, "\r\n");
	   snprintf(tmp, sizeof(tmp) - 1, "\r\n--%s\r\n%s", mime->boundary, tmp2);
	 }

	 buffer = silc_buffer_realloc(buffer, buffer->truelen + pd_len +
							strlen(tmp));
	 if (!buffer)
	   return NULL;
	 silc_buffer_put_tail(buffer, tmp, strlen(tmp));
	 silc_buffer_pull_tail(buffer, strlen(tmp));
	 silc_buffer_put_tail(buffer, pd, pd_len);
	 silc_buffer_pull_tail(buffer, pd_len);
	 silc_free(pd);
    }

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp) - 1, "\r\n--%s--\r\n", mime->boundary);
    buffer = silc_buffer_realloc(buffer, buffer->truelen + strlen(tmp));
    if (!buffer)
	 return NULL;
    silc_buffer_put_tail(buffer, tmp, strlen(tmp));
    silc_buffer_pull_tail(buffer, strlen(tmp));
  }

  ret = silc_buffer_steal(buffer, encoded_len);
  silc_buffer_free(buffer);

  return ret;
}

static void silc_mime_assemble_dest(void *key, void *context,
							 void *user_context)
{
  silc_mime_free(context);
}

void silc_mime_assemble(SilcMimeAssembler assembler, SilcMime partial)
{
  char *type, *id = NULL, *tmp;
  SilcHashTable f;
  SilcMime p, complete;
  int i, number, total = -1;
  const unsigned char *data;
  SilcUInt32 data_len;
  SilcBuffer compbuf = NULL;

  SILC_LOG_DEBUG(("Assembling MIME fragments"));

  if (!assembler || !partial)
    goto err;

  type = (char *)silc_mime_get_field(partial, "Content-Type");
  if (!type)
    goto err;

  /* Get ID */
  tmp = strstr(type, "id=");
  if (!tmp)
    goto err;
  if (strlen(tmp) <= 4)
    goto err;
  tmp += 3;
  if (*tmp == '"')
    tmp++;
  id = strdup(tmp);
  if (strchr(id, ';'))
    *strchr(id, ';') = '\0';
  if (strrchr(id, '"'))
    *strrchr(id, '"') = '\0';

  SILC_LOG_DEBUG(("Fragment ID %s", id));

  /* Get fragment number */
  tmp = strstr(type, "number=");
  if (!tmp)
    goto err;
  tmp = strchr(tmp, '=');
  if (strlen(tmp) < 2)
    goto err;
  tmp++;
  if (strchr(tmp, ';')) {
    tmp = strdup(tmp);
    *strchr(tmp, ';') = '\0';
    number = atoi(tmp);
    silc_free(tmp);
  } else {
    number = atoi(tmp);
  }

  SILC_LOG_DEBUG(("Fragment number %d", number));

  /* Find fragments with this ID. */
  if (!silc_hash_table_find(assembler->fragments, (void *)id,
					   NULL, (void **)&f)) {
    /* This is new fragment to new message.  Add to hash table and return. */
    f = silc_hash_table_alloc(0, silc_hash_uint, NULL, NULL, NULL,
						silc_mime_assemble_dest, NULL, TRUE);
    if (!f)
	 goto err;
    silc_hash_table_add(f, SILC_32_TO_PTR(number), partial);
    silc_hash_table_add(assembler->fragments, id, f);
    return;
  }

  /* Try to get total number */
  tmp = strstr(type, "total=");
  if (tmp) {
    tmp = strchr(tmp, '=');
    if (strlen(tmp) < 2)
	 goto err;
    tmp++;
    if (strchr(tmp, ';')) {
	 tmp = strdup(tmp);
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
    return;
  }

  silc_hash_table_add(f, SILC_32_TO_PTR(number), partial);

  /* Verify that we really have all the fragments */
  if (silc_hash_table_count(f) < total)
    return;

  /* Assemble the complete MIME message now. We get them in order from
	the hash table. */
  for (i = 1; i <= total; i++) {
    if (!silc_hash_table_find(f, SILC_32_TO_PTR(i), NULL, (void **)&p))
	 goto err;

    /* The fragment is in the data portion of the partial message */
    data = silc_mime_get_data(p, &data_len);
    if (!data)
	 goto err;

    /* Assemble */
    if (!compbuf) {
	 compbuf = silc_buffer_alloc_size(data_len);
	 if (!compbuf)
	   goto err;
	 silc_buffer_put(compbuf, data, data_len);
    } else {
	 compbuf = silc_buffer_realloc(compbuf, compbuf->truelen + data_len);
	 if (!compbuf)
	   goto err;
	 silc_buffer_put_tail(compbuf, data, data_len);
	 silc_buffer_pull_tail(compbuf, data_len);
    }
  }

  /* Now parse the complete MIME message and deliver it */
  complete = silc_mime_decode((const unsigned char *)compbuf->head,
						compbuf->truelen);
  if (!complete)
    goto err;

  if (assembler->complete)
    assembler->complete(complete, assembler->complete_context);

  /* Delete the hash table entry. Destructors will free memory */
  silc_hash_table_del(assembler->fragments, (void *)id);

  silc_free(id);
  silc_buffer_free(compbuf);
  return;

 err:
  silc_free(id);
  if (compbuf)
    silc_buffer_free(compbuf);
  silc_mime_free(partial);
}

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
    srand((time(NULL) + buf_len) ^ rand());
    snprintf(id, sizeof(id) - 1, "%X%X%X",
		   (unsigned int)rand(), (unsigned int)time(NULL),
		   (unsigned int)buf_len);

    SILC_LOG_DEBUG(("Fragment ID %s", id));

    partial = silc_mime_alloc();
    if (!partial)
	 return NULL;

    silc_mime_add_field(partial, "MIME-Version", "1.0");
    memset(type, 0, sizeof(type));
    snprintf(type, sizeof(type) - 1,
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
	   snprintf(type, sizeof(type) - 1,
			  "message/partial; id=\"%s\"; number=%d",
			  id, num++);
	   silc_mime_add_data(partial, buf + off, max_size);
	   off += max_size;
	   len -= max_size;
	 } else {
	   snprintf(type, sizeof(type) - 1,
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

void silc_mime_add_field(SilcMime mime, const char *field, const char *value)
{
  if (!mime || !field || !value)
    return;

  silc_hash_table_add(mime->fields, strdup(field), strdup(value));
}

const char *silc_mime_get_field(SilcMime mime, const char *field)
{
  char *value;

  if (!mime || !field)
    return NULL;

  if (!silc_hash_table_find(mime->fields, (void *)field,
					   NULL, (void **)&value))
    return NULL;

  return (const char *)value;
}

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

const unsigned char *silc_mime_get_data(SilcMime mime, SilcUInt32 *data_len)
{
  if (!mime)
    return NULL;

  if (data_len)
    *data_len = mime->data_len;

  return mime->data;
}

bool silc_mime_is_partial(SilcMime mime)
{
  const char *type = silc_mime_get_field(mime, "Content-Type");
  if (!type)
    return FALSE;

  if (strstr(type, "message/partial"))
    return FALSE;

  return TRUE;
}

void silc_mime_set_multipart(SilcMime mime, const char *type,
					    const char *boundary)
{
  char tmp[1024];

  if (!mime || !type || !boundary)
    return;

  memset(tmp, 0, sizeof(tmp));
  snprintf(tmp, sizeof(tmp) - 1, "multipart/%s; boundary=%s", type, boundary);
  silc_mime_add_field(mime, "Content-Type", tmp);
  silc_free(mime->boundary);
  mime->boundary = strdup(boundary);

  if (mime->multiparts)
    return;
  mime->multiparts = silc_dlist_init();
}

bool silc_mime_add_multipart(SilcMime mime, SilcMime part)
{
  if (!mime || !mime->multiparts || !part)
    return FALSE;

  silc_dlist_add(mime->multiparts, part);
  return TRUE;
}

bool silc_mime_is_multipart(SilcMime mime)
{
  if (!mime)
    return FALSE;

  return mime->multiparts != NULL;
}

SilcDList silc_mime_get_multiparts(SilcMime mime)
{
  if (!mime)
    return NULL;

  return mime->multiparts;
}
