/*

  client_attrs.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

typedef struct {
  SilcBuffer buffer;
} SilcAttrForeach;

/* Add one attribute that was found from hash table */

static void silc_client_attributes_process_foreach(void *key, void *context,
						   void *user_context)
{
  SilcAttribute attribute = (SilcAttribute)SILC_PTR_TO_32(key);
  SilcAttributePayload attr = context;
  SilcAttrForeach *f = user_context;
  const unsigned char *data;
  SilcUInt32 data_len;

  if (!context) {
    SILC_LOG_DEBUG(("Attribute %d was not set", attribute));

    /* USER_PUBLIC_KEY we have set earlier */
    if (attribute == SILC_ATTRIBUTE_USER_PUBLIC_KEY)
      return;

    /* The requested attribute was not found */
    f->buffer = silc_attribute_payload_encode(f->buffer, attribute,
					      SILC_ATTRIBUTE_FLAG_INVALID,
					      NULL, 0);
    return;
  }

  SILC_LOG_DEBUG(("Attribute %d found", attribute));
  data = silc_attribute_get_data(attr, &data_len);

#if 0
  /* We replace the TIMEZONE with valid value here */
  if (attribute == SILC_ATTRIBUTE_TIMEZONE) {
    data = (const unsigned char *)silc_get_time(0);
    data_len = strlen(data);
    f->buffer = silc_attribute_payload_encode(f->buffer, attribute,
					      SILC_ATTRIBUTE_FLAG_VALID,
					      (void *)data, data_len);
    return;
  }
#endif

  f->buffer = silc_attribute_payload_encode_data(f->buffer, attribute,
						 SILC_ATTRIBUTE_FLAG_VALID,
						 data, data_len);
}

/* Process list of attributes.  Returns reply to the requested attributes. */

SilcBuffer silc_client_attributes_process(SilcClient client,
					  SilcSocketConnection sock,
					  SilcDList attrs)
{
  SilcClientConnection conn = sock->user_data;
  SilcBuffer buffer = NULL;
  SilcAttrForeach f;
  SilcAttribute attribute;
  SilcAttributePayload attr;
  SilcAttributeObjPk pk;
  unsigned char sign[2048 + 1];
  SilcUInt32 sign_len;

  SILC_LOG_DEBUG(("Process Requested Attributes"));

  /* If nothing is set by application assume that we don't want to use
     attributes, ignore the request. */
  if (!conn->internal->attrs)
    return NULL;

  /* Always put our public key. */
  pk.type = "silc-rsa";
  pk.data = silc_pkcs_public_key_encode(client->public_key, &pk.data_len);
  buffer = silc_attribute_payload_encode(buffer,
					 SILC_ATTRIBUTE_USER_PUBLIC_KEY,
					 pk.data ? SILC_ATTRIBUTE_FLAG_VALID :
					 SILC_ATTRIBUTE_FLAG_INVALID,
					 &pk, sizeof(pk));
  silc_free(pk.data);

  /* Go through all requested attributes */
  f.buffer = buffer;
  silc_dlist_start(attrs);
  while ((attr = silc_dlist_get(attrs)) != SILC_LIST_END) {
    /* Put all attributes of this type */
    attribute = silc_attribute_get_attribute(attr);

    /* Ignore signature since we will compute it later */
    if (attribute == SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE)
      continue;

    silc_hash_table_find_foreach(conn->internal->attrs,
				 SILC_32_TO_PTR(attribute),
				 silc_client_attributes_process_foreach,
				 &f);
  }
  buffer = f.buffer;

  /* Finally compute the digital signature of all the data we provided. */
  if (silc_pkcs_sign_with_hash(client->pkcs, client->sha1hash,
			       buffer->data, buffer->len,
			       sign, &sign_len)) {
    pk.type = NULL;
    pk.data = sign;
    pk.data_len = sign_len;
    buffer =
      silc_attribute_payload_encode(buffer,
				    SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE,
				    SILC_ATTRIBUTE_FLAG_VALID,
				    &pk, sizeof(pk));
  }

  return buffer;
}

static void silc_client_attribute_destruct(void *key, void *context,
					   void *user_context)
{
  silc_attribute_payload_free(context);
}

/* Add new attribute */

SilcAttributePayload silc_client_attribute_add(SilcClient client,
					       SilcClientConnection conn,
					       SilcAttribute attribute,
					       void *object,
					       SilcUInt32 object_size)
{
  SilcAttributePayload attr;

  attr = silc_attribute_payload_alloc(attribute, SILC_ATTRIBUTE_FLAG_VALID,
				      object, object_size);
  if (!attr)
    return NULL;

  if (!conn->internal->attrs)
    conn->internal->attrs =
      silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL,
			    NULL, silc_client_attribute_destruct,
			    NULL, TRUE);
  silc_hash_table_add(conn->internal->attrs,
		      SILC_32_TO_PTR(attribute), attr);
  return attr;
}

static void silc_client_attribute_del_foreach(void *key, void *context,
					      void *user_context)
{
  SilcClientConnection conn = user_context;
  SilcAttributePayload attr = context;
  SilcAttribute attribute;
  if (!attr)
    return;
  attribute = silc_attribute_get_attribute(attr);
  silc_hash_table_del_by_context(conn->internal->attrs,
				 SILC_32_TO_PTR(attribute), attr);
}

/* Delete one attribute */

bool silc_client_attribute_del(SilcClient client,
			       SilcClientConnection conn,
			       SilcAttribute attribute,
			       SilcAttributePayload attr)
{
  bool ret;

  if (!conn->internal->attrs)
    return FALSE;

  if (attr) {
    attribute = silc_attribute_get_attribute(attr);
    ret = silc_hash_table_del_by_context(conn->internal->attrs,
					 SILC_32_TO_PTR(attribute), attr);
  } else if (attribute) {
    silc_hash_table_find_foreach(conn->internal->attrs,
				 SILC_32_TO_PTR(attribute),
				 silc_client_attribute_del_foreach, conn);
    ret = TRUE;
  } else{
    return FALSE;
  }

  if (ret)
    if (!silc_hash_table_count(conn->internal->attrs)) {
      silc_hash_table_free(conn->internal->attrs);
      conn->internal->attrs = NULL;
    }

  return ret;
}

/* Return all attributes */

SilcHashTable silc_client_attributes_get(SilcClient client,
					 SilcClientConnection conn)
{
  return conn->internal->attrs;
}

/* Construct a Requested Attributes buffer. If the `attribute' is zero (0)
   then all attributes are requested.  Additionally `attribute' and
   all variable arguments can be one requested attribute.  Always set
   the last requested attribute to zero (0) to complete list of
   requested attribute. */

SilcBuffer silc_client_attributes_request(SilcAttribute attribute, ...)
{
  va_list va;
  SilcBuffer buffer = NULL;

  if (!attribute)
    return silc_client_attributes_request(SILC_ATTRIBUTE_USER_INFO,
					  SILC_ATTRIBUTE_SERVICE,
					  SILC_ATTRIBUTE_STATUS_MOOD,
					  SILC_ATTRIBUTE_STATUS_FREETEXT,
					  SILC_ATTRIBUTE_STATUS_MESSAGE,
					  SILC_ATTRIBUTE_PREFERRED_LANGUAGE,
					  SILC_ATTRIBUTE_PREFERRED_CONTACT,
					  SILC_ATTRIBUTE_TIMEZONE,
					  SILC_ATTRIBUTE_GEOLOCATION,
					  SILC_ATTRIBUTE_DEVICE_INFO,
					  SILC_ATTRIBUTE_USER_PUBLIC_KEY,
					  SILC_ATTRIBUTE_USER_ICON, 0);

  va_start(va, attribute);
  while (attribute) {
    buffer = silc_attribute_payload_encode(buffer, attribute, 0, NULL, 0);
    attribute = (SilcAttribute)va_arg(va, SilcUInt32);
  }
  va_end(va);

  return buffer;
}
