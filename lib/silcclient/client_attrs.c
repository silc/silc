/*

  client_attrs.c 

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

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

/* Add one attribute that was found from hash table */

static void silc_client_attributes_process_foreach(void *key, void *context,
						   void *user_context)
{
  SilcAttribute attribute = (SilcAttribute)(SilcUInt32)key;
  SilcAttributePayload attr = context;
  SilcBuffer buffer = user_context;
  const unsigned char *data;
  SilcUInt32 data_len;

  if (!context) {
    SILC_LOG_DEBUG(("Attribute %d was not set", attribute));

    /* USER_PUBLIC_KEY we have set earlier */
    if (attribute == SILC_ATTRIBUTE_USER_PUBLIC_KEY)
      return;

    /* The requested attribute was not found */
    buffer = silc_attribute_payload_encode(buffer, attribute,
					   SILC_ATTRIBUTE_FLAG_INVALID,
					   NULL, 0);
    return;
  }

  SILC_LOG_DEBUG(("Attribute %d found", attribute));
  data = silc_attribute_get_data(attr, &data_len);
  buffer = silc_attribute_payload_encode_data(buffer, attribute,
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
  SilcAttribute attribute;
  SilcAttributePayload attr;
  SilcAttributeObjPk pk;
  unsigned char sign[2048];
  SilcUInt32 sign_len;

  SILC_LOG_DEBUG(("Process Requested Attributes"));

  /* If nothing is set by application assume that we don't want to use
     attributes, ignore the request. */
  if (!conn->attrs)
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
  silc_dlist_start(attrs);
  while ((attr = silc_dlist_get(attrs)) != SILC_LIST_END) {
    /* Put all attributes of this type */
    attribute = silc_attribute_get_attribute(attr);

    /* Ignore signature since we will compute it later */
    if (attribute == SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE)
      continue;

    silc_hash_table_find_foreach(conn->attrs, (void *)(SilcUInt32)attribute,
				 silc_client_attributes_process_foreach,
				 buffer);
  }

  /* Finally compute the digital signature of all the data we provided. */
  if (silc_pkcs_sign_with_hash(client->pkcs, client->internal->sha1hash,
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

  if (!conn->attrs)
    conn->attrs = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL,
					NULL, silc_client_attribute_destruct,
					NULL, TRUE);
  silc_hash_table_add(conn->attrs, (void *)(SilcUInt32)attribute, attr);
  return attr;
}

/* Delete one attribute */

bool silc_client_attribute_del(SilcClient client,
			       SilcClientConnection conn,
			       SilcAttributePayload attr)
{
  SilcAttribute attribute = silc_attribute_get_attribute(attr);
  bool ret;

  ret = silc_hash_table_del_by_context(conn->attrs,
				       (void *)(SilcUInt32)attribute, attr);

  if (ret)
    if (!silc_hash_table_count(conn->attrs)) {
      silc_hash_table_free(conn->attrs);
      conn->attrs = NULL;
    }

  return ret;
}

/* Return all attributes */

const SilcHashTable silc_client_attributes_get(SilcClient client,
					       SilcClientConnection conn)
{
  return (const SilcHashTable)conn->attrs;
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
					  SILC_ATTRIBUTE_USER_PUBLIC_KEY, 0);

  va_start(va, attribute);
  while (attribute) {
    buffer = silc_attribute_payload_encode(buffer, attribute, 0, NULL, 0);
    attribute = (SilcAttribute)va_arg(va, SilcUInt32);
  }
  va_end(va);

  return buffer;
}
