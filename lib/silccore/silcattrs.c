/*

  silcattrs.c 

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
/* Implementation of Attribute Payload routines */
/* $Id$ */

#include "silcincludes.h"
#include "silcattrs.h"

/******************************************************************************

                             Attribute Payload

******************************************************************************/

struct SilcAttributePayloadStruct {
  SilcAttribute attribute;
  SilcAttributeFlags flags;
  SilcUInt16 data_len;
  unsigned char *data;
};

/* Parse one attribute payload */

SilcAttributePayload
silc_attribute_payload_parse(const unsigned char *payload,
			     SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcAttributePayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing attribute payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Attribute Payload. */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_CHAR(&newp->attribute),
			     SILC_STR_UI_CHAR(&newp->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->data, 
							 &newp->data_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (newp->data_len > buffer.len - 4) {
    SILC_LOG_ERROR(("Incorrect attribute payload"));
    goto err;
  }

  return newp;

 err:
  silc_attribute_payload_free(newp);
  return NULL;
}

/* Encode one attribute payload */

SilcBuffer silc_attribute_payload_encode(SilcAttribute attribute,
					 SilcAttributeFlags flags,
					 const unsigned char *data,
					 SilcUInt32 data_len)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Encoding Attribute Payload"));

  buffer = silc_buffer_alloc_size(4 + data_len);
  if (!buffer)
    return NULL;

  /* Encode the Attribute Payload */
  silc_buffer_format(buffer, 
		     SILC_STR_UI_CHAR(attribute),
		     SILC_STR_UI_CHAR(flags),
		     SILC_STR_UI_SHORT((SilcUInt16)data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);

  return buffer;
}

/* Parse list of payloads */

SilcDList silc_attribute_payload_parse_list(const unsigned char *payload,
					    SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcDList list;
  SilcAttributePayload newp;
  int len, ret;

  SILC_LOG_DEBUG(("Parsing Attribute Payload list"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  list = silc_dlist_init();

  while (buffer.len) {
    newp = silc_calloc(1, sizeof(*newp));
    if (!newp)
      goto err;
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_CHAR(&newp->attribute),
			       SILC_STR_UI_CHAR(&newp->flags),
			       SILC_STR_UI16_NSTRING_ALLOC(&newp->data, 
							   &newp->data_len),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

    if (newp->data_len > buffer.len) {
      SILC_LOG_ERROR(("Incorrect attribute payload in list"));
      goto err;
    }

    len = 4 + newp->data_len;
    if (buffer.len < len)
      break;
    silc_buffer_pull(&buffer, len);

    silc_dlist_add(list, newp);
  }
  
  return list;

 err:
  silc_attribute_payload_list_free(list);
  return NULL;
}

/* Encode list of payloads */

SilcBuffer silc_attribute_payload_encode_list(SilcUInt32 num_attrs, ...)
{
  SilcBuffer buffer = NULL;
  va_list ap;
  int i, len = 0;
  SilcAttribute attribute;
  SilcAttributeFlags flags;
  unsigned char *data;
  SilcUInt32 data_len;

  if (!num_attrs)
    return NULL;

  va_start(ap, num_attrs);
  for (i = 0; i < num_attrs; i++) {
    attribute = va_arg(ap, SilcUInt32);
    flags = va_arg(ap, SilcUInt32);
    data = va_arg(ap, unsigned char *);
    data_len = va_arg(ap, SilcUInt32);

    if (data || !data_len)
      continue;

    len = 4 + data_len;
    buffer = silc_buffer_realloc(buffer,
				 (buffer ? buffer->truelen + len : len));
    silc_buffer_pull_tail(buffer, (buffer->end - buffer->data));
    silc_buffer_format(buffer, 
		       SILC_STR_UI_CHAR(attribute),
		       SILC_STR_UI_CHAR(flags),
		       SILC_STR_UI_SHORT((SilcUInt16)data_len),
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_END);
    silc_buffer_pull(buffer, len);
  }
  va_end(ap);

  if (buffer)
    silc_buffer_push(buffer, buffer->data - buffer->head);

  return buffer;
}

/* Free Attribute Payload */

void silc_attribute_payload_free(SilcAttributePayload payload)
{
  silc_free(payload->data);
  silc_free(payload);
}

/* Free's list of Attribute Payloads */

void silc_attribute_payload_list_free(SilcDList list)
{
  SilcAttributePayload entry;

  silc_dlist_start(list);
  while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
    silc_attribute_payload_free(entry);
    silc_dlist_del(list, entry);
  }

  silc_dlist_uninit(list);
}

/* Return attribute type */

SilcAttribute silc_attribute_get_attribute(SilcAttributePayload payload)
{
  return payload->attribute;
}

/* Return attribute flags */

SilcAttributeFlags silc_attribute_get_flags(SilcAttributePayload payload)
{
  return payload->flags;
}

/* Return attribute data from the payload */

const unsigned char *silc_attribute_get_data(SilcAttributePayload payload,
					     SilcUInt32 *data_len)
{
  if (data_len)
    *data_len = payload->data_len;
  return (const unsigned char *)payload->data;
}

/* Return parsed attribute object */

bool silc_attribute_get_object(SilcAttributePayload payload,
			       SilcAttribute attribute,
			       void **object, SilcUInt32 object_size)
{
  SilcUInt16 len;
  bool ret = FALSE;

  if (!attribute || !object || !(*object))
    return FALSE;

  switch (attribute) {
  case SILC_ATTRIBUTE_USER_INFO:
    SILC_NOT_IMPLEMENTED("SILC_ATTRIBUTE_USER_INFO");
    break;

  case SILC_ATTRIBUTE_SERVICE:
    {
      SilcAttributeObjService *service = *object;
      if (object_size != sizeof(*service))
	break;
      if (payload->data_len < 7)
	break;
      SILC_GET32_MSB(service->port, payload->data);
      SILC_GET16_MSB(len, payload->data + 4);
      if (payload->data_len < 7 + len)
	break;
      memcpy(service->address, payload->data + 6,
	     (len < sizeof(service->address) - 1 ? len :
	      sizeof(service->address) - 1));
      service->status = payload->data[6 + len] ? TRUE : FALSE;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_STATUS_MOOD:
  case SILC_ATTRIBUTE_PREFERRED_CONTACT:
    {
      SilcUInt32 *mask = *object;
      if (object_size != sizeof(SilcUInt32))
	break;
      if (payload->data_len < 4)
	break;
      SILC_GET32_MSB(*mask, payload->data);
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_STATUS_FREETEXT:
  case SILC_ATTRIBUTE_PREFERRED_LANGUAGE:
  case SILC_ATTRIBUTE_TIMEZONE:
    {
      char *string = *object;
      if (payload->data_len < 2)
	break;
      SILC_GET16_MSB(len, payload->data);
      if (payload->data_len < 2 + len)
	break;
      if (object_size < len)
	break;
      memcpy(string, payload->data + 2, len);
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_STATUS_MESSAGE:
  case SILC_ATTRIBUTE_EXTENSION:
    {
      SilcAttributeObjMime *mime = *object;
      if (object_size != sizeof(*mime))
	break;
      mime->mime = silc_memdup(payload->data, payload->data_len);
      mime->mime_len = payload->data_len;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_GEOLOCATION:
    {
      SilcAttributeObjGeo *geo = *object;
      SilcBufferStruct buffer;
      int res;
      if (object_size != sizeof(*geo))
	break;
      silc_buffer_set(&buffer, (unsigned char *)payload->data,
		      payload->data_len);
      res = silc_buffer_unformat(&buffer,
				 SILC_STR_UI16_STRING_ALLOC(&geo->longitude),
				 SILC_STR_UI16_STRING_ALLOC(&geo->latitude),
				 SILC_STR_UI16_STRING_ALLOC(&geo->altitude),
				 SILC_STR_UI16_STRING_ALLOC(&geo->accuracy),
				 SILC_STR_END);
      if (res == 1)
	break;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_DEVICE_INFO:
    {
      SilcAttributeObjDevice *dev = *object;
      SilcBufferStruct buffer;
      SilcUInt32 type;
      int res;
      if (object_size != sizeof(*dev))
	break;
      silc_buffer_set(&buffer, (unsigned char *)payload->data,
		      payload->data_len);
      res =
	silc_buffer_unformat(&buffer,
			     SILC_STR_UI_INT(&type),
			     SILC_STR_UI16_STRING_ALLOC(&dev->manufacturer),
			     SILC_STR_UI16_STRING_ALLOC(&dev->version),
			     SILC_STR_UI16_STRING_ALLOC(&dev->model),
			     SILC_STR_UI16_STRING_ALLOC(&dev->language),
			     SILC_STR_END);
      if (res == 1)
	break;
      dev->type = type;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_USER_PUBLIC_KEY:
  case SILC_ATTRIBUTE_SERVER_PUBLIC_KEY:
    {
      SilcAttributeObjPk *pk = *object;
      SilcBufferStruct buffer;
      int res;
      if (object_size != sizeof(*pk))
	break;
      silc_buffer_set(&buffer, (unsigned char *)payload->data,
		      payload->data_len);
      res =
	silc_buffer_unformat(&buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&pk->type, &len),
			     SILC_STR_END);
      if (res == 1)
	break;
      pk->data = silc_memdup(payload->data + 2 + len,
			     payload->data_len - 2 - len);
      pk->data_len = payload->data_len - 2 - len;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE:
  case SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE:
    {
      SilcAttributeObjPk *pk = *object;
      if (object_size != sizeof(*pk))
	break;
      pk->type = NULL;
      pk->data = silc_memdup(payload->data, payload->data_len);
      pk->data_len = payload->data_len;
      ret = TRUE;
    }
    break;

  default:
    break;
  }

  return ret;
}
