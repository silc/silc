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

/* Internal routine for encoding a attribute */

static unsigned char *
silc_attribute_payload_encode_int(SilcAttribute attribute,
				  SilcAttributeFlags flags,
				  void *object,
				  SilcUInt32 object_size,
				  SilcUInt32 *ret_len)
{
  SilcBuffer tmpbuf = NULL;
  unsigned char tmp[4], *str = NULL, *ret;
  int len;

  /* Encode according to attribute type */
  if (flags & SILC_ATTRIBUTE_FLAG_VALID) {
    if (!object && !object_size)
      return NULL;

    switch (attribute) {

    case SILC_ATTRIBUTE_USER_INFO:
      {
	SilcVCard vcard = object;
	if (object_size != sizeof(*vcard))
	  return NULL;
	str = silc_vcard_encode(vcard, &object_size);
	if (!str)
	  return NULL;
	object = str;
      }
      break;

    case SILC_ATTRIBUTE_SERVICE:
      {
	SilcAttributeObjService *service = object;
	if (object_size != sizeof(*service))
	  return NULL;
	len = strlen(service->address);
	str = silc_malloc(7 + len);
	if (!str)
	  return NULL;
	SILC_PUT32_MSB(service->port, str);
	SILC_PUT16_MSB(len, str + 4);
	memcpy(str + 6, service->address, len);
	str[6 + len] = service->status;
	object = str;
	object_size = 7 + len;
      }
      break;

    case SILC_ATTRIBUTE_STATUS_MOOD:
    case SILC_ATTRIBUTE_PREFERRED_CONTACT:
      {
	SilcUInt32 mask = (SilcUInt32)object;
	if (object_size != sizeof(SilcUInt32))
	  return NULL;
	SILC_PUT32_MSB(mask, tmp);
	object = tmp;
	object_size = sizeof(SilcUInt32);
      }
      break;

    case SILC_ATTRIBUTE_STATUS_FREETEXT:
    case SILC_ATTRIBUTE_PREFERRED_LANGUAGE:
    case SILC_ATTRIBUTE_TIMEZONE:
      {
	unsigned char *string = object;
	str = silc_malloc(2 + object_size);
	if (!str)
	  return NULL;
	SILC_PUT16_MSB(object_size, str);
	memcpy(str + 2, string, object_size);
	object = str;
	object_size += 2;
      }
      break;

    case SILC_ATTRIBUTE_STATUS_MESSAGE:
    case SILC_ATTRIBUTE_EXTENSION:
      {
	SilcAttributeObjMime *mime = object;
	if (object_size != sizeof(*mime))
	  return NULL;
	object = (void *)mime->mime;
	object_size = mime->mime_len;
      }
      break;

    case SILC_ATTRIBUTE_GEOLOCATION:
      {
	SilcAttributeObjGeo *geo = object;
	int len1, len2, len3, len4;
	if (object_size != sizeof(*geo))
	  return NULL;
	len1 = (geo->longitude ? strlen(geo->longitude) : 0);
	len2 = (geo->latitude  ? strlen(geo->latitude)  : 0);
	len3 = (geo->altitude  ? strlen(geo->altitude)  : 0);
	len4 = (geo->accuracy  ? strlen(geo->accuracy)  : 0);
	if (len1 + len2 + len3 + len4 == 0)
	  return NULL;
	len = len1 + len2 + len3 + len4;
	tmpbuf = silc_buffer_alloc_size(8 + len);
	if (!tmpbuf)
	  return NULL;
	silc_buffer_format(tmpbuf,
			   SILC_STR_UI_SHORT(len1),
			   SILC_STR_UI16_STRING(len1 ? geo->longitude : ""),
			   SILC_STR_UI_SHORT(len2),
			   SILC_STR_UI16_STRING(len2 ? geo->latitude : ""),
			   SILC_STR_UI_SHORT(len3),
			   SILC_STR_UI16_STRING(len3 ? geo->altitude : ""),
			   SILC_STR_UI_SHORT(len4),
			   SILC_STR_UI16_STRING(len4 ? geo->accuracy : ""),
			   SILC_STR_END);
	object = tmpbuf->data;
	object_size = tmpbuf->len;
      }
      break;

    case SILC_ATTRIBUTE_DEVICE_INFO:
      {
	SilcAttributeObjDevice *dev = object;
	int len1, len2, len3, len4;
	if (object_size != sizeof(*dev))
	  return NULL;
	len1 = (dev->manufacturer ? strlen(dev->manufacturer) : 0);
	len2 = (dev->version      ? strlen(dev->version)      : 0);
	len3 = (dev->model        ? strlen(dev->model)        : 0);
	len4 = (dev->language     ? strlen(dev->language)     : 0);
	if (len1 + len2 + len3 + len4 == 0)
	  return NULL;
	len = len1 + len2 + len3 + len4;
	tmpbuf = silc_buffer_alloc_size(4 + 8 + len);
	if (!tmpbuf)
	  return NULL;
	silc_buffer_format(tmpbuf,
			   SILC_STR_UI_INT(dev->type),
			   SILC_STR_UI_SHORT(len1),
			   SILC_STR_UI16_STRING(len1 ? dev->manufacturer : ""),
			   SILC_STR_UI_SHORT(len2),
			   SILC_STR_UI16_STRING(len2 ? dev->version : ""),
			   SILC_STR_UI_SHORT(len3),
			   SILC_STR_UI16_STRING(len3 ? dev->model : ""),
			   SILC_STR_UI_SHORT(len4),
			   SILC_STR_UI16_STRING(len4 ? dev->language : ""),
			   SILC_STR_END);
	object = tmpbuf->data;
	object_size = tmpbuf->len;
      }
      break;

    case SILC_ATTRIBUTE_USER_PUBLIC_KEY:
    case SILC_ATTRIBUTE_SERVER_PUBLIC_KEY:
      {
	SilcAttributeObjPk *pk = object;
	if (object_size != sizeof(*pk))
	  return NULL;
	len = (pk->type ? strlen(pk->type) : 0);
	tmpbuf = silc_buffer_alloc_size(2 + len + pk->data_len);
	if (!tmpbuf)
	  return NULL;
	silc_buffer_format(tmpbuf,
			   SILC_STR_UI_SHORT(len),
			   SILC_STR_UI16_STRING(pk->type),
			   SILC_STR_UI_XNSTRING(pk->data, pk->data_len),
			   SILC_STR_END);
	object = tmpbuf->data;
	object_size = tmpbuf->len;
      }
      break;

    case SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE:
    case SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE:
      {
	SilcAttributeObjPk *pk = object;
	if (object_size != sizeof(*pk))
	  return NULL;
	object = pk->data;
	object_size = pk->data_len;
      }
      break;

    default:
      return NULL;
      break;
    }

    ret = silc_memdup(object, object_size);

    if (tmpbuf)
      silc_buffer_free(tmpbuf);
    silc_free(str);

    if (ret_len)
      *ret_len = object_size;

    return ret;
  }

  return NULL;
}

/* Allocates attribute payload and encodes the attribute there */

SilcAttributePayload silc_attribute_payload_alloc(SilcAttribute attribute,
						  SilcAttributeFlags flags,
						  void *object,
						  SilcUInt32 object_size)
{
  SilcAttributePayload attr;
  SilcUInt32 tmp_len;

  attr = silc_calloc(1, sizeof(*attr));
  if (!attr)
    return NULL;

  attr->attribute = attribute;
  attr->flags = flags;
  attr->data =
    silc_attribute_payload_encode_int(attribute, flags, object,
				      object_size, &tmp_len);
  attr->data_len = (SilcUInt16)tmp_len;
  if (!attr->data) {
    silc_free(attr);
    return NULL;
  }

  return attr;
}

/* Parse list of payloads */

SilcDList silc_attribute_payload_parse(const unsigned char *payload,
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

/* Encode one attribute payload to buffer */

SilcBuffer silc_attribute_payload_encode(SilcBuffer attrs,
					 SilcAttribute attribute,
					 SilcAttributeFlags flags,
					 void *object,
					 SilcUInt32 object_size)
{
  object = silc_attribute_payload_encode_int(attribute, flags, object,
					     object_size, &object_size);
  attrs = silc_attribute_payload_encode_data(attrs, attribute, flags,
					     (const unsigned char *)object,
					     object_size);
  silc_free(object);
  return attrs;
}

/* Encoded the attribute data directly to buffer */

SilcBuffer silc_attribute_payload_encode_data(SilcBuffer attrs,
					      SilcAttribute attribute,
					      SilcAttributeFlags flags,
					      const unsigned char *data,
					      SilcUInt32 data_len)
{
  SilcBuffer buffer = attrs;
  int len;

  len = 4 + data_len;
  buffer = silc_buffer_realloc(buffer,
			       (buffer ? buffer->truelen + len : len));
  if (!buffer)
    return NULL;
  silc_buffer_pull(buffer, buffer->len);
  silc_buffer_pull_tail(buffer, len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_CHAR(attribute),
		     SILC_STR_UI_CHAR(flags),
		     SILC_STR_UI_SHORT((SilcUInt16)data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);
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
    *data_len = (SilcUInt32)payload->data_len;
  return (const unsigned char *)payload->data;
}

/* Construct digital signature verification data */

unsigned char *silc_attribute_get_verify_data(SilcDList attrs,
					      bool server_verification,
					      SilcUInt32 *data_len)
{
  SilcAttributePayload attr;
  SilcBufferStruct buffer;
  unsigned char *data = NULL;
  SilcUInt32 len = 0;

  silc_dlist_start(attrs);
  while ((attr = silc_dlist_get(attrs)) != SILC_LIST_END) {
    switch (attr->attribute) {
    case SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE:
      /* Server signature is never part of the verification data */
      break;

    case SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE:
      /* For user signature verification this is not part of the data */
      if (!server_verification)
	break;

      /* Fallback, for server signature verification, user digital signature
	 is part of verification data. */

    default:
      /* All other data is part of the verification data */
      data = silc_realloc(data, sizeof(*data) * (4 + attr->data_len + len));
      if (!data)
	return NULL;
      silc_buffer_set(&buffer, data + len, 4 + attr->data_len);
      silc_buffer_format(&buffer, 
			 SILC_STR_UI_CHAR(attr->attribute),
			 SILC_STR_UI_CHAR(attr->flags),
			 SILC_STR_UI_SHORT(attr->data_len),
			 SILC_STR_UI_XNSTRING(attr->data, attr->data_len),
			 SILC_STR_END);
      len += 4 + attr->data_len;
      break;
    }
  }

  if (data_len)
    *data_len = len;

  return data;
}

/* Return parsed attribute object */

bool silc_attribute_get_object(SilcAttributePayload payload,
			       void *object, SilcUInt32 object_size)
{
  SilcUInt16 len;
  bool ret = FALSE;

  if (!object || payload->flags & SILC_ATTRIBUTE_FLAG_INVALID)
    return FALSE;

  switch (payload->attribute) {
  case SILC_ATTRIBUTE_USER_INFO:
    {
      SilcVCard vcard = object;
      if (object_size != sizeof(*vcard))
	break;
      if (!silc_vcard_decode(payload->data, payload->data_len, vcard))
	break;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_SERVICE:
    {
      SilcAttributeObjService *service = object;
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
      SilcUInt32 *mask = (SilcUInt32 *)object;
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
      char *string = object;
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
      SilcAttributeObjMime *mime = object;
      if (object_size != sizeof(*mime))
	break;
      mime->mime = (const unsigned char *)payload->data;
      mime->mime_len = payload->data_len;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_GEOLOCATION:
    {
      SilcAttributeObjGeo *geo = object;
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
      if (res == -1)
	break;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_DEVICE_INFO:
    {
      SilcAttributeObjDevice *dev = object;
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
      if (res == -1)
	break;
      dev->type = type;
      ret = TRUE;
    }
    break;

  case SILC_ATTRIBUTE_USER_PUBLIC_KEY:
  case SILC_ATTRIBUTE_SERVER_PUBLIC_KEY:
    {
      SilcAttributeObjPk *pk = object;
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
      if (res == -1)
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
      SilcAttributeObjPk *pk = object;
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
