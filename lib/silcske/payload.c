/*

  payload.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcske_i.h"

/* Encodes Key Exchange Start Payload into a SILC Buffer to be sent
   to the other end. */

SilcSKEStatus silc_ske_payload_start_encode(SilcSKE ske,
					    SilcSKEStartPayload payload,
					    SilcBuffer *return_buffer)
{
  SilcBuffer buf;
  int ret;

  SILC_LOG_DEBUG(("Encoding KE Start Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  buf = silc_buffer_alloc_size(payload->len);
  if (!buf)
    return SILC_SKE_STATUS_OUT_OF_MEMORY;

  /* Encode the payload */
  ret = silc_buffer_format(buf,
			   SILC_STR_UI_CHAR(0),        /* RESERVED field */
			   SILC_STR_UI_CHAR(payload->flags),
			   SILC_STR_UI_SHORT(payload->len),
			   SILC_STR_UI_XNSTRING(payload->cookie,
						payload->cookie_len),
			   SILC_STR_UI_SHORT(payload->version_len),
			   SILC_STR_UI_XNSTRING(payload->version,
						payload->version_len),
			   SILC_STR_UI_SHORT(payload->ke_grp_len),
			   SILC_STR_UI_XNSTRING(payload->ke_grp_list,
						payload->ke_grp_len),
			   SILC_STR_UI_SHORT(payload->pkcs_alg_len),
			   SILC_STR_UI_XNSTRING(payload->pkcs_alg_list,
						payload->pkcs_alg_len),
			   SILC_STR_UI_SHORT(payload->enc_alg_len),
			   SILC_STR_UI_XNSTRING(payload->enc_alg_list,
						payload->enc_alg_len),
			   SILC_STR_UI_SHORT(payload->hash_alg_len),
			   SILC_STR_UI_XNSTRING(payload->hash_alg_list,
						payload->hash_alg_len),
			   SILC_STR_UI_SHORT(payload->hmac_alg_len),
			   SILC_STR_UI_XNSTRING(payload->hmac_alg_list,
						payload->hmac_alg_len),
			   SILC_STR_UI_SHORT(payload->comp_alg_len),
			   SILC_STR_UI_XNSTRING(payload->comp_alg_list,
						payload->comp_alg_len),
			   SILC_STR_END);
  if (ret == -1) {
    silc_buffer_free(buf);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Return the encoded buffer */
  *return_buffer = buf;

  SILC_LOG_HEXDUMP(("KE Start Payload"), buf->data, silc_buffer_len(buf));

  return SILC_SKE_STATUS_OK;
}

/* Parses the Key Exchange Start Payload. Parsed data is returned
   to allocated payload structure. */

SilcSKEStatus
silc_ske_payload_start_decode(SilcSKE ske,
			      SilcBuffer buffer,
			      SilcSKEStartPayload *return_payload)
{
  SilcSKEStartPayload payload;
  SilcSKEStatus status = SILC_SKE_STATUS_ERROR;
  unsigned char tmp;
  int ret;

  SILC_LOG_DEBUG(("Decoding Key Exchange Start Payload"));

  SILC_LOG_HEXDUMP(("KE Start Payload"), buffer->data,
		   silc_buffer_len(buffer));

  payload = silc_calloc(1, sizeof(*payload));
  if (!payload)
    return SILC_SKE_STATUS_OUT_OF_MEMORY;
  payload->cookie_len = SILC_SKE_COOKIE_LEN;

  /* Parse start of the payload */
  ret =
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_CHAR(&tmp),     /* RESERVED Field */
			 SILC_STR_UI_CHAR(&payload->flags),
			 SILC_STR_UI_SHORT(&payload->len),
			 SILC_STR_UI_XNSTRING_ALLOC(&payload->cookie,
						    payload->cookie_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->version,
						     &payload->version_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->ke_grp_list,
						     &payload->ke_grp_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->pkcs_alg_list,
						     &payload->pkcs_alg_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->enc_alg_list,
						     &payload->enc_alg_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->hash_alg_list,
						     &payload->hash_alg_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->hmac_alg_list,
						     &payload->hmac_alg_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&payload->comp_alg_list,
						     &payload->comp_alg_len),
			 SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed KE Start Payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (tmp != 0) {
    SILC_LOG_ERROR(("Bad RESERVED field in KE Start Payload"));
    status = SILC_SKE_STATUS_BAD_RESERVED_FIELD;
    goto err;
  }

  if (payload->len != silc_buffer_len(buffer)) {
    SILC_LOG_ERROR(("Garbage after KE Start Payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  /* Check for mandatory fields */
  if (!payload->cookie || !payload->version_len ||
      !payload->ke_grp_len || !payload->pkcs_alg_len ||
      !payload->enc_alg_len || !payload->hash_alg_len ||
      !payload->hmac_alg_len) {
    SILC_LOG_ERROR(("KE Start Payload is missing mandatory fields"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_ske_payload_start_free(payload);

  ske->status = status;
  return status;
}

/* Free's Start Payload */

void silc_ske_payload_start_free(SilcSKEStartPayload payload)
{
  if (payload) {
    silc_free(payload->cookie);
    silc_free(payload->version);
    silc_free(payload->ke_grp_list);
    silc_free(payload->pkcs_alg_list);
    silc_free(payload->enc_alg_list);
    silc_free(payload->hash_alg_list);
    silc_free(payload->hmac_alg_list);
    silc_free(payload->comp_alg_list);
    silc_free(payload);
  }
}

/* Encodes Key Exchange Payload into a SILC Buffer to be sent to the other
   end. */

SilcSKEStatus silc_ske_payload_ke_encode(SilcSKE ske,
					 SilcSKEKEPayload payload,
					 SilcBuffer *return_buffer)
{
  SilcBuffer buf;
  unsigned char *x_str;
  SilcUInt32 x_len;
  int ret;

  SILC_LOG_DEBUG(("Encoding KE Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  if (ske->start_payload &&
      ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL &&
      !payload->sign_data) {
    SILC_LOG_DEBUG(("Signature data is missing"));
    return SILC_SKE_STATUS_ERROR;
  }

  /* Encode the integer into binary data */
  x_str = silc_mp_mp2bin(&payload->x, 0, &x_len);

  /* Allocate channel payload buffer. The length of the buffer
     is 4 + public key + 2 + x + 2 + signature. */
  buf = silc_buffer_alloc_size(4 + payload->pk_len + 2 + x_len +
			       2 + payload->sign_len);
  if (!buf)
    return SILC_SKE_STATUS_OUT_OF_MEMORY;

  /* Encode the payload */
  ret = silc_buffer_format(buf,
			   SILC_STR_UI_SHORT(payload->pk_len),
			   SILC_STR_UI_SHORT(payload->pk_type),
			   SILC_STR_UI_XNSTRING(payload->pk_data,
						payload->pk_len),
			   SILC_STR_UI_SHORT(x_len),
			   SILC_STR_UI_XNSTRING(x_str, x_len),
			   SILC_STR_UI_SHORT(payload->sign_len),
			   SILC_STR_UI_XNSTRING(payload->sign_data,
						payload->sign_len),
			   SILC_STR_END);
  if (ret == -1) {
    memset(x_str, 'F', x_len);
    silc_free(x_str);
    silc_buffer_free(buf);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Return encoded buffer */
  *return_buffer = buf;

  SILC_LOG_HEXDUMP(("KE Payload"), buf->data, silc_buffer_len(buf));

  memset(x_str, 'F', x_len);
  silc_free(x_str);

  return SILC_SKE_STATUS_OK;
}

/* Parses the Key Exchange Payload. Parsed data is returned to allocated
   payload structure. */

SilcSKEStatus silc_ske_payload_ke_decode(SilcSKE ske,
					 SilcBuffer buffer,
					 SilcSKEKEPayload *return_payload)
{
  SilcSKEStatus status = SILC_SKE_STATUS_ERROR;
  SilcSKEKEPayload payload;
  unsigned char *x = NULL;
  SilcUInt16 x_len;
  SilcUInt32 tot_len = 0, len2;
  int ret;

  SILC_LOG_DEBUG(("Decoding Key Exchange Payload"));

  SILC_LOG_HEXDUMP(("KE Payload"), buffer->data, silc_buffer_len(buffer));

  payload = silc_calloc(1, sizeof(*payload));
  if (!payload)
    return SILC_SKE_STATUS_OUT_OF_MEMORY;

  len2 = silc_buffer_len(buffer);

  /* Parse start of the payload */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&payload->pk_len),
			     SILC_STR_UI_SHORT(&payload->pk_type),
			     SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_ERROR(("Cannot decode public key from KE payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (ske->start_payload &&
      ((payload->pk_type < SILC_SKE_PK_TYPE_SILC ||
	payload->pk_type > SILC_SKE_PK_TYPE_SPKI) || !payload->pk_len)) {
    SILC_LOG_ERROR(("Malformed public key in KE payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  tot_len += payload->pk_len + 4;

  /* Parse PK data and the signature */
  silc_buffer_pull(buffer, 4);
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&payload->pk_data,
							payload->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&x, &x_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&payload->sign_data,
							 &payload->sign_len),
			     SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed KE Payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  tot_len += x_len + 2;
  tot_len += payload->sign_len + 2;

  if (x_len < 16) {
    SILC_LOG_ERROR(("Too short DH value in KE Payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (ske->start_payload &&
      (ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) &&
      (payload->sign_len < 3 || !payload->sign_data)) {
    SILC_LOG_ERROR(("The signature data is missing - both parties are "
		    "required to do authentication"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (tot_len != len2) {
    SILC_LOG_ERROR(("Garbage after KE payload"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  /* Decode the binary data to integer */
  silc_mp_init(&payload->x);
  silc_mp_bin2mp(x, x_len, &payload->x);
  memset(x, 0, sizeof(x_len));
  silc_free(x);

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_free(payload->pk_data);
  silc_free(payload->sign_data);
  silc_free(x);
  silc_free(payload);
  ske->status = status;
  return status;
}

/* Free's KE Payload */

void silc_ske_payload_ke_free(SilcSKEKEPayload payload)
{
  if (payload) {
    silc_free(payload->pk_data);
    silc_mp_uninit(&payload->x);
    silc_free(payload->sign_data);
    silc_free(payload);
  }
}
