/*

  payload.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "payload_internal.h"

/* Encodes Key Exchange Start Payload into a SILC Buffer to be sent
   to the other end. */

SilcSKEStatus silc_ske_payload_start_encode(SilcSKE ske,
					    SilcSKEStartPayload *payload,
					    SilcBuffer *return_buffer)
{
  SilcBuffer buf;
  int ret;

  SILC_LOG_DEBUG(("Encoding KE Start Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  buf = silc_buffer_alloc(payload->len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

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

  SILC_LOG_HEXDUMP(("KE Start Payload"), buf->data, buf->len);

  return SILC_SKE_STATUS_OK;
}

/* Parses the Key Exchange Start Payload. Parsed data is returned
   to allocated payload structure. */

SilcSKEStatus 
silc_ske_payload_start_decode(SilcSKE ske,
			      SilcBuffer buffer,
			      SilcSKEStartPayload **return_payload)
{
  SilcSKEStartPayload *payload;
  SilcSKEStatus status = SILC_SKE_STATUS_ERROR;
  unsigned char tmp;
  int ret, len, len2;

  SILC_LOG_DEBUG(("Decoding Key Exchange Start Payload"));

  SILC_LOG_HEXDUMP(("KE Start Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));
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
			 SILC_STR_UI_SHORT(&payload->ke_grp_len),
			 SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (tmp != 0) {
    SILC_LOG_DEBUG(("Bad reserved field"));
    status = SILC_SKE_STATUS_BAD_RESERVED_FIELD;
    goto err;
  }

  if (payload->len != buffer->len) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  if (payload->ke_grp_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 = len = 1 + 1 + 2 + payload->cookie_len + 2 + payload->version_len + 2;
  silc_buffer_pull(buffer, len);

  /* Parse group list */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&payload->ke_grp_list, 
							payload->ke_grp_len),
			     SILC_STR_UI_SHORT(&payload->pkcs_alg_len),
			     SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (payload->pkcs_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->ke_grp_len + 2;
  silc_buffer_pull(buffer, len);

  /* Parse PKCS alg list */
  ret = 
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_XNSTRING_ALLOC(&payload->pkcs_alg_list, 
						    payload->pkcs_alg_len),
			 SILC_STR_UI_SHORT(&payload->enc_alg_len),
			 SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (payload->enc_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->pkcs_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Parse encryption alg list */
  ret = 
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_XNSTRING_ALLOC(&payload->enc_alg_list, 
						    payload->enc_alg_len),
			 SILC_STR_UI_SHORT(&payload->hash_alg_len),
			 SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (payload->hash_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->enc_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Parse hash alg list */
  ret = 
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_XNSTRING_ALLOC(&payload->hash_alg_list, 
						    payload->hash_alg_len),
			 SILC_STR_UI_SHORT(&payload->comp_alg_len),
			 SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  len2 += len = payload->hash_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Parse compression alg list */
  if (payload->comp_alg_len) {
    ret = 
      silc_buffer_unformat(buffer,
			   SILC_STR_UI_XNSTRING_ALLOC(&payload->comp_alg_list, 
						      payload->comp_alg_len),
			   SILC_STR_END);
    if (ret == -1) {
      status = SILC_SKE_STATUS_ERROR;
      goto err;
    }
  }

  silc_buffer_push(buffer, len2);

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_ske_payload_start_free(payload);

  ske->status = status;
  return status;
}

/* Free's Start Payload */

void silc_ske_payload_start_free(SilcSKEStartPayload *payload)
{
  if (payload) {
    if (payload->cookie)
      silc_free(payload->cookie);
    if (payload->version)
      silc_free(payload->version);
    if (payload->ke_grp_list)
      silc_free(payload->ke_grp_list);
    if (payload->pkcs_alg_list)
      silc_free(payload->pkcs_alg_list);
    if (payload->enc_alg_list)
      silc_free(payload->enc_alg_list);
    if (payload->hash_alg_list)
      silc_free(payload->hash_alg_list);
    if (payload->comp_alg_list)
      silc_free(payload->comp_alg_list);
    silc_free(payload);
  }
}

/* Encodes Key Exchange 1 Payload into a SILC Buffer to be sent
   to the other end. */

SilcSKEStatus silc_ske_payload_one_encode(SilcSKE ske,
					  SilcSKEOnePayload *payload,
					  SilcBuffer *return_buffer)
{
  SilcBuffer buf;
  unsigned char *e_str;
  unsigned int e_len;
  int ret;

  SILC_LOG_DEBUG(("Encoding KE 1 Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  /* Encode the integer into binary data */
  e_str = silc_mp_mp2bin(&payload->e, 0, &e_len);
  if (!e_str)
    return SILC_SKE_STATUS_ERROR;

  /* Allocate channel payload buffer. The length of the buffer
     is 2 + e. */
  buf = silc_buffer_alloc(e_len + 2 + payload->pk_len + 2 + 2);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  /* Encode the payload */
  ret = silc_buffer_format(buf, 
			   SILC_STR_UI_SHORT(payload->pk_len),
			   SILC_STR_UI_SHORT(payload->pk_type),
			   SILC_STR_UI_XNSTRING(payload->pk_data, 
						payload->pk_len),
			   SILC_STR_UI_SHORT(e_len),
			   SILC_STR_UI_XNSTRING(e_str, e_len),
			   SILC_STR_END);
  if (ret == -1) {
    memset(e_str, 'F', e_len);
    silc_free(e_str);
    silc_buffer_free(buf);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Return encoded buffer */
  *return_buffer = buf;

  memset(e_str, 'F', e_len);
  silc_free(e_str);

  return SILC_SKE_STATUS_OK;
}

/* Parses the Key Exchange 1 Payload. Parsed data is returned
   to allocated payload structure. */

SilcSKEStatus silc_ske_payload_one_decode(SilcSKE ske,
					  SilcBuffer buffer,
					  SilcSKEOnePayload **return_payload)
{
  SilcSKEOnePayload *payload;
  SilcSKEStatus status = SILC_SKE_STATUS_ERROR;
  unsigned char *e;
  unsigned short e_len;
  int ret;

  SILC_LOG_DEBUG(("Decoding Key Exchange 1 Payload"));

  SILC_LOG_HEXDUMP(("KE 1 Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));

  /* Parse start of the payload */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&payload->pk_len),
			     SILC_STR_UI_SHORT(&payload->pk_type),
			     SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }
		       
  if (payload->pk_len < 5) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  /* Parse public key data */
  silc_buffer_pull(buffer, 2 + 2);
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&payload->pk_data,
							payload->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&e, &e_len),
			     SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (e_len < 3) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  silc_buffer_push(buffer, 2 + 2);

  if (payload->pk_len + 2 + 2 + 2 + e_len != buffer->len) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  /* Decode the HEX string to integer */
  silc_mp_init(&payload->e);
  silc_mp_bin2mp(e, e_len, &payload->e);
  memset(e, 0, sizeof(e_len));
  silc_free(e);

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_free(payload);
  ske->status = status;
  return status;
}

/* Free's KE1 Payload */

void silc_ske_payload_one_free(SilcSKEOnePayload *payload)
{
  if (payload) {
    if (payload->pk_data)
      silc_free(payload->pk_data);
    silc_free(payload);
  }
}

/* Encodes Key Exchange 2 Payload into a SILC Buffer to be sent
   to the other end. */

SilcSKEStatus silc_ske_payload_two_encode(SilcSKE ske,
					  SilcSKETwoPayload *payload,
					  SilcBuffer *return_buffer)
{
  SilcBuffer buf;
  unsigned char *f_str;
  unsigned int f_len;
  unsigned int len;
  int ret;

  SILC_LOG_DEBUG(("Encoding KE 2 Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  /* Encode the integer into HEX string */
  f_str = silc_mp_mp2bin(&payload->f, 0, &f_len);

  /* Allocate channel payload buffer. The length of the buffer
     is 2 + 2 + public key + 2 + f + 2 + signature. */
  len = payload->pk_len + 2 + 2 + f_len + 2 + payload->sign_len + 2;
  buf = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  /* Encode the payload */
  ret = silc_buffer_format(buf, 
			   SILC_STR_UI_SHORT(payload->pk_len),
			   SILC_STR_UI_SHORT(payload->pk_type),
			   SILC_STR_UI_XNSTRING(payload->pk_data, 
						payload->pk_len),
			   SILC_STR_UI_SHORT(f_len),
			   SILC_STR_UI_XNSTRING(f_str, f_len),
			   SILC_STR_UI_SHORT(payload->sign_len),
			   SILC_STR_UI_XNSTRING(payload->sign_data, 
						payload->sign_len),
			   SILC_STR_END);
  if (ret == -1) {
    memset(f_str, 'F', f_len);
    silc_free(f_str);
    silc_buffer_free(buf);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Return encoded buffer */
  *return_buffer = buf;

  memset(f_str, 'F', f_len);
  silc_free(f_str);

  return SILC_SKE_STATUS_OK;
}

/* Parses the Key Exchange 2 Payload. Parsed data is returned
   to allocated payload structure. */

SilcSKEStatus silc_ske_payload_two_decode(SilcSKE ske,
					  SilcBuffer buffer,
					  SilcSKETwoPayload **return_payload)
{
  SilcSKEStatus status = SILC_SKE_STATUS_ERROR;
  SilcSKETwoPayload *payload;
  unsigned char *f;
  unsigned short f_len;
  unsigned int tot_len = 0, len2;
  int ret;

  SILC_LOG_DEBUG(("Decoding Key Exchange 2 Payload"));

  SILC_LOG_HEXDUMP(("KE 2 Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));

  len2 = buffer->len;

  /* Parse start of the payload */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&payload->pk_len),
			     SILC_STR_UI_SHORT(&payload->pk_type),
			     SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  if (payload->pk_len < 5) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  tot_len += payload->pk_len + 4;

  /* Parse PK data and the signature */
  silc_buffer_pull(buffer, 4);
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&payload->pk_data,
							payload->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&f, &f_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&payload->sign_data, 
							 &payload->sign_len),
			     SILC_STR_END);
  if (ret == -1) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  tot_len += f_len + 2;
  tot_len += payload->sign_len + 2;

  if (f_len < 3) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (payload->sign_len < 3) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }

  if (tot_len != len2) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD;
    goto err;
  }
  
  /* Decode the HEX string to integer */
  silc_mp_init(&payload->f);
  silc_mp_bin2mp(f, f_len, &payload->f);
  memset(f, 0, sizeof(f_len));
  silc_free(f);

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  if (payload->pk_data)
    silc_free(payload->pk_data);
  if (payload->sign_data)
    silc_free(payload->sign_data);
  silc_free(payload);
  ske->status = status;
  return status;
}

/* Free's KE2 Payload */

void silc_ske_payload_two_free(SilcSKETwoPayload *payload)
{
  if (payload) {
    if (payload->pk_data)
      silc_free(payload->pk_data);
    if (payload->sign_data)
      silc_free(payload->sign_data);
    silc_free(payload);
  }
}
