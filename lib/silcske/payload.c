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
/* XXX TODO: This is not optimized version and should be optimized! 
   Use *_ALLOC buffer formatting in payload decodings! */
/*
 * $Id$
 * $Log$
 * Revision 1.2  2000/07/05 06:05:15  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "payload_internal.h"

/* Temporary buffer used in payload decoding */
unsigned char buf[16384];

/* Encodes Key Exchange Start Payload into a SILC Buffer to be sent
   to the other end. */

SilcSKEStatus silc_ske_payload_start_encode(SilcSKE ske,
					    SilcSKEStartPayload *payload,
					    SilcBuffer *return_buffer)
{
  SilcBuffer buf;

  SILC_LOG_DEBUG(("Encoding KE Start Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  /* Allocate channel payload buffer. */
  buf = silc_buffer_alloc(payload->len);

  silc_buffer_pull_tail(buf, payload->len);

  /* Encode the payload */
  silc_buffer_format(buf,
		     SILC_STR_UI_CHAR(0),        /* RESERVED field */
		     SILC_STR_UI_CHAR(payload->flags),
		     SILC_STR_UI_SHORT(payload->len),
		     SILC_STR_UI_XNSTRING(payload->cookie, 
					  payload->cookie_len),
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
  int len, len2;

  SILC_LOG_DEBUG(("Decoding Key Exchange Start Payload"));

  SILC_LOG_HEXDUMP(("KE Start Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));
  memset(buf, 0, sizeof(buf));

  /* Parse the entire payload */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_CHAR(&tmp),     /* RESERVED Field */
		       SILC_STR_UI_CHAR(&payload->flags),
		       SILC_STR_UI_SHORT(&payload->len),
		       SILC_STR_UI_XNSTRING(&buf, SILC_SKE_COOKIE_LEN),
		       SILC_STR_UI_SHORT(&payload->ke_grp_len),
		       SILC_STR_END);

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

  len2 = len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN + 2;
  silc_buffer_pull(buffer, len);

  /* Copy cookie from payload */
  payload->cookie = silc_calloc(SILC_SKE_COOKIE_LEN, 
				sizeof(unsigned char));
  payload->cookie_len = SILC_SKE_COOKIE_LEN;
  memcpy(payload->cookie, buf, SILC_SKE_COOKIE_LEN);
  memset(buf, 0, sizeof(buf));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->ke_grp_len),
		       SILC_STR_UI_SHORT(&payload->pkcs_alg_len),
		       SILC_STR_END);

  if (payload->pkcs_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->ke_grp_len + 2;
  silc_buffer_pull(buffer, len);

  /* Copy KE groups from payload */
  payload->ke_grp_list = silc_calloc(payload->ke_grp_len + 1, 
				     sizeof(unsigned char));
  memcpy(payload->ke_grp_list, buf, payload->ke_grp_len);
  memset(buf, 0, sizeof(buf));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->pkcs_alg_len),
		       SILC_STR_UI_SHORT(&payload->enc_alg_len),
		       SILC_STR_END);

  if (payload->enc_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->pkcs_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Copy PKCS algs from payload */
  payload->pkcs_alg_list = silc_calloc(payload->pkcs_alg_len + 1, 
				       sizeof(unsigned char));
  memcpy(payload->pkcs_alg_list, buf, payload->pkcs_alg_len);
  memset(buf, 0, sizeof(buf));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->enc_alg_len),
		       SILC_STR_UI_SHORT(&payload->hash_alg_len),
		       SILC_STR_END);

  if (payload->hash_alg_len < 1) {
    SILC_LOG_DEBUG(("Bad payload length"));
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  len2 += len = payload->enc_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Copy encryption algs from payload */
  payload->enc_alg_list = silc_calloc(payload->enc_alg_len + 1, 
				      sizeof(unsigned char));
  memcpy(payload->enc_alg_list, buf, payload->enc_alg_len);
  memset(buf, 0, sizeof(buf));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->hash_alg_len),
		       SILC_STR_UI_SHORT(&payload->comp_alg_len),
		       SILC_STR_END);

  len2 += len = payload->hash_alg_len + 2;
  silc_buffer_pull(buffer, len);

  /* Copy hash algs from payload */
  payload->hash_alg_list = silc_calloc(payload->hash_alg_len + 1, 
				       sizeof(unsigned char));
  memcpy(payload->hash_alg_list, buf, payload->hash_alg_len);
  memset(buf, 0, sizeof(buf));

  if (payload->comp_alg_len) {
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_XNSTRING(&buf, payload->comp_alg_len),
			 SILC_STR_END);

    /* Copy compression algs from payload */
    payload->comp_alg_list = silc_calloc(payload->comp_alg_len + 1, 
					 sizeof(unsigned char));
    memcpy(payload->comp_alg_list, buf, payload->comp_alg_len);
    memset(buf, 0, sizeof(buf));
  }

  silc_buffer_push(buffer, len2);

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_ske_payload_start_free(payload);

  return status;
}

/* Free's Start Payload */

void silc_ske_payload_start_free(SilcSKEStartPayload *payload)
{
  if (payload) {
    if (payload->cookie)
      silc_free(payload->cookie);
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
  unsigned short e_len;

  SILC_LOG_DEBUG(("Encoding KE 1 Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  /* Encode the integer into HEX string */
  e_len = silc_mp_sizeinbase(&payload->e, 16);
  e_str = silc_calloc(e_len + 1, sizeof(unsigned char));
  silc_mp_get_str(e_str, 16, &payload->e);

  /* Allocate channel payload buffer. The length of the buffer
     is 2 + e. */
  buf = silc_buffer_alloc(e_len + 2);

  silc_buffer_pull_tail(buf, e_len + 2);

  /* Encode the payload */
  silc_buffer_format(buf, 
		     SILC_STR_UI_SHORT(e_len + 2),
		     SILC_STR_UI_XNSTRING(e_str, e_len),
		     SILC_STR_END);

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
  unsigned short e_len;

  SILC_LOG_DEBUG(("Decoding Key Exchange 1 Payload"));

  SILC_LOG_HEXDUMP(("KE 1 Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));

  memset(buf, 0, sizeof(buf));

  /* Parse the payload */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&e_len),
		       SILC_STR_END);
		       
  if (e_len < 1) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  if (e_len != buffer->len) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  /* Length includes the length field length as well. Remove it. */
  e_len -= 2;

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(NULL),
		       SILC_STR_UI_XNSTRING(&buf, e_len),
		       SILC_STR_END);

  /* Decode the HEX string to integer */
  silc_mp_init(&payload->e);
  silc_mp_set_str(&payload->e, buf, 16);
  memset(buf, 0, sizeof(buf));

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  silc_free(payload);

  return status;
}

/* Free's KE1 Payload */

void silc_ske_payload_one_free(SilcSKEOnePayload *payload)
{
  if (payload) {
    silc_mp_clear(&payload->e);
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

  SILC_LOG_DEBUG(("Encoding KE 2 Payload"));

  if (!payload)
    return SILC_SKE_STATUS_ERROR;

  /* Encode the integer into HEX string */
  f_len = silc_mp_sizeinbase(&payload->f, 16);
  f_str = silc_calloc(f_len + 1, sizeof(unsigned char));
  silc_mp_get_str(f_str, 16, &payload->f);

  /* Allocate channel payload buffer. The length of the buffer
     is 2 + 2 + public key + 2 + f + 2 + signature. */
  len = payload->pk_len + 2 + 2 + f_len + 2 + payload->sign_len + 2;
  buf = silc_buffer_alloc(len);

  silc_buffer_pull_tail(buf, len);

  /* Encode the payload */
  silc_buffer_format(buf, 
		     SILC_STR_UI_SHORT(payload->pk_len + 4),
		     SILC_STR_UI_SHORT(payload->pk_type),
		     SILC_STR_UI_XNSTRING(payload->pk_data, 
					  payload->pk_len),
		     SILC_STR_UI_SHORT(f_len + 2),
		     SILC_STR_UI_XNSTRING(f_str, f_len),
		     SILC_STR_UI_SHORT(payload->sign_len + 2),
		     SILC_STR_UI_XNSTRING(payload->sign_data, 
					  payload->sign_len),
		     SILC_STR_END);

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
  unsigned short f_len;
  unsigned int tot_len = 0, len2;

  SILC_LOG_DEBUG(("Decoding Key Exchange 2 Payload"));

  SILC_LOG_HEXDUMP(("KE 2 Payload"), buffer->data, buffer->len);

  payload = silc_calloc(1, sizeof(*payload));
  memset(buf, 0, sizeof(buf));

  len2 = buffer->len;

  /* Parse the payload */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&payload->pk_len),
		       SILC_STR_UI_SHORT(&payload->pk_type),
		       SILC_STR_END);

  if (payload->pk_len < 5) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  tot_len += payload->pk_len;

  payload->pk_len -= 4;
  silc_buffer_pull(buffer, 4);
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->pk_len),
		       SILC_STR_UI_SHORT(&f_len),
		       SILC_STR_END);

  if (f_len < 3) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  tot_len += f_len;

  payload->pk_data = silc_calloc(payload->pk_len + 1, 
				 sizeof(unsigned char));
  memcpy(payload->pk_data, buf, payload->pk_len);
  memset(buf, 0, sizeof(buf));

  f_len -= 2;
  silc_buffer_pull(buffer, payload->pk_len + 2);
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, f_len),
		       SILC_STR_UI_SHORT(&payload->sign_len),
		       SILC_STR_END);

  if (payload->sign_len < 3) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }

  tot_len += payload->sign_len;

  if (tot_len != len2) {
    status = SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH;
    goto err;
  }
  
  /* Decode the HEX string to integer */
  silc_mp_init(&payload->f);
  silc_mp_set_str(&payload->f, buf, 16);
  memset(buf, 0, sizeof(buf));

  payload->sign_len -= 2;
  silc_buffer_pull(buffer, f_len + 2);
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING(&buf, payload->sign_len),
		       SILC_STR_END);

  payload->sign_data = silc_calloc(payload->sign_len + 1, 
				 sizeof(unsigned char));
  memcpy(payload->sign_data, buf, payload->sign_len);
  memset(buf, 0, sizeof(buf));

  /* Return the payload */
  *return_payload = payload;

  return SILC_SKE_STATUS_OK;

 err:
  if (payload->pk_data)
    silc_free(payload->pk_data);
  if (payload->sign_data)
    silc_free(payload->sign_data);
  silc_free(payload);

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
    silc_mp_clear(&payload->f);
    silc_free(payload);
  }
}
