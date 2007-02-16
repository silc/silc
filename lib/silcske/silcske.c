/*

  silcske.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2007 Pekka Riikonen

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
#include "silcske.h"
#include "groups_internal.h"

/************************** Types and definitions ***************************/

/* Structure to hold all SKE callbacks. */
struct SilcSKECallbacksStruct {
  SilcSKEVerifyCb verify_key;
  SilcSKECompletionCb completed;
  void *context;
};

/************************ Static utility functions **************************/

/* States */
SILC_FSM_STATE(silc_ske_st_initiator_start);
SILC_FSM_STATE(silc_ske_st_initiator_phase1);
SILC_FSM_STATE(silc_ske_st_initiator_phase2);
SILC_FSM_STATE(silc_ske_st_initiator_phase3);
SILC_FSM_STATE(silc_ske_st_initiator_phase4);
SILC_FSM_STATE(silc_ske_st_initiator_end);
SILC_FSM_STATE(silc_ske_st_initiator_aborted);
SILC_FSM_STATE(silc_ske_st_initiator_error);
SILC_FSM_STATE(silc_ske_st_initiator_failure);
SILC_FSM_STATE(silc_ske_st_responder_start);
SILC_FSM_STATE(silc_ske_st_responder_phase1);
SILC_FSM_STATE(silc_ske_st_responder_phase2);
SILC_FSM_STATE(silc_ske_st_responder_phase4);
SILC_FSM_STATE(silc_ske_st_responder_phase5);
SILC_FSM_STATE(silc_ske_st_responder_end);
SILC_FSM_STATE(silc_ske_st_responder_aborted);
SILC_FSM_STATE(silc_ske_st_responder_failure);
SILC_FSM_STATE(silc_ske_st_responder_error);
SILC_FSM_STATE(silc_ske_st_rekey_initiator_start);
SILC_FSM_STATE(silc_ske_st_rekey_initiator_done);
SILC_FSM_STATE(silc_ske_st_rekey_initiator_end);
SILC_TASK_CALLBACK(silc_ske_packet_send_retry);

SilcSKEKeyMaterial
silc_ske_process_key_material(SilcSKE ske,
			      SilcUInt32 req_iv_len,
			      SilcUInt32 req_enc_key_len,
			      SilcUInt32 req_hmac_key_len,
			      SilcSKERekeyMaterial *rekey);
static SilcBool silc_ske_packet_send(SilcSKE ske,
				     SilcPacketType type,
				     SilcPacketFlags flags,
				     const unsigned char *data,
				     SilcUInt32 data_len);

/* Packet callback */

static SilcBool silc_ske_packet_receive(SilcPacketEngine engine,
					SilcPacketStream stream,
					SilcPacket packet,
					void *callback_context,
					void *app_context)
{
  SilcSKE ske = callback_context;

  /* Clear retransmission */
  ske->retry_timer = SILC_SKE_RETRY_MIN;
  ske->retry_count = 0;
  silc_schedule_task_del_by_callback(ske->schedule,
				     silc_ske_packet_send_retry);

  /* Signal for new packet */
  ske->packet = packet;

  /* Check if we were aborted */
  if (ske->aborted) {
    silc_packet_free(packet);
    ske->packet = NULL;

    if (ske->responder)
      silc_fsm_next(&ske->fsm, silc_ske_st_responder_aborted);
    else
      silc_fsm_next(&ske->fsm, silc_ske_st_initiator_aborted);

    silc_fsm_continue_sync(&ske->fsm);
    return TRUE;
  }

  /* See if received failure from remote */
  if (packet->type == SILC_PACKET_FAILURE) {
    if (ske->responder)
      silc_fsm_next(&ske->fsm, silc_ske_st_responder_failure);
    else
      silc_fsm_next(&ske->fsm, silc_ske_st_initiator_failure);
  }

  /* Handle rekey and SUCCESS packets synchronously.  After SUCCESS packets
     they keys are taken into use immediately, hence the synchronous
     processing to get the keys in use as soon as possible. */
  if (ske->rekeying || packet->type == SILC_PACKET_SUCCESS)
    silc_fsm_continue_sync(&ske->fsm);
  else
    silc_fsm_continue(&ske->fsm);

  return TRUE;
}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_ske_stream_cbs =
{
  silc_ske_packet_receive, NULL, NULL
};

/* Aborts SKE protocol */

static void silc_ske_abort(SilcAsyncOperation op, void *context)
{
  SilcSKE ske = context;
  ske->aborted = TRUE;
}

/* Public key verification completion callback */

static void silc_ske_pk_verified(SilcSKE ske, SilcSKEStatus status,
				 void *completion_context)
{
  ske->status = status;
  SILC_FSM_CALL_CONTINUE(&ske->fsm);
}

/* SKR find callback */

static void silc_ske_skr_callback(SilcSKR repository,
				  SilcSKRFind find,
				  SilcSKRStatus status,
				  SilcDList keys, void *context)
{
  SilcSKE ske = context;

  silc_skr_find_free(find);

  if (status != SILC_SKR_OK) {
    if (ske->callbacks->verify_key) {
      /* Verify from application */
      ske->callbacks->verify_key(ske, ske->prop->public_key,
				 ske->callbacks->context,
				 silc_ske_pk_verified, NULL);
      return;
    }
  }

  if (keys)
    silc_dlist_uninit(keys);

  /* Continue */
  ske->status = (status == SILC_SKR_OK ? SILC_SKE_STATUS_OK :
		 SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY);
  SILC_FSM_CALL_CONTINUE(&ske->fsm);
}

/* Checks remote and local versions */

static SilcSKEStatus silc_ske_check_version(SilcSKE ske)
{
  SilcUInt32 r_software_version = 0;

  if (!ske->remote_version || !ske->version)
    return SILC_SKE_STATUS_BAD_VERSION;

  if (!silc_parse_version_string(ske->remote_version, NULL, NULL,
				 &r_software_version, NULL, NULL))
    return SILC_SKE_STATUS_BAD_VERSION;

  /* Backwards compatibility checks */

  /* Old server versions requires "valid" looking Source ID in the SILC
     packets during initial key exchange.  All version before 1.1.0. */
  if (r_software_version < 110) {
    SilcClientID id;
    memset(&id, 0, sizeof(id));
    id.ip.data_len = 4;
    SILC_LOG_DEBUG(("Remote is old version, add dummy Source ID to packets"));
    silc_packet_set_ids(ske->stream, SILC_ID_CLIENT, &id, 0, NULL);
  }

  return SILC_SKE_STATUS_OK;
}

/* Selects the supported security properties from the initiator's Key
   Exchange Start Payload.  A responder function.  Saves our reply
   start payload to ske->start_payload. */

static SilcSKEStatus
silc_ske_select_security_properties(SilcSKE ske,
				    SilcSKEStartPayload remote_payload,
				    SilcSKESecurityProperties *prop)
{
  SilcSKEStatus status;
  SilcSKEStartPayload rp, payload;
  char *cp;
  int len;

  SILC_LOG_DEBUG(("Parsing KE Start Payload"));

  rp = remote_payload;

  /* Check for mandatory fields */
  if (!rp->ke_grp_len) {
    SILC_LOG_DEBUG(("KE group not defined in payload"));
    return SILC_SKE_STATUS_BAD_PAYLOAD;
  }
  if (!rp->pkcs_alg_len) {
    SILC_LOG_DEBUG(("PKCS alg not defined in payload"));
    return SILC_SKE_STATUS_BAD_PAYLOAD;
  }
  if (!rp->enc_alg_len) {
    SILC_LOG_DEBUG(("Encryption alg not defined in payload"));
    return SILC_SKE_STATUS_BAD_PAYLOAD;
  }
  if (!rp->hash_alg_len) {
    SILC_LOG_DEBUG(("Hash alg not defined in payload"));
    return SILC_SKE_STATUS_BAD_PAYLOAD;
  }
  if (!rp->hmac_alg_len) {
    SILC_LOG_DEBUG(("HMAC not defined in payload"));
    return SILC_SKE_STATUS_BAD_PAYLOAD;
  }

  /* Allocate security properties */
  *prop = silc_calloc(1, sizeof(**prop));
  if (!(*prop))
    return SILC_SKE_STATUS_OUT_OF_MEMORY;

  /* Allocate our reply start payload */
  payload = silc_calloc(1, sizeof(*payload));
  if (!payload) {
    silc_free(*prop);
    return SILC_SKE_STATUS_OUT_OF_MEMORY;
  }

  /* Check version string */
  ske->remote_version = silc_memdup(rp->version, rp->version_len);
  status = silc_ske_check_version(ske);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  /* Flags are returned unchanged. */
  (*prop)->flags = payload->flags = rp->flags;

  /* Take cookie, we must return it to sender unmodified. */
  payload->cookie = silc_calloc(SILC_SKE_COOKIE_LEN, sizeof(unsigned char));
  if (!payload->cookie) {
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    return status;
  }
  payload->cookie_len = SILC_SKE_COOKIE_LEN;
  memcpy(payload->cookie, rp->cookie, SILC_SKE_COOKIE_LEN);

  /* In case IV included flag and session port is set the first 16-bits of
     cookie will include our session port. */
  if (rp->flags & SILC_SKE_SP_FLAG_IV_INCLUDED && ske->session_port) {
    /* Take remote port */
    SILC_GET16_MSB((*prop)->remote_port, payload->cookie);

    /* Put out port */
    SILC_PUT16_MSB(ske->session_port, payload->cookie);
  }

  /* Put our version to our reply */
  payload->version = strdup(ske->version);
  if (!payload->version) {
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    return status;
  }
  payload->version_len = strlen(ske->version);

  /* Get supported Key Exchange groups */
  cp = rp->ke_grp_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed KE group `%s'", item));

      if (silc_ske_group_get_by_name(item, NULL) == SILC_SKE_STATUS_OK) {
	SILC_LOG_DEBUG(("Found KE group `%s'", item));

	payload->ke_grp_len = len;
	payload->ke_grp_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->ke_grp_len && !payload->ke_grp_list) {
      SILC_LOG_DEBUG(("Could not find supported KE group"));
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_GROUP;
    }
  } else {
    SILC_LOG_DEBUG(("Proposed KE group `%s'", rp->ke_grp_list));
    SILC_LOG_DEBUG(("Found KE group `%s'", rp->ke_grp_list));

    payload->ke_grp_len = rp->ke_grp_len;
    payload->ke_grp_list = strdup(rp->ke_grp_list);
  }

  /* Save group to security properties */
  status = silc_ske_group_get_by_name(payload->ke_grp_list, &(*prop)->group);
  if (status != SILC_SKE_STATUS_OK) {
    silc_free(payload);
    return SILC_SKE_STATUS_UNKNOWN_GROUP;
  }

  /* Get supported PKCS algorithms */
  cp = rp->pkcs_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed PKCS alg `%s'", item));

      if (silc_pkcs_find_algorithm(item, NULL)) {
	SILC_LOG_DEBUG(("Found PKCS alg `%s'", item));

	payload->pkcs_alg_len = len;
	payload->pkcs_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->pkcs_alg_len && !payload->pkcs_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported PKCS alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_PKCS;
    }
  } else {
    SILC_LOG_DEBUG(("Proposed PKCS alg `%s'", rp->pkcs_alg_list));
    SILC_LOG_DEBUG(("Found PKCS alg `%s'", rp->pkcs_alg_list));

    payload->pkcs_alg_len = rp->pkcs_alg_len;
    payload->pkcs_alg_list = strdup(rp->pkcs_alg_list);
  }

  /* Get supported encryption algorithms */
  cp = rp->enc_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed encryption alg `%s'", item));

      if (silc_cipher_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found encryption alg `%s'", item));

	payload->enc_alg_len = len;
	payload->enc_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->enc_alg_len && !payload->enc_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported encryption alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_CIPHER;
    }
  } else {
    SILC_LOG_DEBUG(("Proposed encryption alg `%s' and selected it",
		    rp->enc_alg_list));

    payload->enc_alg_len = rp->enc_alg_len;
    payload->enc_alg_list = strdup(rp->enc_alg_list);
  }

  /* Save selected cipher to security properties */
  if (silc_cipher_alloc(payload->enc_alg_list, &(*prop)->cipher) == FALSE) {
    silc_free(payload->ke_grp_list);
    silc_free(payload->pkcs_alg_list);
    silc_free(payload);
    return SILC_SKE_STATUS_UNKNOWN_CIPHER;
  }

  /* Get supported hash algorithms */
  cp = rp->hash_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed hash alg `%s'", item));

      if (silc_hash_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found hash alg `%s'", item));

	payload->hash_alg_len = len;
	payload->hash_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->hash_alg_len && !payload->hash_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported hash alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
    }
  } else {
    SILC_LOG_DEBUG(("Proposed hash alg `%s' and selected it",
		    rp->hash_alg_list));

    payload->hash_alg_len = rp->hash_alg_len;
    payload->hash_alg_list = strdup(rp->hash_alg_list);
  }

  /* Save selected hash algorithm to security properties */
  if (silc_hash_alloc(payload->hash_alg_list, &(*prop)->hash) == FALSE) {
    silc_free(payload->ke_grp_list);
    silc_free(payload->pkcs_alg_list);
    silc_free(payload->enc_alg_list);
    silc_free(payload);
    return SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
  }

  /* Get supported HMACs */
  cp = rp->hmac_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed HMAC `%s'", item));

      if (silc_hmac_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found HMAC `%s'", item));

	payload->hmac_alg_len = len;
	payload->hmac_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->hmac_alg_len && !payload->hmac_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported HMAC"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload->hash_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_HMAC;
    }
  } else {
    SILC_LOG_DEBUG(("Proposed HMAC `%s' and selected it",
		    rp->hmac_alg_list));

    payload->hmac_alg_len = rp->hmac_alg_len;
    payload->hmac_alg_list = strdup(rp->hmac_alg_list);
  }

  /* Save selected HMACc to security properties */
  if (silc_hmac_alloc(payload->hmac_alg_list, NULL, &(*prop)->hmac) == FALSE) {
    silc_free(payload->ke_grp_list);
    silc_free(payload->pkcs_alg_list);
    silc_free(payload->enc_alg_list);
    silc_free(payload->hash_alg_list);
    silc_free(payload);
    return SILC_SKE_STATUS_UNKNOWN_HMAC;
  }

  /* Get supported compression algorithms */
  cp = rp->comp_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      if (!item) {
	ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	return status;
      }
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed Compression `%s'", item));

#if 1
      if (!strcmp(item, "none")) {
	SILC_LOG_DEBUG(("Found Compression `%s'", item));
	payload->comp_alg_len = len;
	payload->comp_alg_list = item;
	break;
      }
#else
      if (silc_hmac_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found Compression `%s'", item));
	payload->comp_alg_len = len;
	payload->comp_alg_list = item;
	break;
      }
#endif

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }
  }

  payload->len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN +
    2 + payload->version_len +
    2 + payload->ke_grp_len + 2 + payload->pkcs_alg_len +
    2 + payload->enc_alg_len + 2 + payload->hash_alg_len +
    2 + payload->hmac_alg_len + 2 + payload->comp_alg_len;

  /* Save our reply payload */
  ske->start_payload = payload;

  return SILC_SKE_STATUS_OK;
}

/* Creates random number such that 1 < rnd < n and at most length
   of len bits. The rnd sent as argument must be initialized. */

static SilcSKEStatus silc_ske_create_rnd(SilcSKE ske, SilcMPInt *n,
					 SilcUInt32 len,
					 SilcMPInt *rnd)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  unsigned char *string;
  SilcUInt32 l;

  if (!len)
    return SILC_SKE_STATUS_ERROR;

  SILC_LOG_DEBUG(("Creating random number"));

  l = ((len - 1) / 8);

  /* Get the random number as string */
  string = silc_rng_get_rn_data(ske->rng, l);
  if (!string)
    return SILC_SKE_STATUS_OUT_OF_MEMORY;

  /* Decode the string into a MP integer */
  silc_mp_bin2mp(string, l, rnd);
  silc_mp_mod_2exp(rnd, rnd, len);

  /* Checks */
  if (silc_mp_cmp_ui(rnd, 1) < 0)
    status = SILC_SKE_STATUS_ERROR;
  if (silc_mp_cmp(rnd, n) >= 0)
    status = SILC_SKE_STATUS_ERROR;

  memset(string, 'F', l);
  silc_free(string);

  return status;
}

/* Creates a hash value HASH as defined in the SKE protocol. If the
   `initiator' is TRUE then this function is used to create the HASH_i
   hash value defined in the protocol. If it is FALSE then this is used
   to create the HASH value defined by the protocol. */

static SilcSKEStatus silc_ske_make_hash(SilcSKE ske,
					unsigned char *return_hash,
					SilcUInt32 *return_hash_len,
					int initiator)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer buf;
  unsigned char *e, *f, *KEY;
  SilcUInt32 e_len, f_len, KEY_len;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  if (initiator == FALSE) {
    e = silc_mp_mp2bin(&ske->ke1_payload->x, 0, &e_len);
    f = silc_mp_mp2bin(&ske->ke2_payload->x, 0, &f_len);
    KEY = silc_mp_mp2bin(ske->KEY, 0, &KEY_len);

    /* Format the buffer used to compute the hash value */
    buf = silc_buffer_alloc_size(silc_buffer_len(ske->start_payload_copy) +
				 ske->ke2_payload->pk_len +
				 ske->ke1_payload->pk_len +
				 e_len + f_len + KEY_len);
    if (!buf)
      return SILC_SKE_STATUS_OUT_OF_MEMORY;

    /* Initiator is not required to send its public key */
    if (!ske->ke1_payload->pk_data) {
      ret =
	silc_buffer_format(buf,
			   SILC_STR_UI_XNSTRING(
				   ske->start_payload_copy->data,
				   silc_buffer_len(ske->start_payload_copy)),
			   SILC_STR_UI_XNSTRING(ske->ke2_payload->pk_data,
						ske->ke2_payload->pk_len),
			   SILC_STR_UI_XNSTRING(e, e_len),
			   SILC_STR_UI_XNSTRING(f, f_len),
			   SILC_STR_UI_XNSTRING(KEY, KEY_len),
			   SILC_STR_END);
    } else {
      ret =
	silc_buffer_format(buf,
			   SILC_STR_UI_XNSTRING(
				   ske->start_payload_copy->data,
				   silc_buffer_len(ske->start_payload_copy)),
			   SILC_STR_UI_XNSTRING(ske->ke2_payload->pk_data,
						ske->ke2_payload->pk_len),
			   SILC_STR_UI_XNSTRING(ske->ke1_payload->pk_data,
						ske->ke1_payload->pk_len),
			   SILC_STR_UI_XNSTRING(e, e_len),
			   SILC_STR_UI_XNSTRING(f, f_len),
			   SILC_STR_UI_XNSTRING(KEY, KEY_len),
			   SILC_STR_END);
    }
    if (ret == -1) {
      silc_buffer_free(buf);
      memset(e, 0, e_len);
      memset(f, 0, f_len);
      memset(KEY, 0, KEY_len);
      silc_free(e);
      silc_free(f);
      silc_free(KEY);
      return SILC_SKE_STATUS_ERROR;
    }

    memset(e, 0, e_len);
    memset(f, 0, f_len);
    memset(KEY, 0, KEY_len);
    silc_free(e);
    silc_free(f);
    silc_free(KEY);
  } else {
    e = silc_mp_mp2bin(&ske->ke1_payload->x, 0, &e_len);

    buf = silc_buffer_alloc_size(silc_buffer_len(ske->start_payload_copy) +
				 ske->ke1_payload->pk_len + e_len);
    if (!buf)
      return SILC_SKE_STATUS_OUT_OF_MEMORY;

    /* Format the buffer used to compute the hash value */
    ret =
      silc_buffer_format(buf,
			 SILC_STR_UI_XNSTRING(ske->start_payload_copy->data,
		       	             silc_buffer_len(ske->start_payload_copy)),
			 SILC_STR_UI_XNSTRING(ske->ke1_payload->pk_data,
					      ske->ke1_payload->pk_len),
			 SILC_STR_UI_XNSTRING(e, e_len),
			 SILC_STR_END);
    if (ret == -1) {
      silc_buffer_free(buf);
      memset(e, 0, e_len);
      silc_free(e);
      return SILC_SKE_STATUS_ERROR;
    }

    SILC_LOG_HEXDUMP(("hash buf"), buf->data, silc_buffer_len(buf));

    memset(e, 0, e_len);
    silc_free(e);
  }

  /* Make the hash */
  silc_hash_make(ske->prop->hash, buf->data, silc_buffer_len(buf),
		 return_hash);
  *return_hash_len = silc_hash_len(ske->prop->hash);

  if (initiator == FALSE) {
    SILC_LOG_HEXDUMP(("HASH"), return_hash, *return_hash_len);
  } else {
    SILC_LOG_HEXDUMP(("HASH_i"), return_hash, *return_hash_len);
  }

  silc_buffer_free(buf);

  return status;
}

/* Generate rekey material */

static SilcSKERekeyMaterial
silc_ske_make_rekey_material(SilcSKE ske, SilcSKEKeyMaterial keymat)
{
  SilcSKERekeyMaterial rekey;
  const char *hash;

  /* Create rekey material */
  rekey = silc_calloc(1, sizeof(*rekey));
  if (!rekey)
    return NULL;

  if (ske->prop) {
    if (ske->prop->group)
      rekey->ske_group = silc_ske_group_get_number(ske->prop->group);
    rekey->pfs = (ske->prop->flags & SILC_SKE_SP_FLAG_PFS ? TRUE : FALSE);
    hash = silc_hash_get_name(ske->prop->hash);
    rekey->hash = silc_memdup(hash, strlen(hash));
    if (!rekey->hash)
      return NULL;
  }

  if (rekey->pfs == FALSE) {
    rekey->send_enc_key = silc_memdup(keymat->send_enc_key,
				      keymat->enc_key_len / 8);
    if (!rekey->send_enc_key) {
      silc_free(rekey);
      return NULL;
    }
    rekey->enc_key_len = keymat->enc_key_len;
  }

  return rekey;
}

/* Assembles security properties */

static SilcSKEStartPayload
silc_ske_assemble_security_properties(SilcSKE ske,
				      SilcSKESecurityPropertyFlag flags,
				      const char *version)
{
  SilcSKEStartPayload rp;
  int i;

  SILC_LOG_DEBUG(("Assembling KE Start Payload"));

  rp = silc_calloc(1, sizeof(*rp));

  /* Set flags */
  rp->flags = (unsigned char)flags;

  /* Set random cookie */
  rp->cookie = silc_calloc(SILC_SKE_COOKIE_LEN, sizeof(*rp->cookie));
  for (i = 0; i < SILC_SKE_COOKIE_LEN; i++)
    rp->cookie[i] = silc_rng_get_byte_fast(ske->rng);
  rp->cookie_len = SILC_SKE_COOKIE_LEN;

  /* In case IV included flag and session port is set the first 16-bits of
     cookie will include our session port. */
  if (flags & SILC_SKE_SP_FLAG_IV_INCLUDED && ske->session_port)
    SILC_PUT16_MSB(ske->session_port, rp->cookie);

  /* Put version */
  rp->version = strdup(version);
  rp->version_len = strlen(version);

  /* Get supported Key Exhange groups */
  rp->ke_grp_list = silc_ske_get_supported_groups();
  rp->ke_grp_len = strlen(rp->ke_grp_list);

  /* Get supported PKCS algorithms */
  rp->pkcs_alg_list = silc_pkcs_get_supported();
  rp->pkcs_alg_len = strlen(rp->pkcs_alg_list);

  /* Get supported encryption algorithms */
  rp->enc_alg_list = silc_cipher_get_supported();
  rp->enc_alg_len = strlen(rp->enc_alg_list);

  /* Get supported hash algorithms */
  rp->hash_alg_list = silc_hash_get_supported();
  rp->hash_alg_len = strlen(rp->hash_alg_list);

  /* Get supported HMACs */
  rp->hmac_alg_list = silc_hmac_get_supported();
  rp->hmac_alg_len = strlen(rp->hmac_alg_list);

  /* XXX */
  /* Get supported compression algorithms */
  rp->comp_alg_list = strdup("none");
  rp->comp_alg_len = strlen("none");

  rp->len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN +
    2 + rp->version_len +
    2 + rp->ke_grp_len + 2 + rp->pkcs_alg_len +
    2 + rp->enc_alg_len + 2 + rp->hash_alg_len +
    2 + rp->hmac_alg_len + 2 + rp->comp_alg_len;

  return rp;
}

/* Packet retransmission callback. */

SILC_TASK_CALLBACK(silc_ske_packet_send_retry)
{
  SilcSKE ske = context;

  if (ske->retry_count++ >= SILC_SKE_RETRY_COUNT ||
      ske->aborted) {
    SILC_LOG_DEBUG(("Retransmission limit reached, packet was lost"));
    ske->retry_count = 0;
    ske->retry_timer = SILC_SKE_RETRY_MIN;
    silc_free(ske->retrans.data);
    ske->retrans.data = NULL;
    ske->status = SILC_SKE_STATUS_TIMEOUT;
    if (ske->responder)
      silc_fsm_next(&ske->fsm, silc_ske_st_responder_failure);
    else
      silc_fsm_next(&ske->fsm, silc_ske_st_initiator_failure);
    silc_fsm_continue_sync(&ske->fsm);
    return;
  }

  SILC_LOG_DEBUG(("Retransmitting packet"));
  silc_ske_packet_send(ske, ske->retrans.type, ske->retrans.flags,
		       ske->retrans.data, ske->retrans.data_len);
}

/* Install retransmission timer */

static void silc_ske_install_retransmission(SilcSKE ske)
{
  if (!silc_packet_stream_is_udp(ske->stream))
    return;

  if (ske->retrans.data) {
    SILC_LOG_DEBUG(("Installing retransmission timer %d secs",
		    ske->retry_timer));
    silc_schedule_task_add_timeout(ske->schedule, silc_ske_packet_send_retry,
				   ske, ske->retry_timer, 0);
  }
  ske->retry_timer = ((ske->retry_timer * SILC_SKE_RETRY_MUL) +
		      (silc_rng_get_rn16(ske->rng) % SILC_SKE_RETRY_RAND));
}

/* Sends SILC packet.  Handles retransmissions with UDP streams. */

static SilcBool silc_ske_packet_send(SilcSKE ske,
				     SilcPacketType type,
				     SilcPacketFlags flags,
				     const unsigned char *data,
				     SilcUInt32 data_len)
{
  SilcBool ret;

  /* Send the packet */
  ret = silc_packet_send(ske->stream, type, flags, data, data_len);

  if (silc_packet_stream_is_udp(ske->stream) &&
      type != SILC_PACKET_FAILURE && type != SILC_PACKET_REKEY) {
    silc_free(ske->retrans.data);
    ske->retrans.type = type;
    ske->retrans.flags = flags;
    ske->retrans.data = silc_memdup(data, data_len);
    ske->retrans.data_len = data_len;
    silc_ske_install_retransmission(ske);
  }

  return ret;
}

/* Calls completion callback.  Completion is called always in this function
   and must not be called anywhere else. */

static void silc_ske_completion(SilcSKE ske)
{
  /* Call the completion callback */
  if (!ske->freed && !ske->aborted && ske->callbacks->completed) {
    if (ske->status != SILC_SKE_STATUS_OK)
      ske->callbacks->completed(ske, ske->status, NULL, NULL, NULL,
			        ske->callbacks->context);
    else
      ske->callbacks->completed(ske, ske->status, ske->prop, ske->keymat,
			        ske->rekey, ske->callbacks->context);
  }
}

/* SKE FSM destructor. */

static void silc_ske_finished(SilcFSM fsm, void *fsm_context,
			      void *destructor_context)
{
  SilcSKE ske = fsm_context;
  ske->running = FALSE;
  if (ske->freed)
    silc_ske_free(ske);
}

/* Key exchange timeout task callback */

SILC_TASK_CALLBACK(silc_ske_timeout)
{
  SilcSKE ske = context;

  SILC_LOG_DEBUG(("Timeout"));

  ske->packet = NULL;
  ske->status = SILC_SKE_STATUS_TIMEOUT;
  if (ske->responder)
    silc_fsm_next(&ske->fsm, silc_ske_st_responder_failure);
  else
    silc_fsm_next(&ske->fsm, silc_ske_st_initiator_failure);

  silc_fsm_continue_sync(&ske->fsm);
}

/******************************* Protocol API *******************************/

/* Allocates new SKE object. */

SilcSKE silc_ske_alloc(SilcRng rng, SilcSchedule schedule,
		       SilcSKR repository, SilcPublicKey public_key,
		       SilcPrivateKey private_key, void *context)
{
  SilcSKE ske;

  SILC_LOG_DEBUG(("Allocating new Key Exchange object"));

  if (!rng || !schedule)
    return NULL;

  if (!public_key) {
    SILC_LOG_ERROR(("Public key must be given to silc_ske_alloc"));
    return NULL;
  }

  ske = silc_calloc(1, sizeof(*ske));
  if (!ske)
    return NULL;
  ske->status = SILC_SKE_STATUS_OK;
  ske->rng = rng;
  ske->repository = repository;
  ske->user_data = context;
  ske->schedule = schedule;
  ske->public_key = public_key;
  ske->private_key = private_key;
  ske->retry_timer = SILC_SKE_RETRY_MIN;

  return ske;
}

/* Free's SKE object. */

void silc_ske_free(SilcSKE ske)
{
  SILC_LOG_DEBUG(("Freeing Key Exchange object"));

  if (!ske)
    return;

  if (ske->running) {
    ske->freed = TRUE;

    if (ske->aborted) {
      /* If already aborted, destroy the session immediately */
      ske->packet = NULL;
      ske->status = SILC_SKE_STATUS_ERROR;
      if (ske->responder)
	silc_fsm_next(&ske->fsm, silc_ske_st_responder_failure);
      else
	silc_fsm_next(&ske->fsm, silc_ske_st_initiator_failure);
      silc_fsm_continue_sync(&ske->fsm);
    }
    return;
  }

  /* Free start payload */
  if (ske->start_payload)
    silc_ske_payload_start_free(ske->start_payload);

  /* Free KE payload */
  if (ske->ke1_payload)
    silc_ske_payload_ke_free(ske->ke1_payload);
  if (ske->ke2_payload)
    silc_ske_payload_ke_free(ske->ke2_payload);
  silc_free(ske->remote_version);

  /* Free rest */
  if (ske->prop) {
    if (ske->prop->group)
      silc_ske_group_free(ske->prop->group);
    if (ske->prop->cipher)
      silc_cipher_free(ske->prop->cipher);
    if (ske->prop->hash)
      silc_hash_free(ske->prop->hash);
    if (ske->prop->hmac)
      silc_hmac_free(ske->prop->hmac);
    if (ske->prop->public_key)
      silc_pkcs_public_key_free(ske->prop->public_key);
    silc_free(ske->prop);
  }
  if (ske->keymat)
    silc_ske_free_key_material(ske->keymat);
  if (ske->start_payload_copy)
    silc_buffer_free(ske->start_payload_copy);
  if (ske->x) {
    silc_mp_uninit(ske->x);
    silc_free(ske->x);
  }
  if (ske->KEY) {
    silc_mp_uninit(ske->KEY);
    silc_free(ske->KEY);
  }
  silc_free(ske->retrans.data);
  silc_free(ske->hash);
  silc_free(ske->callbacks);

  memset(ske, 'F', sizeof(*ske));
  silc_free(ske);
}

/* Return user context */

void *silc_ske_get_context(SilcSKE ske)
{
  return ske->user_data;
}

/* Sets protocol callbacks */

void silc_ske_set_callbacks(SilcSKE ske,
			    SilcSKEVerifyCb verify_key,
			    SilcSKECompletionCb completed,
			    void *context)
{
  if (ske->callbacks)
    silc_free(ske->callbacks);
  ske->callbacks = silc_calloc(1, sizeof(*ske->callbacks));
  if (!ske->callbacks)
    return;
  ske->callbacks->verify_key = verify_key;
  ske->callbacks->completed = completed;
  ske->callbacks->context = context;
}


/******************************** Initiator *********************************/

/* Start protocol.  Send our proposal */

SILC_FSM_STATE(silc_ske_st_initiator_start)
{
  SilcSKE ske = fsm_context;
  SilcBuffer payload_buf;
  SilcStatus status;

  SILC_LOG_DEBUG(("Start"));

  if (ske->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_ske_st_initiator_aborted);
    return SILC_FSM_CONTINUE;
  }

  /* Encode the payload */
  status = silc_ske_payload_start_encode(ske, ske->start_payload,
					 &payload_buf);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error encoding Start Payload */
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Save the the payload buffer for future use. It is later used to
     compute the HASH value. */
  ske->start_payload_copy = payload_buf;

  /* Send the packet. */
  if (!silc_ske_packet_send(ske, SILC_PACKET_KEY_EXCHANGE, 0,
			    silc_buffer_data(payload_buf),
			    silc_buffer_len(payload_buf))) {
    /** Error sending packet */
    SILC_LOG_DEBUG(("Error sending packet"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Add key exchange timeout */
  silc_schedule_task_add_timeout(ske->schedule, silc_ske_timeout,
				 ske, ske->timeout, 0);

  /** Wait for responder proposal */
  SILC_LOG_DEBUG(("Waiting for responder proposal"));
  silc_fsm_next(fsm, silc_ske_st_initiator_phase1);
  return SILC_FSM_WAIT;
}

/* Phase-1.  Receives responder's proposal */

SILC_FSM_STATE(silc_ske_st_initiator_phase1)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEStartPayload payload;
  SilcSKESecurityProperties prop;
  SilcSKEDiffieHellmanGroup group = NULL;
  SilcBuffer packet_buf = &ske->packet->buffer;
  SilcUInt16 remote_port = 0;
  SilcID id;
  int coff = 0;

  SILC_LOG_DEBUG(("Start"));

  if (ske->packet->type != SILC_PACKET_KEY_EXCHANGE) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_ske_install_retransmission(ske);
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }

  /* Decode the payload */
  status = silc_ske_payload_start_decode(ske, packet_buf, &payload);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error decoding Start Payload */
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Get remote ID and set it to stream */
  if (ske->packet->src_id_len) {
    silc_id_str2id(ske->packet->src_id, ske->packet->src_id_len,
		   ske->packet->src_id_type,
		   (ske->packet->src_id_type == SILC_ID_SERVER ?
		    (void *)&id.u.server_id : (void *)&id.u.client_id),
		   (ske->packet->src_id_type == SILC_ID_SERVER ?
		    sizeof(id.u.server_id) : sizeof(id.u.client_id)));
    silc_packet_set_ids(ske->stream, 0, NULL, ske->packet->src_id_type,
			(ske->packet->src_id_type == SILC_ID_SERVER ?
			 (void *)&id.u.server_id : (void *)&id.u.client_id));
  }

  silc_packet_free(ske->packet);
  ske->packet = NULL;

  /* Check that the cookie is returned unmodified.  In case IV included
     flag and session port has been set, the first two bytes of cookie
     are the session port and we ignore them in this check. */
  if (payload->flags & SILC_SKE_SP_FLAG_IV_INCLUDED && ske->session_port) {
    /* Take remote port */
    SILC_GET16_MSB(remote_port, ske->start_payload->cookie);
    coff = 2;
  }
  if (memcmp(ske->start_payload->cookie + coff, payload->cookie + coff,
	     SILC_SKE_COOKIE_LEN - coff)) {
    /** Invalid cookie */
    SILC_LOG_ERROR(("Invalid cookie, modified or unsupported feature"));
    ske->status = SILC_SKE_STATUS_INVALID_COOKIE;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check version string */
  ske->remote_version = silc_memdup(payload->version, payload->version_len);
  status = silc_ske_check_version(ske);
  if (status != SILC_SKE_STATUS_OK) {
    /** Version mismatch */
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Free our KE Start Payload context, we don't need it anymore. */
  silc_ske_payload_start_free(ske->start_payload);
  ske->start_payload = NULL;

  /* Take the selected security properties into use while doing
     the key exchange.  This is used only while doing the key
     exchange. */
  ske->prop = prop = silc_calloc(1, sizeof(*prop));
  if (!ske->prop)
    goto err;
  prop->flags = payload->flags;
  status = silc_ske_group_get_by_name(payload->ke_grp_list, &group);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  prop->group = group;
  prop->remote_port = remote_port;

  if (silc_pkcs_find_algorithm(payload->pkcs_alg_list, NULL) == NULL) {
    status = SILC_SKE_STATUS_UNKNOWN_PKCS;
    goto err;
  }
  if (silc_cipher_alloc(payload->enc_alg_list, &prop->cipher) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_CIPHER;
    goto err;
  }
  if (silc_hash_alloc(payload->hash_alg_list, &prop->hash) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
    goto err;
  }
  if (silc_hmac_alloc(payload->hmac_alg_list, NULL, &prop->hmac) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HMAC;
    goto err;
  }

  /* Save remote's KE Start Payload */
  ske->start_payload = payload;

  /** Send KE Payload */
  silc_fsm_next(fsm, silc_ske_st_initiator_phase2);
  return SILC_FSM_CONTINUE;

 err:
  if (payload)
    silc_ske_payload_start_free(payload);
  if (group)
    silc_ske_group_free(group);
  if (prop->cipher)
    silc_cipher_free(prop->cipher);
  if (prop->hash)
    silc_hash_free(prop->hash);
  if (prop->hmac)
    silc_hmac_free(prop->hmac);
  silc_free(prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    status = SILC_SKE_STATUS_ERROR;

  /** Error */
  ske->status = status;
  silc_fsm_next(fsm, silc_ske_st_initiator_error);
  return SILC_FSM_CONTINUE;
}

/* Phase-2.  Send KE payload */

SILC_FSM_STATE(silc_ske_st_initiator_phase2)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcBuffer payload_buf;
  SilcMPInt *x;
  SilcSKEKEPayload payload;
  SilcUInt32 pk_len;

  SILC_LOG_DEBUG(("Start"));

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  if (!x){
    /** Out of memory */
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  silc_mp_init(x);
  status =
    silc_ske_create_rnd(ske, &ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error generating random number */
    silc_mp_uninit(x);
    silc_free(x);
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Encode the result to Key Exchange Payload. */

  payload = silc_calloc(1, sizeof(*payload));
  if (!payload) {
    /** Out of memory */
    silc_mp_uninit(x);
    silc_free(x);
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  ske->ke1_payload = payload;

  SILC_LOG_DEBUG(("Computing e = g ^ x mod p"));

  /* Do the Diffie Hellman computation, e = g ^ x mod p */
  silc_mp_init(&payload->x);
  silc_mp_pow_mod(&payload->x, &ske->prop->group->generator, x,
		  &ske->prop->group->group);

  /* Get public key */
  payload->pk_data = silc_pkcs_public_key_encode(ske->public_key, &pk_len);
  if (!payload->pk_data) {
    /** Error encoding public key */
    silc_mp_uninit(x);
    silc_free(x);
    silc_mp_uninit(&payload->x);
    silc_free(payload);
    ske->ke1_payload = NULL;
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  payload->pk_len = pk_len;
  payload->pk_type = silc_pkcs_get_type(ske->public_key);

  /* Compute signature data if we are doing mutual authentication */
  if (ske->private_key && ske->prop->flags & SILC_SKE_SP_FLAG_MUTUAL) {
    unsigned char hash[SILC_HASH_MAXLEN], sign[2048 + 1];
    SilcUInt32 hash_len, sign_len;

    SILC_LOG_DEBUG(("We are doing mutual authentication"));
    SILC_LOG_DEBUG(("Computing HASH_i value"));

    /* Compute the hash value */
    memset(hash, 0, sizeof(hash));
    silc_ske_make_hash(ske, hash, &hash_len, TRUE);

    SILC_LOG_DEBUG(("Signing HASH_i value"));

    /* Sign the hash value */
    if (!silc_pkcs_sign(ske->private_key, hash, hash_len, sign,
			sizeof(sign) - 1, &sign_len, FALSE, ske->prop->hash)) {
      /** Error computing signature */
      silc_mp_uninit(x);
      silc_free(x);
      silc_mp_uninit(&payload->x);
      silc_free(payload->pk_data);
      silc_free(payload);
      ske->ke1_payload = NULL;
      ske->status = SILC_SKE_STATUS_SIGNATURE_ERROR;
      silc_fsm_next(fsm, silc_ske_st_initiator_error);
      return SILC_FSM_CONTINUE;
    }
    payload->sign_data = silc_memdup(sign, sign_len);
    if (payload->sign_data)
      payload->sign_len = sign_len;
    memset(sign, 0, sizeof(sign));
  }

  status = silc_ske_payload_ke_encode(ske, payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error encoding KE payload */
    silc_mp_uninit(x);
    silc_free(x);
    silc_mp_uninit(&payload->x);
    silc_free(payload->pk_data);
    silc_free(payload->sign_data);
    silc_free(payload);
    ske->ke1_payload = NULL;
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  ske->x = x;

  /* Check for backwards compatibility */

  /* Send the packet. */
  if (!silc_ske_packet_send(ske, SILC_PACKET_KEY_EXCHANGE_1, 0,
			    silc_buffer_data(payload_buf),
			    silc_buffer_len(payload_buf))) {
    /** Error sending packet */
    SILC_LOG_DEBUG(("Error sending packet"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  silc_buffer_free(payload_buf);

  /** Waiting responder's KE payload */
  silc_fsm_next(fsm, silc_ske_st_initiator_phase3);
  return SILC_FSM_WAIT;
}

/* Phase-3.  Process responder's KE payload */

SILC_FSM_STATE(silc_ske_st_initiator_phase3)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEKEPayload payload;
  SilcMPInt *KEY;
  SilcBuffer packet_buf = &ske->packet->buffer;

  SILC_LOG_DEBUG(("Start"));

  if (ske->packet->type != SILC_PACKET_KEY_EXCHANGE_2) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_ske_install_retransmission(ske);
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }

  /* Decode the payload */
  status = silc_ske_payload_ke_decode(ske, packet_buf, &payload);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error decoding KE payload */
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  silc_packet_free(ske->packet);
  ske->packet = NULL;
  ske->ke2_payload = payload;

  if (!payload->pk_data && (ske->callbacks->verify_key || ske->repository)) {
    SILC_LOG_DEBUG(("Remote end did not send its public key (or certificate), "
		    "even though we require it"));
    ske->status = SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED;
    goto err;
  }

  SILC_LOG_DEBUG(("Computing KEY = f ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_pow_mod(KEY, &payload->x, ske->x, &ske->prop->group->group);
  ske->KEY = KEY;

  /* Decode the remote's public key */
  if (payload->pk_data &&
      !silc_pkcs_public_key_alloc(payload->pk_type,
				  payload->pk_data, payload->pk_len,
				  &ske->prop->public_key)) {
    SILC_LOG_ERROR(("Unsupported/malformed public key received"));
    status = SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;
    goto err;
  }

  if (ske->prop->public_key && (ske->callbacks->verify_key ||
				ske->repository)) {
    SILC_LOG_DEBUG(("Verifying public key"));

    /** Waiting public key verification */
    silc_fsm_next(fsm, silc_ske_st_initiator_phase4);

    /* If repository is provided, verify the key from there. */
    if (ske->repository) {
      SilcSKRFind find;

      find = silc_skr_find_alloc();
      if (!find) {
	status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	goto err;
      }
      silc_skr_find_set_pkcs_type(find,
				  silc_pkcs_get_type(ske->prop->public_key));
      silc_skr_find_set_public_key(find, ske->prop->public_key);
      silc_skr_find_set_usage(find, SILC_SKR_USAGE_KEY_AGREEMENT);

      /* Find key from repository */
      SILC_FSM_CALL(silc_skr_find(ske->repository, find,
				  silc_ske_skr_callback, ske));
    } else {
      /* Verify from application */
      SILC_FSM_CALL(ske->callbacks->verify_key(ske, ske->prop->public_key,
					       ske->callbacks->context,
					       silc_ske_pk_verified, NULL));
    }
    /* NOT REACHED */
  }

  /** Process key material */
  silc_fsm_next(fsm, silc_ske_st_initiator_phase4);
  return SILC_FSM_CONTINUE;

 err:
  silc_ske_payload_ke_free(payload);
  ske->ke2_payload = NULL;

  silc_mp_uninit(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  /** Error */
  ske->status = status;
  silc_fsm_next(fsm, silc_ske_st_initiator_error);
  return SILC_FSM_CONTINUE;
}

/* Process key material */

SILC_FSM_STATE(silc_ske_st_initiator_phase4)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEKEPayload payload;
  unsigned char hash[SILC_HASH_MAXLEN];
  SilcUInt32 hash_len;
  int key_len, block_len;

  if (ske->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_ske_st_initiator_aborted);
    return SILC_FSM_CONTINUE;
  }

  /* Check result of public key verification */
  if (ske->status != SILC_SKE_STATUS_OK) {
    /** Public key not verified */
    SILC_LOG_DEBUG(("Public key verification failed"));
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  payload = ske->ke2_payload;

  if (ske->prop->public_key) {
    SILC_LOG_DEBUG(("Public key is authentic"));

    /* Compute the hash value */
    status = silc_ske_make_hash(ske, hash, &hash_len, FALSE);
    if (status != SILC_SKE_STATUS_OK)
      goto err;

    SILC_LOG_DEBUG(("Verifying signature (HASH)"));

    /* Verify signature */
    if (!silc_pkcs_verify(ske->prop->public_key, payload->sign_data,
			  payload->sign_len, hash, hash_len, NULL)) {
      SILC_LOG_ERROR(("Signature verification failed, incorrect signature"));
      status = SILC_SKE_STATUS_INCORRECT_SIGNATURE;
      goto err;
    }

    SILC_LOG_DEBUG(("Signature is Ok"));

    ske->hash = silc_memdup(hash, hash_len);
    ske->hash_len = hash_len;
    memset(hash, 'F', hash_len);
  }

  ske->status = SILC_SKE_STATUS_OK;

  /* In case we are doing rekey move to finish it.  */
  if (ske->rekey) {
    /** Finish rekey */
    silc_fsm_next(fsm, silc_ske_st_rekey_initiator_done);
    return SILC_FSM_CONTINUE;
  }

  /* Process key material */
  key_len = silc_cipher_get_key_len(ske->prop->cipher);
  block_len = silc_cipher_get_block_len(ske->prop->cipher);
  hash_len = silc_hash_len(ske->prop->hash);
  ske->keymat = silc_ske_process_key_material(ske, block_len,
					      key_len, hash_len,
					      &ske->rekey);
  if (!ske->keymat) {
    SILC_LOG_ERROR(("Error processing key material"));
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  /* Send SUCCESS packet */
  SILC_PUT32_MSB((SilcUInt32)SILC_SKE_STATUS_OK, hash);
  if (!silc_ske_packet_send(ske, SILC_PACKET_SUCCESS, 0, hash, 4)) {
    /** Error sending packet */
    SILC_LOG_DEBUG(("Error sending packet"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /** Waiting completion */
  silc_fsm_next(fsm, silc_ske_st_initiator_end);
  return SILC_FSM_WAIT;

 err:
  memset(hash, 'F', sizeof(hash));
  silc_ske_payload_ke_free(payload);
  ske->ke2_payload = NULL;

  silc_mp_uninit(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;

  if (ske->hash) {
    memset(ske->hash, 'F', hash_len);
    silc_free(ske->hash);
    ske->hash = NULL;
  }

  if (status == SILC_SKE_STATUS_OK)
    status = SILC_SKE_STATUS_ERROR;

  /** Error */
  ske->status = status;
  silc_fsm_next(fsm, silc_ske_st_initiator_error);
  return SILC_FSM_CONTINUE;
}

/* Protocol completed */

SILC_FSM_STATE(silc_ske_st_initiator_end)
{
  SilcSKE ske = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  if (ske->packet->type != SILC_PACKET_SUCCESS) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_ske_install_retransmission(ske);
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }

  SILC_LOG_DEBUG(("Key exchange completed successfully"));

  silc_packet_free(ske->packet);
  ske->packet = NULL;
  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Aborted by application */

SILC_FSM_STATE(silc_ske_st_initiator_aborted)
{
  SilcSKE ske = fsm_context;
  unsigned char data[4];

  SILC_LOG_DEBUG(("Aborted by caller"));

  /* Send FAILURE packet */
  SILC_PUT32_MSB(SILC_SKE_STATUS_ERROR, data);
  silc_ske_packet_send(ske, SILC_PACKET_FAILURE, 0, data, 4);

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Error occurred.  Send error to remote host */

SILC_FSM_STATE(silc_ske_st_initiator_error)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  unsigned char data[4];

  SILC_LOG_DEBUG(("Error %s (%d) occurred during key exchange",
		  silc_ske_map_status(ske->status), ske->status));

  status = ske->status;
  if (status > SILC_SKE_STATUS_INVALID_COOKIE)
    status = SILC_SKE_STATUS_ERROR;

  /* Send FAILURE packet */
  SILC_PUT32_MSB((SilcUInt32)status, data);
  silc_ske_packet_send(ske, SILC_PACKET_FAILURE, 0, data, 4);

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Failure received from remote */

SILC_FSM_STATE(silc_ske_st_initiator_failure)
{
  SilcSKE ske = fsm_context;
  SilcUInt32 error = SILC_SKE_STATUS_ERROR;

  SILC_LOG_DEBUG(("Error %s (%d) received during key exchange",
		  silc_ske_map_status(ske->status), ske->status));

  if (ske->packet && silc_buffer_len(&ske->packet->buffer) == 4) {
    SILC_GET32_MSB(error, ske->packet->buffer.data);
    ske->status = error;
    silc_packet_free(ske->packet);
    ske->packet = NULL;
  }

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Starts the protocol as initiator */

SilcAsyncOperation silc_ske_initiator(SilcSKE ske,
				      SilcPacketStream stream,
				      SilcSKEParams params,
				      SilcSKEStartPayload start_payload)
{
  SILC_LOG_DEBUG(("Start SKE as initiator"));

  if (!ske || !stream || !params || !params->version)
    return NULL;

  if (!silc_async_init(&ske->op, silc_ske_abort, NULL, ske))
    return NULL;

  if (!silc_fsm_init(&ske->fsm, ske, silc_ske_finished, ske, ske->schedule))
    return NULL;

  if (params->flags & SILC_SKE_SP_FLAG_IV_INCLUDED)
    ske->session_port = params->session_port;

  /* Generate security properties if not provided */
  if (!start_payload) {
    start_payload = silc_ske_assemble_security_properties(ske,
							  params->flags,
							  params->version);
    if (!start_payload)
      return NULL;
  }

  ske->timeout = params->timeout_secs ? params->timeout_secs : 30;
  ske->start_payload = start_payload;
  ske->version = params->version;
  ske->running = TRUE;

  /* Link to packet stream to get key exchange packets */
  ske->stream = stream;
  silc_packet_stream_link(ske->stream, &silc_ske_stream_cbs, ske, 1000000,
			  SILC_PACKET_KEY_EXCHANGE,
			  SILC_PACKET_KEY_EXCHANGE_2,
			  SILC_PACKET_SUCCESS,
			  SILC_PACKET_FAILURE, -1);

  /* Start SKE as initiator */
  silc_fsm_start(&ske->fsm, silc_ske_st_initiator_start);

  return &ske->op;
}

/******************************** Responder *********************************/

/* Start protocol as responder.  Wait initiator's start payload */

SILC_FSM_STATE(silc_ske_st_responder_start)
{
  SilcSKE ske = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  if (ske->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_ske_st_responder_aborted);
    return SILC_FSM_CONTINUE;
  }

  /* Add key exchange timeout */
  silc_schedule_task_add_timeout(ske->schedule, silc_ske_timeout,
				 ske, ske->timeout, 0);

  /** Wait for initiator */
  silc_fsm_next(fsm, silc_ske_st_responder_phase1);
  return SILC_FSM_WAIT;
}

/* Decode initiator's start payload.  Select the security properties from
   the initiator's start payload and send our reply start payload back. */

SILC_FSM_STATE(silc_ske_st_responder_phase1)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEStartPayload remote_payload = NULL;
  SilcBuffer packet_buf = &ske->packet->buffer;

  SILC_LOG_DEBUG(("Start"));

  /* Decode the payload */
  status = silc_ske_payload_start_decode(ske, packet_buf, &remote_payload);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error decoding Start Payload */
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  /* Take a copy of the payload buffer for future use. It is used to
     compute the HASH value. */
  ske->start_payload_copy = silc_buffer_copy(packet_buf);

  silc_packet_free(ske->packet);
  ske->packet = NULL;

  /* Force the mutual authentication flag if we want to do it. */
  if (ske->flags & SILC_SKE_SP_FLAG_MUTUAL) {
    SILC_LOG_DEBUG(("Force mutual authentication"));
    remote_payload->flags |= SILC_SKE_SP_FLAG_MUTUAL;
  }

  /* Force PFS flag if we require it */
  if (ske->flags & SILC_SKE_SP_FLAG_PFS) {
    SILC_LOG_DEBUG(("Force PFS"));
    remote_payload->flags |= SILC_SKE_SP_FLAG_PFS;
  }

  /* Disable IV Included flag if requested */
  if (remote_payload->flags & SILC_SKE_SP_FLAG_IV_INCLUDED &&
      !(ske->flags & SILC_SKE_SP_FLAG_IV_INCLUDED)) {
    SILC_LOG_DEBUG(("We do not support IV Included flag"));
    remote_payload->flags &= ~SILC_SKE_SP_FLAG_IV_INCLUDED;
  }

  /* Check and select security properties */
  status = silc_ske_select_security_properties(ske, remote_payload,
					       &ske->prop);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error selecting proposal */
    silc_ske_payload_start_free(remote_payload);
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  silc_ske_payload_start_free(remote_payload);

  /* Encode our reply payload to send the selected security properties */
  status = silc_ske_payload_start_encode(ske, ske->start_payload,
					 &packet_buf);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  /* Send the packet. */
  if (!silc_ske_packet_send(ske, SILC_PACKET_KEY_EXCHANGE, 0,
			    silc_buffer_data(packet_buf),
			    silc_buffer_len(packet_buf)))
    goto err;

  silc_buffer_free(packet_buf);

  /** Waiting initiator's KE payload */
  silc_fsm_next(fsm, silc_ske_st_responder_phase2);
  return SILC_FSM_WAIT;

 err:
  if (ske->prop->group)
    silc_ske_group_free(ske->prop->group);
  if (ske->prop->cipher)
    silc_cipher_free(ske->prop->cipher);
  if (ske->prop->hash)
    silc_hash_free(ske->prop->hash);
  if (ske->prop->hmac)
    silc_hmac_free(ske->prop->hmac);
  silc_free(ske->prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    status = SILC_SKE_STATUS_ERROR;

  /** Error */
  ske->status = status;
  silc_fsm_next(fsm, silc_ske_st_responder_error);
  return SILC_FSM_CONTINUE;
}

/* Phase-2.  Decode initiator's KE payload */

SILC_FSM_STATE(silc_ske_st_responder_phase2)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEKEPayload recv_payload;
  SilcBuffer packet_buf = &ske->packet->buffer;

  SILC_LOG_DEBUG(("Start"));

  if (ske->packet->type != SILC_PACKET_KEY_EXCHANGE_1) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_ske_install_retransmission(ske);
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }

  /* Decode Key Exchange Payload */
  status = silc_ske_payload_ke_decode(ske, packet_buf, &recv_payload);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error decoding KE payload */
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  ske->ke1_payload = recv_payload;

  silc_packet_free(ske->packet);
  ske->packet = NULL;

  /* Verify the received public key and verify the signature if we are
     doing mutual authentication. */
  if (ske->start_payload &&
      ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) {

    SILC_LOG_DEBUG(("We are doing mutual authentication"));

    if (!recv_payload->pk_data && (ske->callbacks->verify_key ||
				   ske->repository)) {
      /** Public key not provided */
      SILC_LOG_ERROR(("Remote end did not send its public key (or "
		      "certificate), even though we require it"));
      ske->status = SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }

    /* Decode the remote's public key */
    if (recv_payload->pk_data &&
	!silc_pkcs_public_key_alloc(recv_payload->pk_type,
				    recv_payload->pk_data,
				    recv_payload->pk_len,
				    &ske->prop->public_key)) {
      /** Error decoding public key */
      SILC_LOG_ERROR(("Unsupported/malformed public key received"));
      ske->status = SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }

    if (ske->prop->public_key && (ske->callbacks->verify_key ||
				  ske->repository)) {
      SILC_LOG_DEBUG(("Verifying public key"));

      /** Waiting public key verification */
      silc_fsm_next(fsm, silc_ske_st_responder_phase4);

      /* If repository is provided, verify the key from there. */
      if (ske->repository) {
	SilcSKRFind find;

	find = silc_skr_find_alloc();
	if (!find) {
	  ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
	  silc_fsm_next(fsm, silc_ske_st_responder_error);
	  return SILC_FSM_CONTINUE;
	}
	silc_skr_find_set_pkcs_type(find,
				    silc_pkcs_get_type(ske->prop->public_key));
	silc_skr_find_set_public_key(find, ske->prop->public_key);
	silc_skr_find_set_usage(find, SILC_SKR_USAGE_KEY_AGREEMENT);

	/* Find key from repository */
	SILC_FSM_CALL(silc_skr_find(ske->repository, find,
				    silc_ske_skr_callback, ske));
      } else {
	/* Verify from application */
	SILC_FSM_CALL(ske->callbacks->verify_key(ske, ske->prop->public_key,
						 ske->callbacks->context,
						 silc_ske_pk_verified, NULL));
      }
      /* NOT REACHED */
    }
  }

  /** Generate KE2 payload */
  silc_fsm_next(fsm, silc_ske_st_responder_phase4);
  return SILC_FSM_CONTINUE;
}

/* Phase-4. Generate KE2 payload */

SILC_FSM_STATE(silc_ske_st_responder_phase4)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcSKEKEPayload recv_payload, send_payload;
  SilcMPInt *x, *KEY;

  if (ske->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_ske_st_responder_aborted);
    return SILC_FSM_CONTINUE;
  }

  /* Check result of public key verification */
  if (ske->status != SILC_SKE_STATUS_OK) {
    /** Public key not verified */
    SILC_LOG_DEBUG(("Public key verification failed"));
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  recv_payload = ske->ke1_payload;

  /* The public key verification was performed only if the Mutual
     Authentication flag is set. */
  if (ske->start_payload &&
      ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) {
    unsigned char hash[SILC_HASH_MAXLEN];
    SilcUInt32 hash_len;

    SILC_LOG_DEBUG(("Public key is authentic"));

    /* Compute the hash value */
    status = silc_ske_make_hash(ske, hash, &hash_len, TRUE);
    if (status != SILC_SKE_STATUS_OK) {
      /** Error computing hash */
      ske->status = status;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }

    SILC_LOG_DEBUG(("Verifying signature (HASH_i)"));

    /* Verify signature */
    if (!silc_pkcs_verify(ske->prop->public_key, recv_payload->sign_data,
			  recv_payload->sign_len, hash, hash_len, NULL)) {
      /** Incorrect signature */
      SILC_LOG_ERROR(("Signature verification failed, incorrect signature"));
      ske->status = SILC_SKE_STATUS_INCORRECT_SIGNATURE;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }

    SILC_LOG_DEBUG(("Signature is Ok"));

    memset(hash, 'F', hash_len);
  }

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  silc_mp_init(x);
  status =
    silc_ske_create_rnd(ske, &ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error generating random number */
    silc_mp_uninit(x);
    silc_free(x);
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  /* Save the results for later processing */
  send_payload = silc_calloc(1, sizeof(*send_payload));
  ske->x = x;
  ske->ke2_payload = send_payload;

  SILC_LOG_DEBUG(("Computing f = g ^ x mod p"));

  /* Do the Diffie Hellman computation, f = g ^ x mod p */
  silc_mp_init(&send_payload->x);
  silc_mp_pow_mod(&send_payload->x, &ske->prop->group->generator, x,
		  &ske->prop->group->group);

  SILC_LOG_DEBUG(("Computing KEY = e ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_pow_mod(KEY, &ske->ke1_payload->x, ske->x,
		  &ske->prop->group->group);
  ske->KEY = KEY;

  /** Send KE2 payload */
  silc_fsm_next(fsm, silc_ske_st_responder_phase5);
  return SILC_FSM_CONTINUE;
}

/* Phase-5.  Send KE2 payload */

SILC_FSM_STATE(silc_ske_st_responder_phase5)
{
  SilcSKE ske = fsm_context;
  SilcSKEStatus status;
  SilcBuffer payload_buf;
  unsigned char hash[SILC_HASH_MAXLEN], sign[2048 + 1], *pk;
  SilcUInt32 hash_len, sign_len, pk_len;

  SILC_LOG_DEBUG(("Start"));

  if (ske->public_key && ske->private_key) {
    SILC_LOG_DEBUG(("Getting public key"));

    /* Get the public key */
    pk = silc_pkcs_public_key_encode(ske->public_key, &pk_len);
    if (!pk) {
      /** Error encoding public key */
      status = SILC_SKE_STATUS_OUT_OF_MEMORY;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }
    ske->ke2_payload->pk_data = pk;
    ske->ke2_payload->pk_len = pk_len;

    SILC_LOG_DEBUG(("Computing HASH value"));

    /* Compute the hash value */
    memset(hash, 0, sizeof(hash));
    status = silc_ske_make_hash(ske, hash, &hash_len, FALSE);
    if (status != SILC_SKE_STATUS_OK) {
      /** Error computing hash */
      ske->status = status;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }

    ske->hash = silc_memdup(hash, hash_len);
    ske->hash_len = hash_len;

    SILC_LOG_DEBUG(("Signing HASH value"));

    /* Sign the hash value */
    if (!silc_pkcs_sign(ske->private_key, hash, hash_len, sign,
			sizeof(sign) - 1, &sign_len, FALSE, ske->prop->hash)) {
      /** Error computing signature */
      status = SILC_SKE_STATUS_SIGNATURE_ERROR;
      silc_fsm_next(fsm, silc_ske_st_responder_error);
      return SILC_FSM_CONTINUE;
    }
    ske->ke2_payload->sign_data = silc_memdup(sign, sign_len);
    ske->ke2_payload->sign_len = sign_len;
    memset(sign, 0, sizeof(sign));
  }
  ske->ke2_payload->pk_type = silc_pkcs_get_type(ske->public_key);

  /* Encode the Key Exchange Payload */
  status = silc_ske_payload_ke_encode(ske, ske->ke2_payload,
				      &payload_buf);
  if (status != SILC_SKE_STATUS_OK) {
    /** Error encoding KE payload */
    ske->status = status;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send the packet. */
  if (!silc_ske_packet_send(ske, SILC_PACKET_KEY_EXCHANGE_2, 0,
			    payload_buf->data, silc_buffer_len(payload_buf))) {
    SILC_LOG_DEBUG(("Error sending packet"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  silc_buffer_free(payload_buf);

  /** Waiting completion */
  silc_fsm_next(fsm, silc_ske_st_responder_end);
  return SILC_FSM_WAIT;
}

/* Protocol completed */

SILC_FSM_STATE(silc_ske_st_responder_end)
{
  SilcSKE ske = fsm_context;
  unsigned char tmp[4];
  SilcUInt32 hash_len, key_len, block_len;

  if (ske->packet->type != SILC_PACKET_SUCCESS) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_ske_install_retransmission(ske);
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }
  silc_packet_free(ske->packet);
  ske->packet = NULL;

  /* Process key material */
  key_len = silc_cipher_get_key_len(ske->prop->cipher);
  block_len = silc_cipher_get_block_len(ske->prop->cipher);
  hash_len = silc_hash_len(ske->prop->hash);
  ske->keymat = silc_ske_process_key_material(ske, block_len,
					      key_len, hash_len,
					      &ske->rekey);
  if (!ske->keymat) {
    /** Error processing key material */
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_responder_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send SUCCESS packet */
  SILC_PUT32_MSB(SILC_SKE_STATUS_OK, tmp);
  silc_ske_packet_send(ske, SILC_PACKET_SUCCESS, 0, tmp, 4);

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Aborted by application */

SILC_FSM_STATE(silc_ske_st_responder_aborted)
{
  SilcSKE ske = fsm_context;
  unsigned char tmp[4];

  SILC_LOG_DEBUG(("Key exchange protocol aborted"));

  /* Send FAILURE packet */
  SILC_PUT32_MSB(SILC_SKE_STATUS_ERROR, tmp);
  silc_ske_packet_send(ske, SILC_PACKET_FAILURE, 0, tmp, 4);

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Failure received from remote */

SILC_FSM_STATE(silc_ske_st_responder_failure)
{
  SilcSKE ske = fsm_context;
  SilcUInt32 error = SILC_SKE_STATUS_ERROR;

  SILC_LOG_DEBUG(("Key exchange protocol failed"));

  if (ske->packet && silc_buffer_len(&ske->packet->buffer) == 4) {
    SILC_GET32_MSB(error, ske->packet->buffer.data);
    ske->status = error;
    silc_packet_free(ske->packet);
    ske->packet = NULL;
  }

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Error occurred */

SILC_FSM_STATE(silc_ske_st_responder_error)
{
  SilcSKE ske = fsm_context;
  unsigned char tmp[4];

  SILC_LOG_DEBUG(("Error %d (%s) during key exchange protocol",
		  ske->status, silc_ske_map_status(ske->status)));

  /* Send FAILURE packet */
  if (ske->status > SILC_SKE_STATUS_INVALID_COOKIE)
    ske->status = SILC_SKE_STATUS_BAD_PAYLOAD;
  SILC_PUT32_MSB(ske->status, tmp);
  silc_ske_packet_send(ske, SILC_PACKET_FAILURE, 0, tmp, 4);

  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Starts the protocol as responder. */

SilcAsyncOperation silc_ske_responder(SilcSKE ske,
				      SilcPacketStream stream,
				      SilcSKEParams params)
{
  SILC_LOG_DEBUG(("Start SKE as responder"));

  if (!ske || !stream || !params || !params->version)
    return NULL;

  if (!silc_async_init(&ske->op, silc_ske_abort, NULL, ske))
    return NULL;

  if (!silc_fsm_init(&ske->fsm, ske, silc_ske_finished, ske, ske->schedule))
    return NULL;

  ske->responder = TRUE;
  ske->flags = params->flags;
  ske->timeout = params->timeout_secs ? params->timeout_secs : 30;
  if (ske->flags & SILC_SKE_SP_FLAG_IV_INCLUDED)
    ske->session_port = params->session_port;
  ske->version = strdup(params->version);
  if (!ske->version)
    return NULL;
  ske->running = TRUE;

  /* Link to packet stream to get key exchange packets */
  ske->stream = stream;
  silc_packet_stream_link(ske->stream, &silc_ske_stream_cbs, ske, 1000000,
			  SILC_PACKET_KEY_EXCHANGE,
			  SILC_PACKET_KEY_EXCHANGE_1,
			  SILC_PACKET_SUCCESS,
			  SILC_PACKET_FAILURE, -1);

  /* Start SKE as responder */
  silc_fsm_start(&ske->fsm, silc_ske_st_responder_start);

  return &ske->op;
}

/***************************** Initiator Rekey ******************************/

/* Start rekey */

SILC_FSM_STATE(silc_ske_st_rekey_initiator_start)
{
  SilcSKE ske = fsm_context;
  SilcStatus status;

  SILC_LOG_DEBUG(("Start rekey (%s)", ske->rekey->pfs ? "PFS" : "No PFS"));

  if (ske->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_ske_st_initiator_aborted);
    return SILC_FSM_CONTINUE;
  }

  /* Add rekey exchange timeout */
  silc_schedule_task_add_timeout(ske->schedule, silc_ske_timeout,
				 ske, 30, 0);

  ske->prop = silc_calloc(1, sizeof(*ske->prop));
  if (!ske->prop) {
    /** No memory */
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send REKEY packet to start rekey protocol */
  if (!silc_ske_packet_send(ske, SILC_PACKET_REKEY, 0, NULL, 0)) {
    /** Error sending packet */
    SILC_LOG_DEBUG(("Error sending packet"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* If doing rekey without PFS, move directly to the end of the protocol. */
  if (!ske->rekey->pfs) {
    /** Rekey without PFS */
    silc_fsm_next(fsm, silc_ske_st_rekey_initiator_done);
    return SILC_FSM_CONTINUE;
  }

  status = silc_ske_group_get_by_number(ske->rekey->ske_group,
					&ske->prop->group);
  if (status != SILC_SKE_STATUS_OK) {
    /** Unknown group */
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /** Rekey with PFS */
  silc_fsm_next(fsm, silc_ske_st_initiator_phase2);
  return SILC_FSM_CONTINUE;
}

/* Sends REKEY_DONE packet to finish the protocol. */

SILC_FSM_STATE(silc_ske_st_rekey_initiator_done)
{
  SilcSKE ske = fsm_context;
  SilcCipher send_key;
  SilcHmac hmac_send;
  SilcHash hash;
  SilcUInt32 key_len, block_len, hash_len, x_len;
  unsigned char *pfsbuf;

  SILC_LOG_DEBUG(("Start"));

  silc_packet_get_keys(ske->stream, &send_key, NULL, &hmac_send, NULL);
  key_len = silc_cipher_get_key_len(send_key);
  block_len = silc_cipher_get_block_len(send_key);

  if (!silc_hash_alloc(ske->rekey->hash, &hash)) {
    /** Cannot allocate hash */
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  hash_len = silc_hash_len(hash);

  /* Process key material */
  if (ske->rekey->pfs) {
    /* PFS */
    pfsbuf = silc_mp_mp2bin(ske->KEY, 0, &x_len);
    if (pfsbuf) {
      ske->keymat = silc_ske_process_key_material_data(pfsbuf, x_len,
						       block_len, key_len,
						       hash_len, hash);
      memset(pfsbuf, 0, x_len);
      silc_free(pfsbuf);
    }
  } else {
    /* No PFS */
    ske->keymat =
      silc_ske_process_key_material_data(ske->rekey->send_enc_key,
					 ske->rekey->enc_key_len / 8,
					 block_len, key_len,
					 hash_len, hash);
  }

  if (!ske->keymat) {
    SILC_LOG_ERROR(("Error processing key material"));
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  ske->prop->cipher = send_key;
  ske->prop->hmac = hmac_send;
  ske->prop->hash = hash;

  /* Get sending keys */
  if (!silc_ske_set_keys(ske, ske->keymat, ske->prop, &send_key, NULL,
			 &hmac_send, NULL, NULL)) {
    /** Cannot get keys */
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Set the new keys into use.  This will also send REKEY_DONE packet.  Any
     packet sent after this call will be protected with the new keys. */
  if (!silc_packet_set_keys(ske->stream, send_key, NULL, hmac_send, NULL,
			    TRUE)) {
    /** Cannot set keys */
    SILC_LOG_DEBUG(("Cannot set new keys, error sending REKEY_DONE"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /** Wait for REKEY_DONE */
  silc_fsm_next(fsm, silc_ske_st_rekey_initiator_end);
  return SILC_FSM_WAIT;
}

/* Rekey protocol end */

SILC_FSM_STATE(silc_ske_st_rekey_initiator_end)
{
  SilcSKE ske = fsm_context;
  SilcCipher receive_key;
  SilcHmac hmac_receive;
  SilcSKERekeyMaterial rekey;

  SILC_LOG_DEBUG(("Start"));

  if (ske->packet->type != SILC_PACKET_REKEY_DONE) {
    SILC_LOG_DEBUG(("Remote retransmitted an old packet"));
    silc_packet_free(ske->packet);
    ske->packet = NULL;
    return SILC_FSM_WAIT;
  }

  silc_packet_get_keys(ske->stream, NULL, &receive_key, NULL, &hmac_receive);
  ske->prop->cipher = receive_key;
  ske->prop->hmac = hmac_receive;

  /* Get receiving keys */
  if (!silc_ske_set_keys(ske, ske->keymat, ske->prop, NULL, &receive_key,
			 NULL, &hmac_receive, NULL)) {
    /** Cannot get keys */
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  /* Set new receiving keys into use.  All packets received after this will
     be decrypted with the new keys. */
  if (!silc_packet_set_keys(ske->stream, NULL, receive_key, NULL,
			    hmac_receive, FALSE)) {
    /** Cannot set keys */
    SILC_LOG_DEBUG(("Cannot set new keys"));
    ske->status = SILC_SKE_STATUS_ERROR;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Rekey completed successfully"));

  /* Generate new rekey material */
  rekey = silc_ske_make_rekey_material(ske, ske->keymat);
  if (!rekey) {
    /** No memory */
    ske->status = SILC_SKE_STATUS_OUT_OF_MEMORY;
    silc_fsm_next(fsm, silc_ske_st_initiator_error);
    return SILC_FSM_CONTINUE;
  }
  rekey->pfs = ske->rekey->pfs;
  ske->rekey = rekey;

  ske->prop->cipher = NULL;
  ske->prop->hmac = NULL;
  silc_packet_free(ske->packet);
  ske->packet = NULL;
  silc_packet_stream_unlink(ske->stream, &silc_ske_stream_cbs, ske);
  silc_schedule_task_del_by_context(ske->schedule, ske);

  /* Call completion */
  silc_ske_completion(ske);

  return SILC_FSM_FINISH;
}

/* Starts rekey protocol as initiator */

SilcAsyncOperation
silc_ske_rekey_initiator(SilcSKE ske,
			 SilcPacketStream stream,
			 SilcSKERekeyMaterial rekey)
{
  SILC_LOG_DEBUG(("Start SKE rekey as initator"));

  if (!ske || !stream || !rekey)
    return NULL;

  if (!silc_async_init(&ske->op, silc_ske_abort, NULL, ske))
    return NULL;

  if (!silc_fsm_init(&ske->fsm, ske, silc_ske_finished, ske, ske->schedule))
    return NULL;

  ske->rekey = rekey;
  ske->responder = FALSE;
  ske->running = TRUE;
  ske->rekeying = TRUE;

  /* Link to packet stream to get key exchange packets */
  ske->stream = stream;
  silc_packet_stream_link(ske->stream, &silc_ske_stream_cbs, ske, 1000000,
			  SILC_PACKET_REKEY,
			  SILC_PACKET_REKEY_DONE,
			  SILC_PACKET_KEY_EXCHANGE_2,
			  SILC_PACKET_SUCCESS,
			  SILC_PACKET_FAILURE, -1);

  /* Start SKE rekey as initiator */
  silc_fsm_start(&ske->fsm, silc_ske_st_rekey_initiator_start);

  return &ske->op;
}

/***************************** Responder Rekey ******************************/

SILC_FSM_STATE(silc_ske_st_rekey_responder_start);

SILC_FSM_STATE(silc_ske_st_rekey_responder_start)
{
  return SILC_FSM_FINISH;
}

/* Starts rekey protocol as responder */

SilcAsyncOperation
silc_ske_rekey_responder(SilcSKE ske,
			 SilcPacketStream stream,
			 SilcSKERekeyMaterial rekey)
{
  SILC_LOG_DEBUG(("Start SKE rekey as responder"));

  if (!ske || !stream || !rekey)
    return NULL;

  if (!silc_async_init(&ske->op, silc_ske_abort, NULL, ske))
    return NULL;

  if (!silc_fsm_init(&ske->fsm, ske, silc_ske_finished, ske, ske->schedule))
    return NULL;

  ske->rekey = rekey;
  ske->responder = TRUE;
  ske->running = TRUE;
  ske->rekeying = TRUE;

  /* Link to packet stream to get key exchange packets */
  ske->stream = stream;
  silc_packet_stream_link(ske->stream, &silc_ske_stream_cbs, ske, 1000000,
			  SILC_PACKET_REKEY,
			  SILC_PACKET_REKEY_DONE,
			  SILC_PACKET_KEY_EXCHANGE_1,
			  SILC_PACKET_SUCCESS,
			  SILC_PACKET_FAILURE, -1);

  /* Start SKE rekey as responder */
  silc_fsm_start(&ske->fsm, silc_ske_st_rekey_responder_start);

  return &ske->op;
}

/* Processes the provided key material `data' as the SILC protocol
   specification defines. */

SilcSKEKeyMaterial
silc_ske_process_key_material_data(unsigned char *data,
				   SilcUInt32 data_len,
				   SilcUInt32 req_iv_len,
				   SilcUInt32 req_enc_key_len,
				   SilcUInt32 req_hmac_key_len,
				   SilcHash hash)
{
  SilcBuffer buf;
  unsigned char hashd[SILC_HASH_MAXLEN];
  SilcUInt32 hash_len = req_hmac_key_len;
  SilcUInt32 enc_key_len = req_enc_key_len / 8;
  SilcSKEKeyMaterial key;

  SILC_LOG_DEBUG(("Start"));

  if (!req_iv_len || !req_enc_key_len || !req_hmac_key_len)
    return NULL;

  key = silc_calloc(1, sizeof(*key));
  if (!key)
    return NULL;

  buf = silc_buffer_alloc_size(1 + data_len);
  if (!buf)
    return NULL;
  silc_buffer_format(buf,
		     SILC_STR_UI_CHAR(0),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);

  /* Take IVs */
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 0;
  silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
  key->send_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->send_iv, hashd, req_iv_len);
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 1;
  silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
  key->receive_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->receive_iv, hashd, req_iv_len);
  key->iv_len = req_iv_len;

  /* Take the encryption keys. If requested key size is more than
     the size of hash length we will distribute more key material
     as protocol defines. */
  buf->data[0] = 2;
  if (enc_key_len > hash_len) {
    SilcBuffer dist;
    unsigned char k1[SILC_HASH_MAXLEN], k2[SILC_HASH_MAXLEN],
	k3[SILC_HASH_MAXLEN];
    unsigned char *dtmp;

    /* XXX */
    if (enc_key_len > (3 * hash_len))
      return NULL;

    /* Take first round */
    memset(k1, 0, sizeof(k1));
    silc_hash_make(hash, buf->data, silc_buffer_len(buf), k1);

    /* Take second round */
    dist = silc_buffer_alloc_size(data_len + hash_len);
    if (!dist)
      return NULL;
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    memset(k2, 0, sizeof(k2));
    silc_hash_make(hash, dist->data, silc_buffer_len(dist), k2);

    /* Take third round */
    dist = silc_buffer_realloc(dist, data_len + hash_len + hash_len);
    silc_buffer_pull_tail(dist, hash_len);
    silc_buffer_pull(dist, data_len + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, data_len + hash_len);
    memset(k3, 0, sizeof(k3));
    silc_hash_make(hash, dist->data, silc_buffer_len(dist), k3);

    /* Then, save the keys */
    dtmp = silc_calloc((3 * hash_len), sizeof(unsigned char));
    memcpy(dtmp, k1, hash_len);
    memcpy(dtmp + hash_len, k2, hash_len);
    memcpy(dtmp + hash_len + hash_len, k3, hash_len);

    key->send_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->send_enc_key, dtmp, enc_key_len);
    key->enc_key_len = req_enc_key_len;

    memset(dtmp, 0, (3 * hash_len));
    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));
    memset(k3, 0, sizeof(k3));
    silc_free(dtmp);
    silc_buffer_clear(dist);
    silc_buffer_free(dist);
  } else {
    /* Take normal hash as key */
    memset(hashd, 0, sizeof(hashd));
    silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
    key->send_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->send_enc_key, hashd, enc_key_len);
    key->enc_key_len = req_enc_key_len;
  }

  buf->data[0] = 3;
  if (enc_key_len > hash_len) {
    SilcBuffer dist;
    unsigned char k1[SILC_HASH_MAXLEN], k2[SILC_HASH_MAXLEN],
	k3[SILC_HASH_MAXLEN];
    unsigned char *dtmp;

    /* XXX */
    if (enc_key_len > (3 * hash_len))
      return NULL;

    /* Take first round */
    memset(k1, 0, sizeof(k1));
    silc_hash_make(hash, buf->data, silc_buffer_len(buf), k1);

    /* Take second round */
    dist = silc_buffer_alloc_size(data_len + hash_len);
    if (!dist)
      return NULL;
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    memset(k2, 0, sizeof(k2));
    silc_hash_make(hash, dist->data, silc_buffer_len(dist), k2);

    /* Take third round */
    dist = silc_buffer_realloc(dist, data_len + hash_len + hash_len);
    silc_buffer_pull_tail(dist, hash_len);
    silc_buffer_pull(dist, data_len + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, data_len + hash_len);
    memset(k3, 0, sizeof(k3));
    silc_hash_make(hash, dist->data, silc_buffer_len(dist), k3);

    /* Then, save the keys */
    dtmp = silc_calloc((3 * hash_len), sizeof(unsigned char));
    memcpy(dtmp, k1, hash_len);
    memcpy(dtmp + hash_len, k2, hash_len);
    memcpy(dtmp + hash_len + hash_len, k3, hash_len);

    key->receive_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->receive_enc_key, dtmp, enc_key_len);
    key->enc_key_len = req_enc_key_len;

    memset(dtmp, 0, (3 * hash_len));
    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));
    memset(k3, 0, sizeof(k3));
    silc_free(dtmp);
    silc_buffer_clear(dist);
    silc_buffer_free(dist);
  } else {
    /* Take normal hash as key */
    memset(hashd, 0, sizeof(hashd));
    silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
    key->receive_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->receive_enc_key, hashd, enc_key_len);
    key->enc_key_len = req_enc_key_len;
  }

  /* Take HMAC keys */
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 4;
  silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
  key->send_hmac_key = silc_calloc(req_hmac_key_len, sizeof(unsigned char));
  memcpy(key->send_hmac_key, hashd, req_hmac_key_len);
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 5;
  silc_hash_make(hash, buf->data, silc_buffer_len(buf), hashd);
  key->receive_hmac_key = silc_calloc(req_hmac_key_len, sizeof(unsigned char));
  memcpy(key->receive_hmac_key, hashd, req_hmac_key_len);
  key->hmac_key_len = req_hmac_key_len;
  memset(hashd, 0, sizeof(hashd));

  silc_buffer_clear(buf);
  silc_buffer_free(buf);

  SILC_LOG_HEXDUMP(("enc"), key->send_enc_key, key->enc_key_len / 8);

  return key;
}

/* Processes negotiated key material as protocol specifies. This returns
   the actual keys to be used in the SILC. */

SilcSKEKeyMaterial
silc_ske_process_key_material(SilcSKE ske,
			      SilcUInt32 req_iv_len,
			      SilcUInt32 req_enc_key_len,
			      SilcUInt32 req_hmac_key_len,
			      SilcSKERekeyMaterial *rekey)
{
  SilcBuffer buf;
  unsigned char *tmpbuf;
  SilcUInt32 klen;
  SilcSKEKeyMaterial key;

  /* Encode KEY to binary data */
  tmpbuf = silc_mp_mp2bin(ske->KEY, 0, &klen);

  buf = silc_buffer_alloc_size(klen + ske->hash_len);
  if (!buf)
    return NULL;
  silc_buffer_format(buf,
		     SILC_STR_UI_XNSTRING(tmpbuf, klen),
		     SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
		     SILC_STR_END);

  /* Process the key material */
  key = silc_ske_process_key_material_data(buf->data, silc_buffer_len(buf),
					   req_iv_len, req_enc_key_len,
					   req_hmac_key_len,
					   ske->prop->hash);

  memset(tmpbuf, 0, klen);
  silc_free(tmpbuf);
  silc_buffer_clear(buf);
  silc_buffer_free(buf);

  if (rekey) {
    *rekey = silc_ske_make_rekey_material(ske, key);
    if (!(*rekey))
      return NULL;
  }

  return key;
}

/* Free key material structure */

void silc_ske_free_key_material(SilcSKEKeyMaterial key)
{
  if (!key)
    return;

  if (key->send_iv)
    silc_free(key->send_iv);
  if (key->receive_iv)
    silc_free(key->receive_iv);
  if (key->send_enc_key) {
    memset(key->send_enc_key, 0, key->enc_key_len / 8);
    silc_free(key->send_enc_key);
  }
  if (key->receive_enc_key) {
    memset(key->receive_enc_key, 0, key->enc_key_len / 8);
    silc_free(key->receive_enc_key);
  }
  if (key->send_hmac_key) {
    memset(key->send_hmac_key, 0, key->hmac_key_len);
    silc_free(key->send_hmac_key);
  }
  if (key->receive_hmac_key) {
    memset(key->receive_hmac_key, 0, key->hmac_key_len);
    silc_free(key->receive_hmac_key);
  }
  silc_free(key);
}

/* Free rekey material */

void silc_ske_free_rekey_material(SilcSKERekeyMaterial rekey)
{
  if (!rekey)
    return;
  if (rekey->send_enc_key) {
    memset(rekey->send_enc_key, 0, rekey->enc_key_len / 8);
    silc_free(rekey->send_enc_key);
  }
  silc_free(rekey->hash);
  silc_free(rekey);
}

/* Set keys into use */

SilcBool silc_ske_set_keys(SilcSKE ske,
			   SilcSKEKeyMaterial keymat,
			   SilcSKESecurityProperties prop,
			   SilcCipher *ret_send_key,
			   SilcCipher *ret_receive_key,
			   SilcHmac *ret_hmac_send,
			   SilcHmac *ret_hmac_receive,
			   SilcHash *ret_hash)
{
  unsigned char iv[32];

  /* Allocate ciphers to be used in the communication */
  if (ret_send_key) {
    if (!silc_cipher_alloc((char *)silc_cipher_get_name(prop->cipher),
			   ret_send_key))
      return FALSE;
  }
  if (ret_receive_key) {
    if (!silc_cipher_alloc((char *)silc_cipher_get_name(prop->cipher),
			   ret_receive_key))
      return FALSE;
  }

  /* Allocate HMACs */
  if (ret_hmac_send) {
    if (!silc_hmac_alloc((char *)silc_hmac_get_name(prop->hmac), NULL,
			 ret_hmac_send))
      return FALSE;
  }
  if (ret_hmac_receive) {
    if (!silc_hmac_alloc((char *)silc_hmac_get_name(prop->hmac), NULL,
			 ret_hmac_receive))
      return FALSE;
  }

  /* Set key material */
  memset(iv, 0, sizeof(iv));
  if (ske->responder) {
    if (ret_send_key) {
      silc_cipher_set_key(*ret_send_key, keymat->receive_enc_key,
			  keymat->enc_key_len, TRUE);

      if (silc_cipher_get_mode(*ret_send_key) == SILC_CIPHER_MODE_CTR) {
        memcpy(iv, ske->hash, 4);
        memcpy(iv + 4, keymat->receive_iv, 4);
        silc_cipher_set_iv(*ret_send_key, iv);
      } else {
	silc_cipher_set_iv(*ret_send_key, keymat->receive_iv);
      }
    }
    if (ret_receive_key) {
      silc_cipher_set_key(*ret_receive_key, keymat->send_enc_key,
			  keymat->enc_key_len, FALSE);

      if (silc_cipher_get_mode(*ret_receive_key) == SILC_CIPHER_MODE_CTR) {
        memcpy(iv, ske->hash, 4);
        memcpy(iv + 4, keymat->send_iv, 4);
        silc_cipher_set_iv(*ret_receive_key, iv);
      } else {
	silc_cipher_set_iv(*ret_receive_key, keymat->send_iv);
      }
    }
    if (ret_hmac_send)
      silc_hmac_set_key(*ret_hmac_send, keymat->receive_hmac_key,
			keymat->hmac_key_len);
    if (ret_hmac_receive)
      silc_hmac_set_key(*ret_hmac_receive, keymat->send_hmac_key,
			keymat->hmac_key_len);
  } else {
    if (ret_send_key) {
      silc_cipher_set_key(*ret_send_key, keymat->send_enc_key,
			  keymat->enc_key_len, TRUE);

      if (silc_cipher_get_mode(*ret_send_key) == SILC_CIPHER_MODE_CTR) {
        memcpy(iv, ske->hash, 4);
        memcpy(iv + 4, keymat->send_iv, 4);
	silc_cipher_set_iv(*ret_send_key, iv);
      } else {
	silc_cipher_set_iv(*ret_send_key, keymat->send_iv);
      }
    }
    if (ret_receive_key) {
      silc_cipher_set_key(*ret_receive_key, keymat->receive_enc_key,
			  keymat->enc_key_len, FALSE);

      if (silc_cipher_get_mode(*ret_receive_key) == SILC_CIPHER_MODE_CTR) {
        memcpy(iv, ske->hash, 4);
        memcpy(iv + 4, keymat->receive_iv, 4);
	silc_cipher_set_iv(*ret_receive_key, iv);
      } else {
	silc_cipher_set_iv(*ret_receive_key, keymat->receive_iv);
      }
    }
    if (ret_hmac_send)
      silc_hmac_set_key(*ret_hmac_send, keymat->send_hmac_key,
			keymat->hmac_key_len);
    if (ret_hmac_receive)
      silc_hmac_set_key(*ret_hmac_receive, keymat->receive_hmac_key,
			keymat->hmac_key_len);
  }

  /* Allocate hash */
  if (ret_hash) {
    if (!silc_hash_alloc(silc_hash_get_name(prop->hash), ret_hash))
      return FALSE;
  }

  return TRUE;
}

const char *silc_ske_status_string[] =
{
  /* Official */
  "Ok",
  "Unkown error occurred",
  "Bad payload in packet",
  "Unsupported group",
  "Unsupported cipher",
  "Unsupported PKCS",
  "Unsupported hash function",
  "Unsupported HMAC",
  "Unsupported public key (or certificate)",
  "Incorrect signature",
  "Bad or unsupported version",
  "Invalid cookie",

  /* Other errors */
  "Remote did not provide public key",
  "Bad reserved field in packet",
  "Bad payload length in packet",
  "Error computing signature",
  "System out of memory",
  "Key exchange timeout",

  NULL
};

/* Maps status to readable string and returns the string. If string is not
   found and empty character string ("") is returned. */

const char *silc_ske_map_status(SilcSKEStatus status)
{
  int i;

  for (i = 0; silc_ske_status_string[i]; i++)
    if (status == i)
      return silc_ske_status_string[i];

  return "";
}

/* Parses remote host's version string. */

SilcBool silc_ske_parse_version(SilcSKE ske,
				SilcUInt32 *protocol_version,
				char **protocol_version_string,
				SilcUInt32 *software_version,
				char **software_version_string,
				char **vendor_version)
{
  return silc_parse_version_string(ske->remote_version,
				   protocol_version,
				   protocol_version_string,
				   software_version,
				   software_version_string,
				   vendor_version);
}

/* Get security properties */

SilcSKESecurityProperties silc_ske_get_security_properties(SilcSKE ske)
{
  return ske->prop;
}

/* Get key material */

SilcSKEKeyMaterial silc_ske_get_key_material(SilcSKE ske)
{
  return ske->keymat;
}
