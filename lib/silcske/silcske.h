/*

  silcske.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSKE_H
#define SILCSKE_H

#include "silcske_status.h"

/* Forward declaration for SKE object. */
typedef struct SilcSKEStruct *SilcSKE;

/* Forward declaration for security properties. */
typedef struct SilcSKESecurityPropertiesStruct *SilcSKESecurityProperties;

/* Forward declaration for SKE callbacks structure. */
typedef struct SilcSKECallbacksStruct *SilcSKECallbacks;

/* Supported Public Key Types, defined by the protocol */
typedef enum {
  SILC_SKE_PK_TYPE_SILC    = 1,	/* Mandatory type */
  /* Optional types. These are not implemented currently */
  SILC_SKE_PK_TYPE_SSH2    = 2,
  SILC_SKE_PK_TYPE_X509V3  = 3,
  SILC_SKE_PK_TYPE_OPENPGP = 4,
  SILC_SKE_PK_TYPE_SPKI    = 5
} SilcSKEPKType;

/* Packet sending callback. Caller of the SKE routines must provide
   a routine to send packets to negotiation parties. See the
   silc_ske_set_callbacks for more information. */
typedef void (*SilcSKESendPacketCb)(SilcSKE ske, SilcBuffer packet, 
				    SilcPacketType type, void *context);

/* Generic SKE callback function. This is called in various SKE
   routines. The SilcSKE object sent as argument provides all the data
   callers routine might need (payloads etc). This is usually called
   to indicate that the application may continue the execution of the
   SKE protocol. The application should check the ske->status in this
   callback function. This callback is also called when Start Payload
   is processed. See silc_ske_set_callbacks function for more information. */
typedef void (*SilcSKECb)(SilcSKE ske, void *context);

/* Completion callback that will be called when the public key
   has been verified.  The `status' will indicate whether the public
   key were trusted or not. If the `status' is PENDING then the status
   is not considered to be available at this moment. In this case the
   SKE libary will assume that the caller will call this callback again
   when the status is available. See silc_ske_set_callbacks for more
   information. */
typedef void (*SilcSKEVerifyCbCompletion)(SilcSKE ske,
					  SilcSKEStatus status,
					  void *context);

/* Callback function used to verify the received public key or certificate. 
   The verification process is most likely asynchronous. That's why the
   application must call the `completion' callback when the verification
   process has been completed. The library then calls the user callback
   (SilcSKECb), if it was provided for the function that takes this callback
   function as argument, to indicate that the SKE protocol may continue. 
   See silc_ske_set_callbacks for more information. */
typedef void (*SilcSKEVerifyCb)(SilcSKE ske, 
				unsigned char *pk_data,
				uint32 pk_len,
				SilcSKEPKType pk_type,
				void *context,
				SilcSKEVerifyCbCompletion completion,
				void *completion_context);

/* Callback function used to check the version of the remote SKE server.
   The SKE library will call this function so that the appliation may
   check its version against the remote host's version. This returns
   SILC_SKE_STATUS_OK if the version string is Ok, and returns
   SILC_SKE_STATUS_BAD_VERSION if the version was not acceptable. */
typedef SilcSKEStatus (*SilcSKECheckVersion)(SilcSKE ske, 
					     unsigned char *version, 
					     uint32 len, void *context);

/* Context passed to key material processing function. The function
   returns the processed key material into this structure. */
typedef struct {
  unsigned char *send_iv;
  unsigned char *receive_iv;
  uint32 iv_len;
  unsigned char *send_enc_key;
  unsigned char *receive_enc_key;
  uint32 enc_key_len;
  unsigned char *hmac_key;
  uint32 hmac_key_len;
} SilcSKEKeyMaterial;

/* Length of cookie in Start Payload */
#define SILC_SKE_COOKIE_LEN 16

#include "groups.h"
#include "payload.h"

/* Security Property Flags. */
typedef enum {
  SILC_SKE_SP_FLAG_NONE      = 0x00,
  SILC_SKE_SP_FLAG_NO_REPLY  = 0x01,
  SILC_SKE_SP_FLAG_PFS       = 0x02,
  SILC_SKE_SP_FLAG_MUTUAL    = 0x04,
} SilcSKESecurityPropertyFlag;

/* Security Properties negotiated between key exchange parties. This
   structure is filled from the Key Exchange Start Payload which is used
   to negotiate what security properties should be used in the
   communication. */
struct SilcSKESecurityPropertiesStruct {
  unsigned char flags;
  SilcSKEDiffieHellmanGroup group;
  SilcPKCS pkcs;
  SilcCipher cipher;
  SilcHash hash;
  SilcHmac hmac;
  /* XXX SilcZip comp; */
};

struct SilcSKEStruct {
  /* The connection object. This is initialized by the caller. */
  SilcSocketConnection sock;

  /* Security properties negotiated */
  SilcSKESecurityProperties prop;

  /* Key Exchange payloads filled during key negotiation with
     remote data. Responder may save local data here as well. */
  SilcSKEStartPayload *start_payload;
  SilcSKEKEPayload *ke1_payload;
  SilcSKEKEPayload *ke2_payload;

  /* Temporary copy of the KE Start Payload used in the
     HASH computation. */
  SilcBuffer start_payload_copy;

  /* Random number x, 1 < x < q. This is the secret exponent
     used in Diffie Hellman computations. */
  SilcMPInt *x;
  
  /* The secret shared key */
  SilcMPInt *KEY;
  
  /* The hash value HASH of the key exchange */
  unsigned char *hash;
  uint32 hash_len;

  /* Random Number Generator. This is set by the caller and must
     be free'd by the caller. */
  SilcRng rng;

  /* Pointer to the what ever user data. This is set by the caller
     and is not touched by the SKE. The caller must also free this one. */
  void *user_data;

  /* Current status of SKE */
  SilcSKEStatus status;

  /* Reference counter. This is used when SKE library is performing async
     operations, like public key verification. */
  int users;

  /* SKE callbacks. */
  SilcSKECallbacks callbacks;
};

/* Prototypes */
SilcSKE silc_ske_alloc();
void silc_ske_free(SilcSKE ske);
void silc_ske_set_callbacks(SilcSKE ske,
			    SilcSKESendPacketCb send_packet,
			    SilcSKECb payload_receive,
			    SilcSKEVerifyCb verify_key,
			    SilcSKECb proto_continue,
			    SilcSKECheckVersion check_version,
			    void *context);
SilcSKEStatus silc_ske_initiator_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       SilcSKEStartPayload *start_payload);
SilcSKEStatus silc_ske_initiator_phase_1(SilcSKE ske, 
					 SilcBuffer start_payload);
SilcSKEStatus silc_ske_initiator_phase_2(SilcSKE ske,
					 SilcPublicKey public_key,
					 SilcPrivateKey private_key);
SilcSKEStatus silc_ske_initiator_finish(SilcSKE ske,
					SilcBuffer ke_payload);
SilcSKEStatus silc_ske_responder_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       char *version,
				       SilcBuffer start_payload,
				       bool mutual_auth);
SilcSKEStatus silc_ske_responder_phase_1(SilcSKE ske, 
					 SilcSKEStartPayload *start_payload);
SilcSKEStatus silc_ske_responder_phase_2(SilcSKE ske,
					 SilcBuffer ke_payload);
SilcSKEStatus silc_ske_responder_finish(SilcSKE ske,
					SilcPublicKey public_key,
					SilcPrivateKey private_key,
					SilcSKEPKType pk_type);
SilcSKEStatus silc_ske_end(SilcSKE ske);
SilcSKEStatus silc_ske_abort(SilcSKE ske, SilcSKEStatus status);
SilcSKEStatus 
silc_ske_assemble_security_properties(SilcSKE ske,
				      unsigned char flags,
				      char *version,
				      SilcSKEStartPayload **return_payload);
SilcSKEStatus 
silc_ske_select_security_properties(SilcSKE ske,
				    char *version,
				    SilcSKEStartPayload *payload,
				    SilcSKEStartPayload *remote_payload);
SilcSKEStatus silc_ske_create_rnd(SilcSKE ske, SilcMPInt *n, 
				  uint32 len, 
				  SilcMPInt *rnd);
SilcSKEStatus silc_ske_make_hash(SilcSKE ske, 
				 unsigned char *return_hash,
				 uint32 *return_hash_len,
				 int initiator);
SilcSKEStatus 
silc_ske_process_key_material_data(unsigned char *data,
				   uint32 data_len,
				   uint32 req_iv_len,
				   uint32 req_enc_key_len,
				   uint32 req_hmac_key_len,
				   SilcHash hash,
				   SilcSKEKeyMaterial *key);
SilcSKEStatus silc_ske_process_key_material(SilcSKE ske, 
					    uint32 req_iv_len,
					    uint32 req_enc_key_len,
					    uint32 req_hmac_key_len,
					    SilcSKEKeyMaterial *key);
void silc_ske_free_key_material(SilcSKEKeyMaterial *key);

#endif
