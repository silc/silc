/*

  silcske.h

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

/****h* silcske/SILC SKE Interface
 *
 * DESCRIPTION
 *
 * The SILC Key Exchange (SKE) protocol interface. The SKE protocol
 * is used to negotiate secret key material between two parties, to be used
 * as session key or some other key. For example, when client connects to
 * server SKE is performed to exchange public keys, and to generate the key
 * that is then used as session key. Two clients can execute SKE as well
 * two create secret key material for securing for example file transfer
 * stream. This SKE implementation provides easy interface for application
 * that wants to use SKE.
 *
 ***/

#ifndef SILCSKE_H
#define SILCSKE_H

/* Forward declarations */
typedef struct SilcSKECallbacksStruct *SilcSKECallbacks;
typedef struct SilcSKEStruct *SilcSKE;

/****d* silcske/SilcSKEAPI/SilcSKEStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcSKEStatus;
 *
 * DESCRIPTION
 *
 *    Status types returned in SKE callbacks. This tell the status of
 *    the SKE session, and if an error occurred. Application can map the
 *    status to human readable string with silc_ske_map_status function.
 *
 * SOURCE
 */
typedef enum {
  /* These are defined by the protocol */
  SILC_SKE_STATUS_OK                     = 0,  /* No error */
  SILC_SKE_STATUS_ERROR                  = 1,  /* Unknown error */
  SILC_SKE_STATUS_BAD_PAYLOAD            = 2,  /* Malformed payload */
  SILC_SKE_STATUS_UNKNOWN_GROUP          = 3,  /* Unsupported DH group */
  SILC_SKE_STATUS_UNKNOWN_CIPHER         = 4,  /* Unsupported cipher */
  SILC_SKE_STATUS_UNKNOWN_PKCS           = 5,  /* Unsupported PKCS algorithm */
  SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION  = 6,  /* Unsupported hash function */
  SILC_SKE_STATUS_UNKNOWN_HMAC           = 7,  /* Unsupported HMAC */
  SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY = 8,  /* Unsupported/not trusted PK */
  SILC_SKE_STATUS_INCORRECT_SIGNATURE    = 9,  /* Incorrect signature */
  SILC_SKE_STATUS_BAD_VERSION            = 10, /* Unsupported version */
  SILC_SKE_STATUS_INVALID_COOKIE         = 11, /* Cookie was modified */

  /* Implementation specific status types */
  SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED,     /* Remote did not send PK */
  SILC_SKE_STATUS_BAD_RESERVED_FIELD,	       /* Reserved field was not 0 */
  SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH,	       /* Payload includes garbage */
  SILC_SKE_STATUS_SIGNATURE_ERROR,	       /* Error computing signature */
  SILC_SKE_STATUS_OUT_OF_MEMORY,	       /* System out of memory */
} SilcSKEStatus;
/***/

#include "silcske_groups.h"
#include "silcske_payload.h"

/****d* silcske/SilcSKEAPI/SilcSKESecurityPropertyFlag
 *
 * NAME
 *
 *    typedef enum { ... } SilcSKESecurityPropertyFlag
 *
 * DESCRIPTION
 *
 *    SKE security property flags as defined by the SK protocol.
 *
 * SOURCE
 */
typedef enum {
  SILC_SKE_SP_FLAG_NONE         = 0x00,	 /* No flags */
  SILC_SKE_SP_FLAG_IV_INCLUDED  = 0x01,	 /* IV included in packet */
  SILC_SKE_SP_FLAG_PFS          = 0x02,	 /* Perfect Forward Secrecy */
  SILC_SKE_SP_FLAG_MUTUAL       = 0x04,	 /* Mutual authentication */
} SilcSKESecurityPropertyFlag;
/***/

/****s* silcske/SilcSKEAPI/SilcSKESecurityProperties
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSKESecurityProperties;
 *
 * DESCRIPTION
 *
 *    Security Properties negotiated between key exchange parties. This
 *    structure is filled from the Key Exchange Start Payload which is used
 *    to negotiate what security properties must be used in the
 *    communication.
 *
 * SOURCE
 */
typedef struct {
  SilcSKESecurityPropertyFlag flags;	 /* Flags */
  SilcSKEDiffieHellmanGroup group;	 /* Selected Diffie Hellman group */
  SilcCipher cipher;			 /* Selected cipher */
  SilcHmac hmac;			 /* Selected HMAC */
  SilcHash hash;			 /* Selected hash algorithm */
  SilcPKCS pkcs;			 /* Selected PKCS and remote's
					    public key/certificate */
} *SilcSKESecurityProperties;
/***/

/****s* silcske/SilcSKEAPI/SilcSKEKeyMaterial
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSKEKeyMaterial;
 *
 * DESCRIPTION
 *
 *    This is the key material structure, and is passed as argument by the
 *    application to silc_ske_process_key_material* functions. It includes
 *    the processed key material which can be used as SILC session keys.
 *
 * SOURCE
 */
typedef struct {
  unsigned char *send_iv;
  unsigned char *receive_iv;
  SilcUInt32 iv_len;
  unsigned char *send_enc_key;
  unsigned char *receive_enc_key;
  SilcUInt32 enc_key_len;
  unsigned char *send_hmac_key;
  unsigned char *receive_hmac_key;
  SilcUInt32 hmac_key_len;
} *SilcSKEKeyMaterial;
/***/

/****s* silcske/SilcSKEAPI/SilcSKERekeyMaterial
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSKERekeyMaterial;
 *
 * DESCRIPTION
 *
 *    This context is returned after key exchange protocol to application
 *    in the completion callback.  Application may save it and use it later
 *    to perform the rekey with silc_ske_rekey_initiator_start and/or
 *    silc_ske_rekey_responder_start functions.  If application does not
 *    need the context, it may free it with silc_free function.
 *
 *    Application may save application specific data to `user_context'.
 *
 * SOURCE
 */
typedef struct {
  void *user_context;		      /* Application specific data */
  unsigned char *send_enc_key;
  unsigned int enc_key_len  : 23;
  unsigned int ske_group    : 8;
  unsigned int pfs          : 1;
} *SilcSKERekeyMaterial;
/***/

/****d* silcske/SilcSKEAPI/SilcSKEPKType
 *
 * NAME
 *
 *    typedef enum { ... } SilcSKEPKType;
 *
 * DESCRIPTION
 *
 *    Public key and certificate types defined by the SKE protocol.
 *
 * SOURCE
 */
typedef enum {
  SILC_SKE_PK_TYPE_SILC    = 1,	/* SILC Public Key, mandatory */
  SILC_SKE_PK_TYPE_SSH2    = 2,	/* SSH2 Public key, not supported */
  SILC_SKE_PK_TYPE_X509V3  = 3,	/* X.509v3 certificate, not supported */
  SILC_SKE_PK_TYPE_OPENPGP = 4,	/* OpenPGP certificate, not supported */
  SILC_SKE_PK_TYPE_SPKI    = 5	/* SPKI certificate, not supported */
} SilcSKEPKType;
/***/

/****f* silcske/SilcSKEAPI/SilcSKEVerifyCbCompletion
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKEVerifyCbCompletion)(SilcSKE ske,
 *                                              SilcSKEStatus status,
 *                                              void *context);
 *
 * DESCRIPTION
 *
 *    Completion callback that will be called when the public key
 *    has been verified.  The `status' will indicate whether the public
 *    key were trusted or not. If the `status' is PENDING then the status
 *    is not considered to be available at this moment. In this case the
 *    SKE libary will assume that the caller will call this callback again
 *    when the status is available. See silc_ske_set_callbacks for more
 *    information.
 *
 ***/
typedef void (*SilcSKEVerifyCbCompletion)(SilcSKE ske,
					  SilcSKEStatus status,
					  void *context);

/****f* silcske/SilcSKEAPI/SilcSKEVerifyCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKEVerifyCb)(SilcSKE ske,
 *                                    const unsigned char *pk_data,
 *                                    SilcUInt32 pk_len,
 *                                    SilcSKEPKType pk_type,
 *                                    void *context,
 *                                    SilcSKEVerifyCbCompletion completion,
 *                                    void *completion_context);
 *
 * DESCRIPTION
 *
 *    Callback function used to verify the received public key or certificate.
 *    The verification process is most likely asynchronous.  That's why the
 *    application must call the `completion' callback when the verification
 *    process has been completed.  The `context' is the context given as
 *    arugment to silc_ske_set_callbacks.  See silc_ske_set_callbacks for
 *    more information.
 *
 ***/
typedef void (*SilcSKEVerifyCb)(SilcSKE ske,
				const unsigned char *pk_data,
				SilcUInt32 pk_len,
				SilcSKEPKType pk_type,
				void *context,
				SilcSKEVerifyCbCompletion completion,
				void *completion_context);

/****f* silcske/SilcSKEAPI/SilcSKECompletionCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKECompletionCb)(SilcSKE ske,
 *                                        SilcSKEStatus status,
 *                                        SilcSKESecurityProperties prop,
 *                                        SilcSKEKeyMaterial keymat,
 *                                        SilcSKERekeyMaterial rekey,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Completion callback.  This is called after the key exchange protocol
 *    has been completed.  It delivers the status of the protocol, and if
 *    successful the security properties `prop' that was negotiated in the
 *    protocol and the key material `keymat' that can be set into use by
 *    calling silc_ske_set_keys, and the rekey key material `rekey' which
 *    can be used later to start rekey protocol.  The `prop' will remain
 *    valid as long as `ske' is valid.  After `ske' is freed `prop' will
 *    become invalid.
 *
 ***/
typedef void (*SilcSKECompletionCb)(SilcSKE ske,
				    SilcSKEStatus status,
				    SilcSKESecurityProperties prop,
				    SilcSKEKeyMaterial keymat,
				    SilcSKERekeyMaterial rekey,
				    void *context);

/* Prototypes */

/****f* silcske/SilcSKEAPI/silc_ske_alloc
 *
 * SYNOPSIS
 *
 *    SilcSKE silc_ske_alloc(SilcRng rng, SilcSchedule schedule,
 *                           SilcPublicKey public_key,
 *                           SilcPrivateKey private_key, void *context);
 *
 * DESCRIPTION
 *
 *    Allocates the SKE session context and returns it.  The `rng' is
 *    the random number generator the SKE is going to use when it needs
 *    random number generation during the SKE session.  The `context' is
 *    user context that the libary will not touch.  Application can get the
 *    context by calling the fuction silc_ske_get_context function.  The
 *    application is responsible of freeing the `context'.  After the
 *    SKE session context is allocated application must call the
 *    silc_ske_set_callbacks.
 *
 * EXMPALE
 *
 *    // Initiator example
 *    ske = silc_ske_alloc(rng, scheduler, app);
 *    silc_ske_set_callbacks(ske, verify_public_key, completion, app);
 *    start_payload =
 *      silc_ske_assemble_security_properties(ske, SILC_SKE_SP_FLAG_PFS |
 *                                            SILC_SKE_SP_FLAG_MUTUAL,
 *                                            version);
 *    silc_ske_initiator_start(ske);
 *
 ***/
SilcSKE silc_ske_alloc(SilcRng rng, SilcSchedule schedule,
		       SilcPublicKey public_key, SilcPrivateKey private_key,
		       void *context);

/****f* silcske/SilcSKEAPI/silc_ske_free
 *
 * SYNOPSIS
 *
 *    void silc_ske_free(SilcSKE ske);
 *
 * DESCRIPTION
 *
 *    Frees the SKE session context and all allocated resources.
 *
 ***/
void silc_ske_free(SilcSKE ske);

/****f* silcske/SilcSKEAPI/silc_ske_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_ske_get_context(SilcSKE ske);
 *
 * DESCRIPTION
 *
 *    Returns the context that was given as argument to silc_ske_alloc.
 *
 ***/
void *silc_ske_get_context(SilcSKE ske);

/****f* silcske/SilcSKEAPI/silc_ske_set_callbacks
 *
 * SYNOPSIS
 *
 *    void silc_ske_set_callbacks(SilcSKE ske,
 *                                SilcSKEVerifyCb verify_key,
 *                                SilcSKECompletion completed,
 *                                void *context);
 *
 * DESCRIPTION
 *
 *    Sets the callback functions for the SKE session.
 *
 *    The `verify_key' callback is called to verify the received public key
 *    or certificate.  The verification process is most likely asynchronous.
 *    That is why the application must call the completion callback when the
 *    verification process has been completed.  If this SKE session context
 *    is used to perform  rekey, this callback usually is not provided as
 *    argument since sending public key in rekey is not mandatory.  Setting
 *    this callback implies that remote end MUST send its public key.
 *
 *    The `completed' callback will be called once the protocol has completed,
 *    either successfully or with an error.  The status of the protocol is
 *    delivered to application with the callback.
 *
 *    The `context' is passed as argument to all of the above callback
 *    functions.
 *
 ***/
void silc_ske_set_callbacks(SilcSKE ske,
			    SilcSKEVerifyCb verify_key,
			    SilcSKECompletionCb completed,
			    void *context);

/****f* silcske/SilcSKEAPI/silc_ske_initiator_start
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_ske_initiator_start(SilcSKE ske,
 *                             SilcPacketStream stream,
 *                             SilcSKEStartPayload start_payload);
 *
 * DESCRIPTION
 *
 *    Starts the SILC Key Exchange protocol as initiator.  The completion
 *    callback that was set in silc_ske_set_callbacks will be called once
 *    the protocol has completed.
 *
 *    The `stream' is the network connection to the remote host.  Note that
 *    SKE library will take over the packet stream `stream' while the
 *    protocol is in process.  The application will not receive any packets
 *    for `stream' after this function is called.  The `stream' is turned
 *    over to application once the completion callback is called.
 *
 *    The `start_payload' includes all configured security properties that
 *    will be sent to the responder.  The `start_payload' must be provided.
 *    It can be created by calling silc_ske_assemble_security_properties
 *    function.  The caller must not free the payload once it has been
 *    given as argument to this function.
 *
 *    This function returns SilcAsyncOperation operation context which can
 *    be used to control the protocol from the application.  Application may
 *    for example safely abort the protocol at any point, if needed.  Returns
 *    NULL on error.
 *
 ***/
SilcAsyncOperation
silc_ske_initiator(SilcSKE ske,
		   SilcPacketStream stream,
		   SilcSKEStartPayload start_payload);

/****f* silcske/SilcSKEAPI/silc_ske_responder_start
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_ske_responder_start(SilcSKE ske,
 *                             SilcPacketStream stream,
 *                             const char *version,
 *                             SilcBuffer start_payload,
 *                             SilcSKESecurityPropertyFlag flags);
 *
 * DESCRIPTION
 *
 *    Starts SILC Key Exchange protocol as responder.  The completion
 *    callback that was set in silc_ske_set_callbacks will be called once
 *    the protocol has completed.
 *
 *    The `stream' is the network connection to the remote host.  Note that
 *    SKE library will take over the packet stream `stream' while the
 *    protocol is in process.  The application will not receive any packets
 *    for `stream' after this function is called.  The `stream' is turned
 *    over to application once the completion callback is called.
 *
 *    The `version' is the responder's SILC protocol version that will be
 *    sent in reply to the initiator.  The `flags' indicates the
 *    SilcSKESecurityPropertyFlag flags that responder supports and enforces
 *    for the initiator.  Responder may, for example, enforce that the PFS
 *    will be performed in rekey.
 *
 *    This function returns SilcAsyncOperation operation context which can
 *    be used to control the protocol from the application.  Application may
 *    for example safely abort the protocol at any point, if needed.  Returns
 *    NULL on error.
 *
 ***/
SilcAsyncOperation
silc_ske_responder(SilcSKE ske,
		   SilcPacketStream stream,
		   const char *version,
		   SilcSKESecurityPropertyFlag flags);

SilcAsyncOperation
silc_ske_rekey_initiator(SilcSKE ske,
			 SilcPacketStream stream,
			 SilcSKERekeyMaterial rekey);

SilcAsyncOperation
silc_ske_rekey_responder(SilcSKE ske,
			 SilcPacketStream stream,
			 SilcBuffer ke_payload,
			 SilcSKERekeyMaterial rekey);

/****f* silcske/SilcSKEAPI/silc_ske_assemble_security_properties
 *
 * SYNOPSIS
 *
 *    SilcSKEStartPayload
 *    silc_ske_assemble_security_properties(SilcSKE ske,
 *                                          SilcSKESecurityPropertyFlag flags,
 *                                          const char *version);
 *
 * DESCRIPTION
 *
 *    Assembles security properties to Key Exchange Start Payload to be
 *    sent to the remote end.  This checks system wide (SILC system, that is)
 *    settings and chooses from those.  However, if other properties
 *    should be used this function is easy to replace by another function.
 *    Returns NULL on error.  This is an utility function.  This is used
 *    by the initiator of the protocol.  The `version' is the local SILC
 *    protocol version string.
 *
 ***/
SilcSKEStartPayload
silc_ske_assemble_security_properties(SilcSKE ske,
				      SilcSKESecurityPropertyFlag flags,
				      const char *version);

/****f* silcske/SilcSKEAPI/silc_ske_assemble_security_properties
 *
 * SYNOPSIS
 *
 *    SilcBool silc_ske_set_keys(SilcSKE ske,
 *                               SilcSKEKeyMaterial keymat,
 *                               SilcSKESecurityProperties prop,
 *                               SilcCipher *ret_send_key,
 *                               SilcCipher *ret_receive_key,
 *                               SilcHmac *ret_hmac_send,
 *                               SilcHmac *ret_hmac_receive,
 *                               SilcHash *ret_hash);
 *
 * DESCRIPTION
 *
 *    This function can be used after successful key exchange to take the
 *    key material `keymat' with security properties `prop' into use.
 *    This will allocate send and receive ciphers, HMACs and hash for the
 *    application.  Caller must free the returned contexts.  This is an
 *    utility function.
 *
 ***/
SilcBool silc_ske_set_keys(SilcSKE ske,
			   SilcSKEKeyMaterial keymat,
			   SilcSKESecurityProperties prop,
			   SilcCipher *ret_send_key,
			   SilcCipher *ret_receive_key,
			   SilcHmac *ret_hmac_send,
			   SilcHmac *ret_hmac_receive,
			   SilcHash *ret_hash);

/****f* silcske/SilcSKEAPI/silc_ske_parse_version
 *
 * SYNOPSIS
 *
 *    SilcBool silc_ske_parse_version(SilcSKE ske,
 *                                    SilcUInt32 *protocol_version,
 *                                    char **protocol_version_string,
 *                                    SilcUInt32 *software_version,
 *                                    char **software_version_string,
 *                                    char **vendor_version);
 *
 * DESCRIPTION
 *
 *    Utility function to parse the remote host's version string.
 *
 ***/
SilcBool silc_ske_parse_version(SilcSKE ske,
				SilcUInt32 *protocol_version,
				char **protocol_version_string,
				SilcUInt32 *software_version,
				char **software_version_string,
				char **vendor_version);

/****f* silcske/SilcSKEAPI/silc_ske_map_status
 *
 * SYNOPSIS
 *
 *    const char *silc_ske_map_status(SilcSKEStatus status);
 *
 * DESCRIPTION
 *
 *    Utility function to map the `status' into human readable message.
 *
 ***/
const char *silc_ske_map_status(SilcSKEStatus status);

#include "silcske_i.h"

#endif	/* !SILCSKE_H */
