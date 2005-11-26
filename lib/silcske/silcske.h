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

#ifndef SILCSKE_H
#define SILCSKE_H

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
 * stream.
 *
 * This SKE implementation provides easy interface for application
 * that wants to use SKE. In fact, the interface is designed to be
 * application independent, and does not expect that the application using
 * SKE would actually relate in any way to SILC. Hence, the interface
 * can be used in any kind of application needing to perform key exchange
 * protocol with two parties. The network connection is also handled
 * outside the SKE interface.
 *
 * The protocol has initiator and responder. The initiator is the one
 * that starts the protocol, and the responder is the one that receives
 * negotiation request. The protocol has phases, and the interface is
 * split into several phases that the application may call when
 * needed. Heavy operations has been splitted so that application may
 * call next phase with a timeout to give processing times to other
 * things in the application. On the other hand, if application does
 * not care about this it may call the phases immediately without any
 * timeout.
 *
 ***/

#include "silcske_status.h"

/* Length of cookie in Start Payload */
#define SILC_SKE_COOKIE_LEN 16

/* Forward declarations */
typedef struct SilcSKECallbacksStruct *SilcSKECallbacks;
typedef struct SilcSKEStruct *SilcSKE;

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
 *    to negotiate what security properties should be used in the
 *    communication.
 *
 * SOURCE
 */
typedef struct {
  SilcSKESecurityPropertyFlag flags;	 /* Flags */
  SilcSKEDiffieHellmanGroup group;	 /* Selected Diffie Hellman group */
  SilcPKCS pkcs;			 /* Selected PKCS algorithm */
  SilcCipher cipher;			 /* Selected cipher */
  SilcHash hash;			 /* Selected hash algorithm */
  SilcHmac hmac;			 /* Selected HMAC */
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

/****f* silcske/SilcSKEAPI/SilcSKECheckVersion
 *
 * SYNOPSIS
 *
 *    typedef SilcSKEStatus
 *    (*SilcSKECheckVersionCb)(SilcSKE ske,
 *                             const unsigned char *version,
 *                             SilcUInt32 len, void *context);
 *
 * DESCRIPTION
 *
 *    Callback function used to check the version of the remote SKE server.
 *    The SKE library will call this function so that the appliation may
 *    check its version against the remote host's version.  This returns
 *    SILC_SKE_STATUS_OK if the version string is Ok, and returns
 *    SILC_SKE_STATUS_BAD_VERSION if the version was not acceptable.
 *
 ***/
typedef SilcSKEStatus (*SilcSKECheckVersionCb)(SilcSKE ske,
					       const unsigned char *version,
					       SilcUInt32 len, void *context);

/****f* silcske/SilcSKEAPI/SilcSKECompletionCb
 *
 * SYNOPSIS
 *
 *
 * DESCRIPTION
 *
 *
 ***/
typedef void (*SilcSKECompletionCb)(SilcSKE ske,
				    SilcSKEStatus status,
				    SilcSKESecurityProperties prop,
				    SilcSKEKeyMaterial keymat,
				    SilcSKERekeyMaterial rekey,
				    void *context);

/****s* silcske/SilcSKEAPI/SilcSKEStruct
 *
 * NAME
 *
 *    struct SilcSKEStruct { ... };
 *
 * DESCRIPTION
 *
 *    This structure is the SKE session context, and has a type definition
 *    to SilcSKE. The structure includes the network connection socket,
 *    security properties collected during the SKE negotiation, payloads
 *    sent and received during the negotiation, and the actual raw key
 *    material too. The application usually does not need to reference
 *    to the inside of this structure.  However, checking the current
 *    status of the session can easily be checked with ske->status.
 *
 * SOURCE
 */
struct SilcSKEStruct {
  /* The network socket connection stream.  Set by application. */
  SilcPacketStream stream;

  /* Negotiated Security properties.  May be NULL in case of error. */
  SilcSKESecurityProperties prop;

  /* Key Exchange payloads filled during key negotiation with
     remote data. Responder may save local data here as well. */
  SilcSKEStartPayload start_payload;
  SilcSKEKEPayload ke1_payload;
  SilcSKEKEPayload ke2_payload;
  unsigned char *remote_version;

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
  SilcUInt32 hash_len;

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

  /* Backwards support version indicator */
  SilcUInt32 backward_version;

  char *version;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;
  SilcSKEPKType pk_type;
  SilcBuffer packet_buf;
  SilcSKESecurityPropertyFlag flags;
  SilcSKEKeyMaterial keymat;
  SilcSKERekeyMaterial rekey;
  SilcSchedule schedule;
  SilcFSMStruct fsm;
  SilcAsyncOperationStruct op;
  SilcBool aborted;
};
/***/

/* Prototypes */

/****f* silcske/SilcSKEAPI/silc_ske_alloc
 *
 * SYNOPSIS
 *
 *    SilcSKE silc_ske_alloc(SilcRng rng, SilcSchedule schedule,
 *                           void *context);
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
 *    silc_ske_set_callbacks(ske, verify_public_key, check_version, app);
 *    start_payload =
 *      silc_ske_assemble_security_properties(ske, SILC_SKE_SP_FLAG_PFS |
 *                                            SILC_SKE_SP_FLAG_MUTUAL,
 *                                            version);
 *    silc_ske_initiator_start(ske);
 *
 ***/
SilcSKE silc_ske_alloc(SilcRng rng, SilcSchedule schedule, void *context);

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
 *                                SilcSKECheckVersion check_version,
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
 *    The `check_version' callback is called to verify the remote host's
 *    version.  The application may check its own version against the remote
 *    host's version and determine whether supporting the remote host
 *    is possible.
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
			    SilcSKECheckVersionCb check_version,
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
silc_ske_initiator_start(SilcSKE ske,
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
 *    The application has received initiator's first packet from network
 *    and it must provide it as `start_payload' argument to this function.
 *    The function processes the packet and makes security property selection
 *    from the initiator's proposal.  The `version' is the responder's version
 *    that will be sent in reply to the initiator.  The `flags' indicates
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
silc_ske_responder_start(SilcSKE ske,
			 SilcPacketStream stream,
			 const char *version,
			 SilcBuffer start_payload,
			 SilcSKESecurityPropertyFlag flags);

SilcAsyncOperation
silc_ske_rekey_initiator_start(SilcSKE ske,
			       SilcPacketStream stream,
			       SilcSKERekeyMaterial rekey);

SilcAsyncOperation
silc_ske_rekey_responder_start(SilcSKE ske,
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
 *    should be used this function is easy to replace by another function,
 *    as, this function is called by the caller of the library and not
 *    by the SKE library itself.  Returns NULL on error.
 *
 ***/
SilcSKEStartPayload
silc_ske_assemble_security_properties(SilcSKE ske,
				      SilcSKESecurityPropertyFlag flags,
				      const char *version);

/****f* silcske/SilcSKEAPI/silc_ske_parse_version
 *
 * SYNOPSIS
 *
 *    SilcBool silc_ske_parse_version(SilcSKE ske,
 *                                SilcUInt32 *protocol_version,
 *                                char **protocol_version_string,
 *                                SilcUInt32 *software_version,
 *                                char **software_version_string,
 *                                char **vendor_version);
 *
 * DESCRIPTION
 *
 *    This utility function can be used to parse the remote host's version
 *    string.  This returns the protocol version, and software version into
 *    the `protocol_version', `software_version' and `vendor_version' pointers
 *    if they are provided.  The string versions of the versions are saved
 *    in *_string pointers if they are provided.  Returns TRUE if the version
 *    string was successfully parsed.
 *
 ***/
SilcBool silc_ske_parse_version(SilcSKE ske,
			    SilcUInt32 *protocol_version,
			    char **protocol_version_string,
			    SilcUInt32 *software_version,
			    char **software_version_string,
			    char **vendor_version);

#endif	/* !SILCSKE_H */
