/*

  silcske.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2002 Pekka Riikonen

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

/****h* silcske/SilcSKEAPI
 *
 * DESCRIPTION
 *
 * Implementation of the SILC Key Exchange Protocol (SKE). The SKE protocol
 * is used to negotiate secret key material between two parties, to be used
 * as session key or some other key. For example, when client connects to
 * server SKE is performed to exchange public keys, and to generate the key
 * that is then used as session key. Two clients can execute SKE as well
 * two create secret key material for securing for example file transfer
 * stream.
 *
 * SKE is based on Diffie-Hellman, and it derives its functionality from
 * SSH2 Key Exchange protocol, OAKLEY Key Determination protocol and
 * Station-To-Station (STS) protocols.
 *
 * This SKE implementation provides easy interface for application
 * that wants to use SKE. In fact, the interface is designed to be 
 * application independent, and does not expect that the application using
 * SKE would actually relate in any way to SILC. Hence, the interface
 * can be used in any kind of application needing to perform key exchange
 * protocol with two parties. The network connection is also handled
 * outside the SKE interface. For the interface application must provide
 * a packet sending function which SKE library can call when it wants
 * to send packet to the remote host. The actual network connection
 * therefore is handled in the application and not by the SKE library.
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

/****s* silcske/SilcSKEAPI/SilcSKE
 *
 * NAME
 *
 *    typedef struct SilcSKEStruct *SilcSKE;
 *
 * DESCRIPTION
 *
 *    This context is forward declaration for the SilcSKEStruct.
 *    This is allocated by the silc_ske_alloc and freed by the
 *    silc_ske_free function. This context represents the SKE session.
 *
 ***/
typedef struct SilcSKEStruct *SilcSKE;

/****s* silcske/SilcSKEAPI/SilcSKESecurityProperties
 *
 * NAME
 *
 *    typedef struct SilcSKESecurityPropertiesStruct
 *                                 *SilcSKESecurityProperties;
 *
 * DESCRIPTION
 *
 *    This context is forward declaration for the
 *    SilcSKESecurityPropertiesStruct structure. It is allocated by the
 *    library, and it represents the security properties selected during
 *    the SKE negotiation.
 *
 ***/
typedef struct SilcSKESecurityPropertiesStruct *SilcSKESecurityProperties;

/* Forward declaration for SKE callbacks structure, which is internal. */
typedef struct SilcSKECallbacksStruct *SilcSKECallbacks;

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
  SILC_SKE_PK_TYPE_SILC    = 1,	/* Mandatory type */
  /* Optional types. These are not implemented currently */
  SILC_SKE_PK_TYPE_SSH2    = 2,
  SILC_SKE_PK_TYPE_X509V3  = 3,
  SILC_SKE_PK_TYPE_OPENPGP = 4,
  SILC_SKE_PK_TYPE_SPKI    = 5
} SilcSKEPKType;
/***/

/****f* silcske/SilcSKEAPI/SilcSKESendPacketCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKESendPacketCb)(SilcSKE ske, SilcBuffer packet,
 *                                        SilcPacketType type, void *context);
 *
 * DESCRIPTION
 *
 *    Packet sending callback. Caller of the SKE routines must provide
 *    a routine to send packets to negotiation parties. See the
 *    silc_ske_set_callbacks for more information.
 *
 ***/
typedef void (*SilcSKESendPacketCb)(SilcSKE ske, SilcBuffer packet,
				    SilcPacketType type, void *context);

/****f* silcske/SilcSKEAPI/SilcSKECb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKECb)(SilcSKE ske, void *context);
 *
 * DESCRIPTION
 *
 *    Generic SKE callback function. This is called in various SKE
 *    routines. The SilcSKE object sent as argument provides all the data
 *    callers routine might need (payloads etc). This is usually called
 *    to indicate that the application may continue the execution of the
 *    SKE protocol. The application should check the ske->status in this
 *    callback function. This callback is also called when Start Payload
 *    is processed. See silc_ske_set_callbacks function for more information.
 *
 ***/
typedef void (*SilcSKECb)(SilcSKE ske, void *context);

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
 *                                    unsigned char *pk_data,
 *                                    SilcUInt32 pk_len,
 *                                    SilcSKEPKType pk_type,
 *                                    void *context,
 *                                    SilcSKEVerifyCbCompletion completion,
 *                                    void *completion_context);
 *
 * DESCRIPTION
 *
 *    Callback function used to verify the received public key or certificate.
 *    The verification process is most likely asynchronous. That's why the
 *    application must call the `completion' callback when the verification
 *    process has been completed. The library then calls the user callback
 *    (SilcSKECb), if it was provided for the function that takes this callback
 *    function as argument, to indicate that the SKE protocol may continue.
 *    See silc_ske_set_callbacks for more information.
 *
 ***/
typedef void (*SilcSKEVerifyCb)(SilcSKE ske,
				unsigned char *pk_data,
				SilcUInt32 pk_len,
				SilcSKEPKType pk_type,
				void *context,
				SilcSKEVerifyCbCompletion completion,
				void *completion_context);

/****f* silcske/SilcSKEAPI/SilcSKECheckVersion
 *
 * SYNOPSIS
 *
 *    typedef SilcSKEStatus (*SilcSKECheckVersion)(SilcSKE ske,
 *                                                 unsigned char *version,
 *                                                 SilcUInt32 len, void *context);
 *
 * DESCRIPTION
 *
 *    Callback function used to check the version of the remote SKE server.
 *    The SKE library will call this function so that the appliation may
 *    check its version against the remote host's version. This returns
 *    SILC_SKE_STATUS_OK if the version string is Ok, and returns
 *    SILC_SKE_STATUS_BAD_VERSION if the version was not acceptable.
 *
 ***/
typedef SilcSKEStatus (*SilcSKECheckVersion)(SilcSKE ske,
					     unsigned char *version,
					     SilcUInt32 len, void *context);

/****s* silcske/SilcSKEAPI/SilcSKEKeyMaterial
 *
 * NAME
 *
 *    typedef struct { ... } SilcSKEKeyMaterial;
 *
 * DESCRIPTION
 *
 *    This is the key material structure, and is passed as argument by the
 *    application to silc_ske_process_key_material* functions. It includes
 *    the processed key material which can be used as SILC session keys.
 *
 ***/
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
} SilcSKEKeyMaterial;

/* Length of cookie in Start Payload */
#define SILC_SKE_COOKIE_LEN 16

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
  SILC_SKE_SP_FLAG_NONE      = 0x00,     /* No flags */
  SILC_SKE_SP_FLAG_NO_REPLY  = 0x01,	 /* No reply required to payload */
  SILC_SKE_SP_FLAG_PFS       = 0x02,	 /* Perfect Forward Secrecy */
  SILC_SKE_SP_FLAG_MUTUAL    = 0x04,	 /* Mutual authentication */
} SilcSKESecurityPropertyFlag;
/***/

/****s* silcske/SilcSKEAPI/SilcSKESecurityPropertiesStruct
 *
 * NAME
 *
 *    struct SilcSKESecurityPropertiesStruct { ... };
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
struct SilcSKESecurityPropertiesStruct {
  SilcSKESecurityPropertyFlag flags;	 /* Flags */
  SilcSKEDiffieHellmanGroup group;	 /* Selected Diffie Hellman group */
  SilcPKCS pkcs;			 /* Selected PKCS algorithm */
  SilcCipher cipher;			 /* Selected cipher */
  SilcHash hash;			 /* Selected hash algorithm */
  SilcHmac hmac;			 /* Selected HMAC */
};
/***/

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
 *    securit properties collected during the SKE negotiation, payloads
 *    sent and received during the negotiation, and the actual raw key
 *    material too. The application usually does not need to reference
 *    to the inside of this structure.  However, checking the current
 *    status of the session can easily be checked with ske->status.
 *
 * SOURCE
 */
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
};
/***/

/* Prototypes */

/****f* silcske/SilcSKEAPI/silc_ske_alloc
 *
 * SYNOPSIS
 *
 *    SilcSKE silc_ske_alloc(SilcRng rng, void *context);
 *
 * DESCRIPTION
 *
 *    Allocates the SKE session context and returns it.  The `rng' is
 *    the random number generator the SKE is going to use when it needs
 *    random number generation during the SKE session.  The `context' is
 *    user context that the libary will not touch.  The application can
 *    access that context with the ske->user_context if needed.  The
 *    application is responsible of freeing the `context'.  After the
 *    SKE session context is allocated application must call the
 *    silc_ske_set_callbacks.
 *
 ***/
SilcSKE silc_ske_alloc(SilcRng rng, void *context);

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

/****f* silcske/SilcSKEAPI/silc_ske_set_callbacks
 *
 * SYNOPSIS
 *
 *    void silc_ske_set_callbacks(SilcSKE ske,
 *                                SilcSKESendPacketCb send_packet,
 *                                SilcSKECb payload_receive,
 *                                SilcSKEVerifyCb verify_key,
 *                                SilcSKECb proto_continue,
 *                                SilcSKECheckVersion check_version,
 *                                void *context);
 *
 * DESCRIPTION
 *
 *    Sets the callback functions for the SKE session.
 *
 *    The `send_packet' callback is a function that sends the packet to
 *    network. The SKE library will call it at any time packet needs to
 *    be sent to the remote host.
 *
 *    The `payload_receive' callback is called when the remote host's Key
 *    Exchange Start Payload has been processed.  The payload is saved
 *    to ske->start_payload if the application would need it.  The application
 *    must also provide the payload to the next state of the SKE.
 *
 *    The `verify_key' callback is called to verify the received public key
 *    or certificate.  The verification process is most likely asynchronous.
 *    That is why the application must call the completion callback when the
 *    verification process has been completed. The library then calls the user
 *    callback (`proto_continue'), if it is provided to indicate that the SKE
 *    protocol may continue. If this SKE session context is used to perform
 *    rekey, this callback usually is not provided as argument since sending
 *    public key in rekey is not mandatory. Setting this callback implies
 *    that remote end MUST send its public key, and this could cause
 *    problems when performing rekey. When doing normal SKE session this
 *    callback should be set.
 *
 *    The `proto_continue' callback is called to indicate that it is
 *    safe to continue the execution of the SKE protocol after executing
 *    an asynchronous operation, such as calling the `verify_key' callback
 *    function, which is asynchronous. The application should check the
 *    ske->status in this function to check whether it is Ok to continue
 *    the execution of the protocol.
 *
 *    The `check_version' callback is called to verify the remote host's
 *    version. The application may check its own version against the remote
 *    host's version and determine whether supporting the remote host
 *    is possible.
 *
 *    The `context' is passed as argument to all of the above callback
 *    functions.
 *
 ***/
void silc_ske_set_callbacks(SilcSKE ske,
			    SilcSKESendPacketCb send_packet,
			    SilcSKECb payload_receive,
			    SilcSKEVerifyCb verify_key,
			    SilcSKECb proto_continue,
			    SilcSKECheckVersion check_version,
			    void *context);

/****f* silcske/SilcSKEAPI/silc_ske_initiator_start
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_initiator_start(SilcSKE ske, SilcRng rng,
 *                                           SilcSocketConnection sock,
 *                                           SilcSKEStartPayload
 *                                              *start_payload);
 *
 * DESCRIPTION
 *
 *    Starts the SILC Key Exchange protocol for initiator. The connection
 *    to the responder end must be established before calling this function
 *    and the connecting socket must be sent as argument. This function
 *    creates the Key Exchange Start Payload which includes all our
 *    configured security properties. This payload is then sent to the
 *    responder end for further processing. This payload must be sent as
 *    argument to the function, however, it must not be encoded
 *    already, it is done by this function. The caller must not free
 *    the `start_payload' since the SKE library will save it.
 *
 *    Before calling this function application calls the
 *    silc_ske_assemble_security_properties which returns the `start_payload'
 *    which application must provide for this function.
 *
 *    After calling this function the application must wait for reply
 *    from the responder.
 *
 ***/
SilcSKEStatus silc_ske_initiator_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       SilcSKEStartPayload *start_payload);

/****f* silcske/SilcSKEAPI/silc_ske_initiator_phase_1
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_initiator_phase_1(SilcSKE ske,
 *                                             SilcBuffer start_payload);
 *
 * DESCRIPTION
 *
 *    Function called after ske_initiator_start fuction. This receives
 *    the responder's Key Exchange Start payload which includes the
 *    security properties selected by the responder from our payload
 *    sent in the silc_ske_initiator_start function. The `start_payload'
 *    is the received payload and the application must send it as argument.
 *
 *    After calling this function the application must call immediately,
 *    or with short timeout, the silc_ske_initiator_phase_2 function.
 *
 ***/
SilcSKEStatus silc_ske_initiator_phase_1(SilcSKE ske,
					 SilcBuffer start_payload);

/****f* silcske/SilcSKEAPI/silc_ske_initiator_phase_2
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_initiator_phase_2(SilcSKE ske,
 *                                             SilcPublicKey public_key,
 *                                             SilcPrivateKey private_key,
 *                                             SilcSKEPKType pk_type)
 *
 * DESCRIPTION
 *
 *    This function continues the SKE session after the initiator has
 *    called the silc_ske_initiator_phase_1.  After that function returns
 *    the application should call immediately, or with short timeout, this
 *    function which will continue with the session, and sends next phase
 *    packet to the responder.  The caller must provide the caller's
 *    public key and private key as argument, since the public key is
 *    sent to the responder, and the private key is be used to generate
 *    digital signature.
 *
 *    After this function the application must wait for reply from the
 *    responder.
 *
 ***/
SilcSKEStatus silc_ske_initiator_phase_2(SilcSKE ske,
					 SilcPublicKey public_key,
					 SilcPrivateKey private_key,
					 SilcSKEPKType pk_type);

/****f* silcske/SilcSKEAPI/silc_ske_initiator_finish
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_initiator_finish(SilcSKE ske,
 *                                            SilcBuffer ke_payload);
 *
 * DESCRIPTION
 *
 *    Receives the reply from the responder and processes it.  The
 *    `ke_payload' is the reply and application must provide it as argument.
 *    This function will verify the responder's public key, by calling
 *    the `verify_key' callback that was set with silc_ske_set_callbacks
 *    function.
 *
 *    If this function returns error, no callbacks will be called. If
 *    this function needs to verify remote end's public key, this will
 *    return SILC_SKE_STATUS_PENDING, which indicates application that
 *    SKE is performing asynchronous operation and is in pending status.
 *    When in this status application must not continue with calling
 *    any other SKE routine. The asynchronous operation is the `verify_key'
 *    callback, which application completes by calling its completion
 *    callback. After completion the SKE libary will call the 
 *    `proto_continue' callback, to indicate application that pending
 *    status is over and it is safe to continue the execution of SKE,
 *    which application does by calling the silc_ske_end function.
 *
 *    If this function returns SILC_SKE_STATUS_OK, it will not call the
 *    `verify_key' callback, however, it will or has already called the
 *    `proto_continue' callback.
 *
 *    Application must not continue execution of the SKE before library
 *    has called the `proto_continue' callback.  After it is called
 *    the application finishes SKE session by calling silc_ske_end
 *    function.
 *
 ***/
SilcSKEStatus silc_ske_initiator_finish(SilcSKE ske,
					SilcBuffer ke_payload);

/****f* silcske/SilcSKEAPI/silc_ske_responder_start
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_responder_start(SilcSKE ske, SilcRng rng,
 *                                           SilcSocketConnection sock,
 *                                           const char *version,
 *                                           SilcBuffer start_payload,
 *                                           SilcSKESecurityPropertyFlag 
 *                                                               flags);
 *
 * DESCRIPTION
 *
 *    Starts Key Exchange protocol for responder. The application has
 *    received initiator's first packet from network and it must provide
 *    it as `start_payload' argument to this function. The function 
 *    processes the packet and makes security property selection from
 *    the initiator's proposal. The `version' is the responder's version
 *    that will be sent in reply to the initiator. The `flags' indicates
 *    SilcSKESecurityPropertyFlag flags that responder enforces for the
 *    initiator. Responder may, for example, enforce that the PFS
 *    will be performed in rekey. This example can be done by providing
 *    SILC_SKE_SP_FLAG_PFS as `flags'. The `flags' is a bit mask of
 *    enforced flags.
 *
 *    After this function the responder calls immediately, or with short
 *    timeout the silc_ske_responder_phase_1 function.
 *
 ***/
SilcSKEStatus silc_ske_responder_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       const char *version,
				       SilcBuffer start_payload,
				       SilcSKESecurityPropertyFlag flags);

/****f* silcske/SilcSKEAPI/silc_ske_responder_phase_1
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_responder_phase_1(SilcSKE ske);
 *
 * DESCRIPTION
 *
 *    This function is called after the silc_ske_responder_start, and
 *    is used to send our reply to the initiator.  This function is
 *    called either immediately, or with short timeout, after the
 *    silc_ske_responder_start function returned.
 *
 *    After this function the responder must wait for reply from the
 *    initiator.
 *
 ***/
SilcSKEStatus silc_ske_responder_phase_1(SilcSKE ske);

/****f* silcske/SilcSKEAPI/silc_ske_responder_phase_2
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_responder_phase_2(SilcSKE ske,
 *                                             SilcBuffer ke_payload);
 *
 * DESCRIPTION
 *
 *    Receives the reply from the initiator and procedses it.  The
 *    `ke_payload' is the reply and application must provide it as argument.
 *    This function will verify the remote host's public key, by calling
 *    the `verify_key' callback that was set with silc_ske_set_callbacks
 *    function.
 *
 *    If this function returns error, no callbacks will be called. If
 *    this function needs to verify remote end's public key, this will
 *    return SILC_SKE_STATUS_PENDING, which indicates application that
 *    SKE is performing asynchronous operation and is in pending status.
 *    When in this status application must not continue with calling
 *    any other SKE routine. The asynchronous operation is the `verify_key'
 *    callback, which application completes by calling its completion
 *    callback. After completion the SKE libary will call the
 *    `proto_continue' callback, to indicate application that pending
 *    status is over and it is safe to continue the execution of SKE,
 *    which application does by calling the silc_ske_responder_finish
 *    function.
 *
 *    If this function returns SILC_SKE_STATUS_OK, it will not call the
 *    `verify_key' callback, however, it will or has already called the
 *    `proto_continue' callback.
 *
 *    Application must not continue execution of the SKE before library
 *    has called the `proto_continue' callback.  After it is called
 *    the application calls the silc_ske_responder_finish function.
 *
 ***/
SilcSKEStatus silc_ske_responder_phase_2(SilcSKE ske,
					 SilcBuffer ke_payload);

/****f* silcske/SilcSKEAPI/silc_ske_responder_finish
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_responder_finish(SilcSKE ske,
 *                                            SilcPublicKey public_key,
 *                                            SilcPrivateKey private_key,
 *                                            SilcSKEPKType pk_type);
 *
 * DESCRIPTION
 *
 *    This function finishes the responder's SKE session, and this function
 *    is called either immediately, or with short timeout, after the
 *    silc_ske_responder_phase_2 returned. This will send our reply to
 *    the initiator.  The caller must provide the caller's public key and
 *    private key as argument, since the public key is sent to the responder,
 *    and the private key is be used to generate digital signature.
 *
 *    After this function the application must wait for the end indication
 *    from the intiator, and when it is received the silc_ske_end is called.
 *
 ***/
SilcSKEStatus silc_ske_responder_finish(SilcSKE ske,
					SilcPublicKey public_key,
					SilcPrivateKey private_key,
					SilcSKEPKType pk_type);

/****f* silcske/SilcSKEAPI/silc_ske_end
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_end(SilcSKE ske);
 *
 * DESCRIPTION
 *
 *    The Key Exchange protocol is ended by calling this function. This
 *    must not be called until the keys are processed by calling the
 *    silc_ske_process_key_material function. The protocol prohibits
 *    calling this function before key material is processed properly.
 *
 *    This function is for both initiator and responder. After calling
 *    this function initiator must wait for end indication from the
 *    responder. After that the silc_ske_free may be called. The responder
 *    calls this function after it has received the intiator's end
 *    indication.
 *
 * NOTES
 *
 *    Initiator must not start using the negotiated key material before
 *    calling this function or before remote end has sent its end
 *    indication. Only after that the key material may be taken in use.
 *
 ***/
SilcSKEStatus silc_ske_end(SilcSKE ske);

/****f* silcske/SilcSKEAPI/silc_ske_abort
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_abort(SilcSKE ske, SilcSKEStatus status);
 *
 * DESCRIPTION
 *
 *    Aborts the Key Exchange protocol. This is called if error occurs
 *    while performing the protocol. The status argument is the error
 *    status and it is sent to the remote end.
 *
 ***/
SilcSKEStatus silc_ske_abort(SilcSKE ske, SilcSKEStatus status);

/****f* silcske/SilcSKEAPI/silc_ske_assemble_security_properties
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus
 *    silc_ske_assemble_security_properties(SilcSKE ske,
 *                                          SilcSKESecurityPropertyFlag flags,
 *                                          const char *version,
 *                                          SilcSKEStartPayload
 *                                            **return_payload);
 *
 * DESCRIPTION
 *
 *    Assembles security properties to Key Exchange Start Payload to be
 *    sent to the remote end. This checks system wide (SILC system, that is)
 *    settings and chooses from those. However, if other properties
 *    should be used this function is easy to replace by another function,
 *    as, this function is called by the caller of the library and not
 *    by the SKE library itself. The assembled payload is returned into
 *    the `return_payload' pointer.
 *
 ***/
SilcSKEStatus 
silc_ske_assemble_security_properties(SilcSKE ske,
				      SilcSKESecurityPropertyFlag flags,
				      const char *version,
				      SilcSKEStartPayload **return_payload);

/****f* silcske/SilcSKEAPI/silc_ske_select_security_properties
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus 
 *    silc_ske_select_security_properties(SilcSKE ske,
 *                                        const char *version,
 *                                        SilcSKEStartPayload *payload,
 *                                        SilcSKEStartPayload *remote_payload);
 *
 * DESCRIPTION
 *
 *    Parses the Key Exchange Start Payload indicated by `remote_payload',
 *    and selects the security properties properties from it, and puts the
 *    selection into the `payload'. This always attempts to select the
 *    best security properties from the payload, and it always selects
 *    one of each kind of security property, as this is dictated by the
 *    protocol. The `version' is our version, that we will put to the
 *    `payload', since the `payload' is usually sent to the remote end.
 *    the `check_version' callback will be called in this function so
 *    that application can do version check with the remote end.
 *
 ***/
SilcSKEStatus
silc_ske_select_security_properties(SilcSKE ske,
				    const char *version,
				    SilcSKEStartPayload *payload,
				    SilcSKEStartPayload *remote_payload);

/****f* silcske/SilcSKEAPI/silc_ske_process_key_material
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus silc_ske_process_key_material(SilcSKE ske,
 *                                                SilcUInt32 req_iv_len,
 *                                                SilcUInt32 req_enc_key_len,
 *                                                SilcUInt32 req_hmac_key_len,
 *                                                SilcSKEKeyMaterial *key);
 *
 * DESCRIPTION
 *
 *    This function is used by the application to process the key material
 *    negotiated with the SKE session, to actually produce the keys that
 *    is to be used in SILC protocol. The key processing is defined by the
 *    protocol. The `req_iv_len', `req_enc_key_len' and `req_hmac_key_len'
 *    are the request IV length, requested encryption/decrypt key length,
 *    and requested HMAC key length, respectively, and  they cannot be
 *    zero (0). They tell the function how long the keys should be, and
 *    it will produce the requested length keys for the application.
 *    The key material is returned in to the `key', which the caller must
 *    free.
 *
 ***/
SilcSKEStatus silc_ske_process_key_material(SilcSKE ske,
					    SilcUInt32 req_iv_len,
					    SilcUInt32 req_enc_key_len,
					    SilcUInt32 req_hmac_key_len,
					    SilcSKEKeyMaterial *key);

/****f* silcske/SilcSKEAPI/silc_ske_process_key_material_data
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus
 *    silc_ske_process_key_material_data(unsigned char *data,
 *                                       SilcUInt32 data_len,
 *                                       SilcUInt32 req_iv_len,
 *                                       SilcUInt32 req_enc_key_len,
 *                                       SilcUInt32 req_hmac_key_len,
 *                                       SilcHash hash,
 *                                       SilcSKEKeyMaterial *key);
 *
 * DESCRIPTION
 *
 *    This function is equivalent to silc_ske_process_key_material, except
 *    that the caller provides the raw key material as argument, the `data'
 *    and `data_len'. This is special utility function provided for the
 *    application, if it needs to generate key material as the protocol
 *    defines for some other purpose than strictly SILC session key usage.
 *    Hence, this function can be used outside SKE protocol to just produce
 *    key material from some raw data. The `hash' is a hash algorithm that
 *    is used as part of key processing, and caller must provide it.
 *
 ***/
SilcSKEStatus
silc_ske_process_key_material_data(unsigned char *data,
				   SilcUInt32 data_len,
				   SilcUInt32 req_iv_len,
				   SilcUInt32 req_enc_key_len,
				   SilcUInt32 req_hmac_key_len,
				   SilcHash hash,
				   SilcSKEKeyMaterial *key);

/****f* silcske/SilcSKEAPI/silc_ske_free_key_material
 *
 * SYNOPSIS
 *
 *    void silc_ske_free_key_material(SilcSKEKeyMaterial *key);
 *
 * DESCRIPTION
 *
 *    Frees the key material indicated by `key', and all data in it.
 *
 ***/
void silc_ske_free_key_material(SilcSKEKeyMaterial *key);

#endif	/* !SILCSKE_H */
