/*

  silcauth.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Authentication Interface
 *
 * DESCRIPTION
 *
 * Implementations of the SILC Authentication Payload and authentication
 * routines.  The SILC Authentication Payload is used to deliver
 * authentication data usually from client to server in purpose of
 * gaining access to some service.  The Payload and the authentication
 * routines supports both passphrase and public key (signature) based
 * authentication.
 *
 * This interface defines also the SILC Key Agreement Payload that is
 * used by client to agree on key material usually with another client
 * in the network.
 *
 ***/

#ifndef SILCAUTH_H
#define SILCAUTH_H

/****d* silccore/SilcAuthAPI/SilcAuthMethod
 *
 * NAME
 *
 *    typedef SilcUInt16 SilcAuthMethod;
 *
 * DESCRIPTION
 *
 *    Authentication method type definition, the authentication methods
 *    and the authentication status'.  The status defines are used by
 *    all authentication protocols in the SILC.
 *
 * SOURCE
 */
typedef SilcUInt16 SilcAuthMethod;

#define SILC_AUTH_NONE        0	           /* No authentication */
#define SILC_AUTH_PASSWORD    1		   /* Passphrase authentication */
#define SILC_AUTH_PUBLIC_KEY  2		   /* Public key authentication */

/****d* silccore/SilcAuthAPI/SilcAuthResult
 *
 * NAME
 *
 *    typedef SilcUInt32 SilcAuthResult;
 *
 * DESCRIPTION
 *
 *    Authentication protocol status.  Used by all authentication protocols
 *    in SILC.
 *
 * SOURCE
 */
typedef SilcUInt32 SilcAuthResult;

#define SILC_AUTH_OK          0              /* Authentication successful */
#define SILC_AUTH_FAILED      1		     /* Authentication failed */
/***/

/****s* silccore/SilcAuthAPI/SilcAuthPayload
 *
 * NAME
 *
 *    typedef struct SilcAuthPayloadStruct *SilcAuthPayload;
 *
 *
 * DESCRIPTION
 *
 *    This context is the actual Authentication Payload and is allocated
 *    by silc_auth_payload_parse and given as argument usually to all
 *    silc_auth_payload_* functions.  It is freed by silc_auth_payload_free
 *    function.
 *
 ***/
typedef struct SilcAuthPayloadStruct *SilcAuthPayload;

/****f* silccore/SilcAuthAPI/silc_auth_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcAuthPayload silc_auth_payload_parse(SilcStack stack,
 *                                            const unsigned char *data,
 *                                            SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Parses and returns Authentication Payload.  The `data' and the
 *    `data_len' are the raw payload buffer.  If `stack' is non-NULL the
 *    memory is allcoated from `stack'.
 *
 ***/
SilcAuthPayload silc_auth_payload_parse(SilcStack stack,
					const unsigned char *data,
					SilcUInt32 data_len);

/****f* silccore/SilcAuthAPI/silc_auth_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_auth_payload_encode(SilcStack stack,
 *                                        SilcAuthMethod method,
 *                                        const unsigned char *random_data,
 *                                        SilcUInt16 random_len,
 *                                        const unsigned char *auth_data,
 *                                        SilcUInt16 auth_len);
 *
 * DESCRIPTION
 *
 *    Encodes authentication payload into buffer and returns it.
 *    The `random_data' is provided only if doing public key authentication.
 *    The `auth_data' is the actual authentication data.  If the
 *    `method' is SILC_AUTH_PASSWORD the passphase in `auth_data' sent as
 *    argument SHOULD be UTF-8 encoded, if not library will attempt to
 *    encode it.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *    This call consumes the `stack' so caller should push the stack before
 *    calling this function and then later pop it.
 *
 ***/
SilcBuffer silc_auth_payload_encode(SilcStack stack,
				    SilcAuthMethod method,
				    const unsigned char *random_data,
				    SilcUInt16 random_len,
				    const unsigned char *auth_data,
				    SilcUInt16 auth_len);

/****f* silccore/SilcAuthAPI/silc_auth_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_auth_payload_free(SilcAuthPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees authentication payload and all data in it.
 *
 ***/
void silc_auth_payload_free(SilcAuthPayload payload);

/****f* silccore/SilcAuthAPI/silc_auth_get_method
 *
 * SYNOPSIS
 *
 *    SilcAuthMethod silc_auth_get_method(SilcAuthPayload payload);
 *
 * DESCRIPTION
 *
 *    Get authentication method.
 *
 ***/
SilcAuthMethod silc_auth_get_method(SilcAuthPayload payload);

/****f* silccore/SilcAuthAPI/silc_auth_get_public_data
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_auth_get_public_data(SilcAuthPayload payload,
 *                                             SilcUInt32 *pubdata_len);
 *
 * DESCRIPTION
 *
 *    Returns the public data (usually random data) from the payload.
 *    Caller must not free the returned data.
 *
 ***/
unsigned char *silc_auth_get_public_data(SilcAuthPayload payload,
					 SilcUInt32 *pubdata_len);

/****f* silccore/SilcAuthAPI/silc_auth_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_auth_get_data(SilcAuthPayload payload,
 *                                      SilcUInt32 *auth_len);
 *
 * DESCRIPTION
 *
 *    Get the authentication data. The caller must not free the data.  If
 *    the authentication method is passphrase, then the returned string
 *    is UTF-8 encoded passphrase.
 *
 ***/
unsigned char *silc_auth_get_data(SilcAuthPayload payload,
				  SilcUInt32 *auth_len);

/****f* silccore/SilcAuthAPI/SilcAuthGenerated
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcAuthGenerated)(const SilcBuffer data, void *context);
 *
 * DESCRIPTION
 *
 *    Callback of this type is given as argument to
 *    silc_auth_public_key_auth_generate and
 *    silc_auth_public_key_auth_generate_wpub to deliver the generated
 *    Authentication Payload.  If `data' is NULL the generating failed.
 *
 ***/
typedef void (*SilcAuthGenerated)(const SilcBuffer data, void *context);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_generate
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_auth_public_key_auth_generate(SilcPublicKey public_key,
 *                                       SilcPrivateKey private_key,
 *                                       SilcRng rng,
 *                                       SilcHash hash,
 *                                       const void *id,
 *                                       SilcIdType type,
 *                                       SilcAuthGenerated generated,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    Generates Authentication Payload with authentication data. This is used
 *    to do public key based authentication. This generates the random data
 *    and the actual authentication data.
 *
 *    The `private_key' is used to sign the payload.  The `public_key', the
 *    and the `id' is encoded in the payload and signed.  If the `rng' is
 *    NULL then global RNG is used, if non-NULL then `rng' is used as
 *    random number generator.  Also random number is encoded in the
 *    payload before signing it with `private_key'.
 *
 *    The `generated' is called to deliver the generated Authentication
 *    Payload.
 *
 ***/
SilcAsyncOperation
silc_auth_public_key_auth_generate(SilcPublicKey public_key,
				   SilcPrivateKey private_key,
				   SilcRng rng, SilcHash hash,
				   const void *id, SilcIdType type,
				   SilcAuthGenerated generated,
				   void *context);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_generate_wpub
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_auth_public_key_auth_generate_wpub(SilcPublicKey public_key,
 *                                            SilcPrivateKey private_key,
 *                                            const unsigned char *pubdata,
 *                                            SilcUInt32 pubdata_len,
 *                                            SilcHash hash,
 *                                            const void *id,
 *                                            SilcIdType type,
 *                                            SilcAuthGenerated generated,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_auth_public_key_auth_generate but takes the public data
 *    (usually random data) as argument.  This function can be used when
 *    the public data must be something else than purely random or its
 *    structure mut be set before signing.
 *
 *    The `generated' is called to deliver the generated Authentication
 *    Payload.
 *
 ***/
SilcAsyncOperation
silc_auth_public_key_auth_generate_wpub(SilcPublicKey public_key,
					SilcPrivateKey private_key,
					const unsigned char *pubdata,
					SilcUInt32 pubdata_len,
					SilcHash hash,
					const void *id, SilcIdType type,
					SilcAuthGenerated generated,
					void *context);

/****f* silccore/SilcAuthAPI/SilcAuthResult
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcAuthResult)(SilcBool success, void *context);
 *
 * DESCRIPTION
 *
 *    Callback of this type is given as argument to silc_auth_verify,
 *    silc_auth_verify_data, silc_auth_public_key_auth_verify and
 *    silc_auth_public_key_auth_verify_data to deliver the result of
 *    the authentication verification.  If `success' is FALSE the
 *    authentication failed.
 *
 ***/
typedef void (*SilcAuthResultCb)(SilcBool success, void *context);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_verify
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *   silc_auth_public_key_auth_verify(SilcAuthPayload payload,
 *                                    SilcPublicKey public_key,
 *                                    SilcHash hash,
 *                                    const void *id,
 *                                    SilcIdType type,
 *                                    SilcAuthResult result,
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Verifies the authentication data.  Calls the `result' to deliver
 *    the result of the verification.
 *
 ***/
SilcAsyncOperation
silc_auth_public_key_auth_verify(SilcAuthPayload payload,
				 SilcPublicKey public_key,
				 SilcHash hash,
				 const void *id,
				 SilcIdType type,
				 SilcAuthResultCb result,
				 void *context);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_verify_data
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_auth_public_key_auth_verify_data(const unsigned char *payload,
 *                                          SilcUInt32 payload_len,
 *                                          SilcPublicKey public_key,
 *                                          SilcHash hash,
 *                                          const void *id,
 *                                          SilcIdType type,
 *                                          SilcAuthResult result,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_auth_public_key_auth_verify but the payload has not
 *    been parsed yet.  This will parse it.  Calls the `result' to deliver
 *    the result of the verification.
 *
 ***/
SilcAsyncOperation
silc_auth_public_key_auth_verify_data(const unsigned char *payload,
				      SilcUInt32 payload_len,
				      SilcPublicKey public_key,
				      SilcHash hash,
				      const void *id,
				      SilcIdType type,
				      SilcAuthResultCb result,
				      void *context);

/****f* silccore/SilcAuthAPI/silc_auth_verify
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_auth_verify(SilcAuthPayload payload,
 *                     SilcAuthMethod auth_method,
 *                     const void *auth_data,
 *                     SilcUInt32 auth_data_len,
 *                     SilcHash hash,
 *                     const void *id, SilcIdType type,
 *                     SilcAuthResult result, void *context);
 *
 * DESCRIPTION
 *
 *    Verifies the authentication data directly from the Authentication
 *    Payload. Supports all authentication methods. If the authentication
 *    method is passphrase based then the `auth_data' and `auth_data_len'
 *    are the passphrase and its length.  The passphrase MUST be UTF-8
 *    encoded.  If the method is public key authentication then the
 *    `auth_data' is the SilcPublicKey and the `auth_data_len' is ignored.
 *    Calls the `result' to deliver the result of the verification.
 *
 ***/
SilcAsyncOperation
silc_auth_verify(SilcAuthPayload payload, SilcAuthMethod auth_method,
		 const void *auth_data, SilcUInt32 auth_data_len,
		 SilcHash hash, const void *id, SilcIdType type,
		 SilcAuthResultCb result, void *context);

/****f* silccore/SilcAuthAPI/silc_auth_verify_data
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_auth_verify_data(const unsigned char *payload,
 *                          SilcUInt32 payload_len,
 *                          SilcAuthMethod auth_method,
 *                          const void *auth_data,
 *                          SilcUInt32 auth_data_len, SilcHash hash,
 *                          const void *id, SilcIdType type,
 *                          SilcAuthResult result, void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_auth_verify but the payload has not been parsed yet.
 *    Verifies the authentication data directly from the Authentication
 *    Payload. Supports all authentication methods. If the authentication
 *    method is passphrase based then the `auth_data' and `auth_data_len'
 *    are the passphrase and its length.  The passphrase MUST be UTF-8
 *    encoded.  If the method is public key authentication then the
 *    `auth_data' is the SilcPublicKey and the `auth_data_len' is ignored.
 *    Calls the `result' to deliver the result of the verification.
 *
 ***/
SilcAsyncOperation
silc_auth_verify_data(const unsigned char *payload,
		      SilcUInt32 payload_len,
		      SilcAuthMethod auth_method,
		      const void *auth_data,
		      SilcUInt32 auth_data_len, SilcHash hash,
		      const void *id, SilcIdType type,
		      SilcAuthResultCb result, void *context);

/****s* silccore/SilcAuthAPI/SilcKeyAgreementPayload
 *
 * NAME
 *
 *    typedef struct SilcKeyAgreementPayloadStruct *SilcKeyAgreementPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Key Agreement Payload and is allocated
 *    by silc_key_agreement_payload_parse and given as argument usually to all
 *    silc_key_agreement_* functions.  It is freed by the function
 *    silc_key_agreement_payload_free.
 *
 ***/
typedef struct SilcKeyAgreementPayloadStruct *SilcKeyAgreementPayload;

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcKeyAgreementPayload
 *    silc_key_agreement_payload_parse(const unsigned char *payload,
 *                                     SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses and returns an allocated Key Agreement payload.
 *
 ***/
SilcKeyAgreementPayload
silc_key_agreement_payload_parse(const unsigned char *payload,
				 SilcUInt32 payload_len);

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_key_agreement_payload_encode(char *hostname,
 *                                                 SilcUInt16 protocol,
 *                                                 SilcUInt16 port);
 *
 * DESCRIPTION
 *
 *    Encodes the Key Agreement payload and returns the encoded buffer.
 *    The `protocol' is 0 for TCP and 1 for UDP.
 *
 ***/
SilcBuffer silc_key_agreement_payload_encode(const char *hostname,
					     SilcUInt16 protocol,
					     SilcUInt16 port);

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_key_agreement_payload_free(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Key Agreement payload and all data in it.
 *
 ***/
void silc_key_agreement_payload_free(SilcKeyAgreementPayload payload);

/****f* silccore/SilcAuthAPI/silc_key_agreement_get_hostname
 *
 * SYNOPSIS
 *
 *    char *silc_key_agreement_get_hostname(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the hostname in the payload. Caller must not free it.
 *    The hostname is the host that is able to accept key negotiation
 *    using the SILC Key Exchange protocol.
 *
 ***/
char *silc_key_agreement_get_hostname(SilcKeyAgreementPayload payload);

/****f* silccore/SilcAuthAPI/silc_key_agreement_get_protocol
 *
 * SYNOPSIS
 *
 *    SilcUInt16
 *    silc_key_agreement_get_protocol(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the protocol in the payload.  The protocol is either TCP (0)
 *    or UDP (1).
 *
 ***/
SilcUInt16 silc_key_agreement_get_protocol(SilcKeyAgreementPayload payload);

/****f* silccore/SilcAuthAPI/silc_key_agreement_get_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_key_agreement_get_port(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the port in the payload.  The port is the port on the
 *    host returned by silc_key_agreement_get_hostname that is running
 *    the SILC Key Exchange protocol.
 *
 ***/
SilcUInt16 silc_key_agreement_get_port(SilcKeyAgreementPayload payload);

#endif
