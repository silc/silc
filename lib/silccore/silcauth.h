/*

  silcauth.h
 
  Author: Pekka Riikonen <priikone@silcnet.org>
 
  Copyright (C) 2001 Pekka Riikonen
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SilcAuthAPI
 *
 * DESCRIPTION
 *
 * Implementations of the Silc Authentication Payload and authentication
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

/****d* silccore/SilcAuthAPI/SilcAuthMethod
 *
 * NAME
 * 
 *    typedef uint16 SilcAuthMethod;
 *
 * DESCRIPTION
 *
 *    Authentication method type definition, the authentication methods
 *    and the authentication status'.  The status defines are used by
 *    all authentication protocols in the SILC.
 *
 * SOURCE
 */
typedef uint16 SilcAuthMethod;

#define SILC_AUTH_NONE        0	           /* No authentication */
#define SILC_AUTH_PASSWORD    1		   /* Passphrase authentication */
#define SILC_AUTH_PUBLIC_KEY  2		   /* Public key authentication */

/* Authentication protocol status message (used by all authentication
   protocols in the SILC). */
#define SILC_AUTH_OK          0
#define SILC_AUTH_FAILED      1
/***/

/* Prototypes */

/****f* silccore/SilcAuthAPI/silc_auth_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcAuthPayload silc_auth_payload_parse(unsigned char *data,
 *                                            uint32 data_len);
 *
 * DESCRIPTION
 *
 *    Parses and returns Authentication Payload.  The `data' and the
 *    `data_len' are the raw payload buffer.
 *
 ***/
SilcAuthPayload silc_auth_payload_parse(unsigned char *data,
					uint32 data_len);

/****f* silccore/SilcAuthAPI/silc_auth_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_auth_payload_encode(SilcAuthMethod method,
 *                                        unsigned char *random_data,
 *                                        uint16 random_len,
 *                                        unsigned char *auth_data,
 *                                        uint16 auth_len);
 *
 * DESCRIPTION
 *
 *    Encodes authentication payload into buffer and returns it.
 *    The `random_data' is provided only if doing public key authentication.
 *    The `auth_data' is the actual authentication data.
 *
 ***/
SilcBuffer silc_auth_payload_encode(SilcAuthMethod method,
				    unsigned char *random_data,
				    uint16 random_len,
				    unsigned char *auth_data,
				    uint16 auth_len);

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

/****f* silccore/SilcAuthAPI/silc_auth_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_auth_get_data(SilcAuthPayload payload,
 *                                      uint32 *auth_len);
 *
 * DESCRIPTION
 *
 *    Get the authentication data. The caller must not free the data.
 *
 ***/
unsigned char *silc_auth_get_data(SilcAuthPayload payload,
				  uint32 *auth_len);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_generate
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_auth_public_key_auth_generate(SilcPublicKey public_key,
 *                                                  SilcPrivateKey private_key,
 *                                                  SilcHash hash,
 *                                                  void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Generates Authentication Payload with authentication data. This is used
 *    to do public key based authentication. This generates the random data
 *    and the actual authentication data. Returns NULL on error and the
 *    encoded Authentication Payload on success.
 *
 ***/
SilcBuffer silc_auth_public_key_auth_generate(SilcPublicKey public_key,
					      SilcPrivateKey private_key,
					      SilcHash hash,
					      void *id, SilcIdType type);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_verify
 *
 * SYNOPSIS
 *
 *    int silc_auth_public_key_auth_verify(SilcAuthPayload payload,
 *                                         SilcPublicKey public_key, 
 *                                         SilcHash hash,
 *                                         void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Verifies the authentication data. Returns TRUE if authentication was
 *    successful.
 *
 ***/
int silc_auth_public_key_auth_verify(SilcAuthPayload payload,
				     SilcPublicKey public_key, SilcHash hash,
				     void *id, SilcIdType type);

/****f* silccore/SilcAuthAPI/silc_auth_public_key_auth_verify_data
 *
 * SYNOPSIS
 *
 *    int silc_auth_public_key_auth_verify_data(SilcBuffer payload,
 *                                              SilcPublicKey public_key, 
 *                                              SilcHash hash,
 *                                              void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Same as silc_auth_public_key_auth_verify but the payload has not
 *    been parsed yet.  This will parse it.  Returns TRUE if authentication
 *    was successful.
 *
 ***/
int silc_auth_public_key_auth_verify_data(SilcBuffer payload,
					  SilcPublicKey public_key, 
					  SilcHash hash,
					  void *id, SilcIdType type);

/****f* silccore/SilcAuthAPI/silc_auth_verify
 *
 * SYNOPSIS
 *
 *    int silc_auth_verify(SilcAuthPayload payload, SilcAuthMethod auth_method,
 *                         void *auth_data, uint32 auth_data_len, 
 *                         SilcHash hash, void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Verifies the authentication data directly from the Authentication 
 *    Payload. Supports all authentication methods. If the authentication
 *    method is passphrase based then the `auth_data' and `auth_data_len'
 *    are the passphrase and its length. If the method is public key
 *    authentication then the `auth_data' is the SilcPublicKey and the
 *    `auth_data_len' is ignored.
 *
 ***/
int silc_auth_verify(SilcAuthPayload payload, SilcAuthMethod auth_method,
		     void *auth_data, uint32 auth_data_len, 
		     SilcHash hash, void *id, SilcIdType type);

/****f* silccore/SilcAuthAPI/silc_auth_verify_data
 *
 * SYNOPSIS
 *
 *    int silc_auth_verify_data(unsigned char *payload, uint32 payload_len,
 *                              SilcAuthMethod auth_method, void *auth_data,
 *                              uint32 auth_data_len, SilcHash hash, 
 *                              void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Same as silc_auth_verify but the payload has not been parsed yet.
 *    Verifies the authentication data directly from the Authentication 
 *    Payload. Supports all authentication methods. If the authentication
 *    method is passphrase based then the `auth_data' and `auth_data_len'
 *    are the passphrase and its length. If the method is public key
 *    authentication then the `auth_data' is the SilcPublicKey and the
 *    `auth_data_len' is ignored.
 *
 ***/
int silc_auth_verify_data(unsigned char *payload, uint32 payload_len,
			  SilcAuthMethod auth_method, void *auth_data,
			  uint32 auth_data_len, SilcHash hash, 
			  void *id, SilcIdType type);

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcKeyAgreementPayload 
 *    silc_key_agreement_payload_parse(SilcBuffer buffer);
 *
 * DESCRIPTION
 *
 *    Parses and returns an allocated Key Agreement payload.
 *
 ***/
SilcKeyAgreementPayload silc_key_agreement_payload_parse(SilcBuffer buffer);

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_key_agreement_payload_encode(char *hostname,
 *                                                 uint32 port);
 *
 * DESCRIPTION
 *
 *    Encodes the Key Agreement protocol and returns the encoded buffer
 *
 ***/
SilcBuffer silc_key_agreement_payload_encode(const char *hostname,
					     uint32 port);

/****f* silccore/SilcAuthAPI/silc_key_agreement_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_key_agreement_payload_free(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Key Agreement protocol and all data in it.
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

/****f* silccore/SilcAuthAPI/silc_key_agreement_get_port
 *
 * SYNOPSIS
 *
 *    uint32 silc_key_agreement_get_port(SilcKeyAgreementPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the port in the payload.  The port is the port on the
 *    host returned by silc_key_agreement_get_hostname that is running
 *    the SILC Key Exchange protocol.
 *
 ***/
uint32 silc_key_agreement_get_port(SilcKeyAgreementPayload payload);

#endif
