/*

  protocol.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* SILC client protocol types */
#define SILC_PROTOCOL_SERVER_NONE               0
#define SILC_PROTOCOL_SERVER_CONNECTION_AUTH    1
#define SILC_PROTOCOL_SERVER_KEY_EXCHANGE       2
#define SILC_PROTOCOL_SERVER_REKEY              3
#define SILC_PROTOCOL_SERVER_BACKUP             4
/* #define SILC_PROTOCOL_SERVER_MAX             255 */

/* Internal context for Key Exchange protocol. */
typedef struct {
  void *server;
  void *context;
  SilcSocketConnection sock;
  SilcRng rng;

  /* TRUE if we are receiveing part of the protocol */
  bool responder;

  /* Destinations ID taken from authenticataed packet so that we can
     get the destinations ID. */
  void *dest_id;
  SilcIdType dest_id_type;

  /* Pointer to the configurations. */
  void *cconfig;
  void *sconfig;
  void *rconfig;

  SilcTask timeout_task;
  SilcPacketContext *packet;
  SilcSKE ske;
  SilcSKEKeyMaterial *keymat;
} SilcServerKEInternalContext;

/* Internal context for connection authentication protocol */
typedef struct {
  void *server;
  void *context;
  SilcSocketConnection sock;

  /* TRUE if we are receiving part of the protocol */
  bool responder;

  /* SKE object from Key Exchange protocol. */
  SilcSKE ske;

  /* Auth method that must be used. This is resolved before this
     connection authentication protocol is started. Used when we are
     initiating. */
  uint32 auth_meth;

  /* Authentication data if we alreay know it. This is filled before
     starting the protocol if we know the authentication data. Otherwise
     these are and remain NULL. Used when we are initiating. */
  void *auth_data;
  uint32 auth_data_len;

  /* Destinations ID from KE protocol context */
  void *dest_id;
  SilcIdType dest_id_type;

  /* Pointer to the configurations. */
  void *cconfig;
  void *sconfig;
  void *rconfig;

  SilcTask timeout_task;
  SilcPacketContext *packet;
  uint16 conn_type;
} SilcServerConnAuthInternalContext;

/* Internal context for the rekey protocol */
typedef struct {
  void *server;
  void *context;
  SilcSocketConnection sock;
  bool responder;		    /* TRUE if we are receiving party */
  bool pfs;			    /* TRUE if PFS is to be used */
  SilcSKE ske;			    /* Defined if PFS is used */
  SilcPacketContext *packet;
} SilcServerRekeyInternalContext;

/* Prototypes */
void silc_server_protocols_register(void);
void silc_server_protocols_unregister(void);
int silc_server_protocol_ke_set_keys(SilcServer server,
				     SilcSKE ske,
				     SilcSocketConnection sock,
				     SilcSKEKeyMaterial *keymat,
				     SilcCipher cipher,
				     SilcPKCS pkcs,
				     SilcHash hash,
				     SilcHmac hmac,
				     SilcSKEDiffieHellmanGroup group,
				     bool is_responder);

#endif
