/*

  protocol.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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
#define SILC_PROTOCOL_CLIENT_NONE 0
#define SILC_PROTOCOL_CLIENT_CONNECTION_AUTH 1
#define SILC_PROTOCOL_CLIENT_KEY_EXCHANGE 2
/* #define SILC_PROTOCOL_CLIENT_MAX 255 */

/* Internal context for key exchange protocol */
typedef struct {
  void *client;
  SilcSocketConnection sock;
  SilcRng rng;
  int responder;

  /* Destinations ID taken from authenticataed packet so that we can
     get the destinations ID. */
  void *dest_id;
  SilcIdType dest_id_type;

  SilcBuffer packet;
  SilcSKE ske;
} SilcClientKEInternalContext;

/* Internal context for connection authentication protocol */
typedef struct {
  void *client;
  SilcSocketConnection sock;

  /* SKE object from Key Exchange protocol. */
  SilcSKE ske;

  /* Auth method that must be used. This is resolved before this
     connection authentication protocol is started. */
  unsigned int auth_meth;

  /* Destinations ID from KE protocol context */
  void *dest_id;
  SilcIdType dest_id_type;

  /* Authentication data if we alreay know it. This is filled before
     starting the protocol if we know the authentication data. Otherwise
     these are and remain NULL. */
  unsigned char *auth_data;
  unsigned int auth_data_len;

  SilcTask timeout_task;
} SilcClientConnAuthInternalContext;

/* Prototypes */

#endif
