/*

  client_internal.h

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

#ifndef CLIENT_INTERNAL_H
#define CLIENT_INTERNAL_H

/* Internal context for connection process. This is needed as we
   doing asynchronous connecting. */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcTask task;
  int sock;
  char *host;
  int port;
  int tries;
  void *context;
} SilcClientInternalConnectContext;

/* Structure to hold ping time information. Every PING command will 
   add entry of this structure and is removed after reply to the ping
   as been received. */
struct SilcClientPingStruct {
  time_t start_time;
  void *dest_id;
  char *dest_name;
};

/* Structure to hold away messages set by user. This is mainly created
   for future extensions where away messages could be set according filters
   such as nickname and hostname. For now only one away message can 
   be set in one connection. */
struct SilcClientAwayStruct {
  char *away;
  struct SilcClientAwayStruct *next;
};

/* Failure context. This is allocated when failure packet is received.
   Failure packets are processed with timeout and data is saved in this
   structure. */
typedef struct {
  SilcClient client;
  SilcSocketConnection sock;
  uint32 failure;
} SilcClientFailureContext;

/* Protypes */

SILC_TASK_CALLBACK_GLOBAL(silc_client_packet_process);
SILC_TASK_CALLBACK_GLOBAL(silc_client_failure_callback);
int silc_client_packet_send_real(SilcClient client,
				 SilcSocketConnection sock,
				 bool force_send,
				 bool flush);

#endif
