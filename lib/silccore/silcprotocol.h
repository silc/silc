/*

  silcprotocol.h

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

#ifndef SILCPROTOCOL_H
#define SILCPROTOCOL_H

/* Protocol type definition. */
typedef unsigned char SilcProtocolType;

/* Protocol state definition. */
typedef unsigned char SilcProtocolState;

/* Protocol states. Do NOT change the values of these states, especially
   the START state or you break every protocol. */
#define SILC_PROTOCOL_STATE_UNKNOWN 0
#define SILC_PROTOCOL_STATE_START 1
#define SILC_PROTOCOL_STATE_END 253
#define SILC_PROTOCOL_STATE_ERROR 254

/* Connection Authentication protocols' authentication methods */
#define SILC_PROTOCOL_CONN_AUTH_NONE 0
#define SILC_PROTOCOL_CONN_AUTH_PASSWORD 1
#define SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY 2

/* Type definition for above auth methods */
typedef unsigned char SilcProtocolAuthMeth;

/* 
   SILC Protocol Object.

   Short description of the field following:
   
   SilcProtocolType type

       Protocol type. This is enumeration.
  
   SilcProtocolCallback callback;

       Callback function for the protocol. This is SilcTaskCallback function
       pointer as the protocols in SILC are executed as timeout tasks.

   The object expands to another structure as well. Short description of 
   these fields following:

   SilcProtocolObject *protocol

       This is the pointer to the protocol object defined above.

   SilcProtocolState state

       Protocol state. This is enumeration. The state of the protocol can
       be changed in the callback function.

   void *context

       Context to be sent for the callback function. This is usually 
       object for either SILC client or server. However, this abstraction 
       makes it possible that this pointer could be some other object as well. 

   SilcProtocolExecute execute;

       Executes the protocol and its states. The correct state must be set
       before calling this function. The state is usually set in the protocol
       specific routines.

   SilcProtocolExecute execute_final;

       Executes the final callback function of the protocol. Read on.

   SilcProtocolFinalCallback final_callback;

       This is a callback function that is called with timeout _after_ the
       protocol has finished or error occurs. If this is NULL, naturally 
       nothing will be executed. Protocol should call this function only at 
       SILC_PROTOCOL_STATE_END and SILC_PROTOCOL_STATE_ERROR states.

*/
typedef SilcTaskCallback SilcProtocolCallback;

typedef struct SilcProtocolObjectStruct {
  SilcProtocolType type;
  SilcProtocolCallback callback;

  struct SilcProtocolObjectStruct *next;
} SilcProtocolObject;

typedef SilcTaskCallback SilcProtocolFinalCallback;
typedef SilcTaskCallback SilcProtocolExecute;

typedef struct SilcProtocolStruct {
  SilcProtocolObject *protocol;
  SilcProtocolState state;
  void *context;

  //  SilcProtocolExecute execute;
  void (*execute)(void *, int, void *, int, long, long);
  SilcProtocolExecute execute_final;
  SilcProtocolFinalCallback final_callback;
} *SilcProtocol;

/* Prototypes */
void silc_protocol_register(SilcProtocolType type,
			    SilcProtocolCallback callback);
void silc_protocol_unregister(SilcProtocolType type,
                              SilcProtocolCallback callback);
void silc_protocol_alloc(SilcProtocolType type, SilcProtocol *new_protocol,
			 void *context, SilcProtocolFinalCallback callback);
void silc_protocol_free(SilcProtocol protocol);
void silc_protocol_execute(void *qptr, int type,
			   void *context, int fd,
			   long secs, long usecs);
void silc_protocol_execute_final(void *qptr, int type, 
				 void *context, int fd);

#endif
