/*

  ops.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef OPS_H
#define OPS_H

/*
 * SILC Client Operations
 *
 * These functions must be implemented by the application calling the
 * SILC client library. The client library can call these functions at
 * any time.
 *
 * To use this structure: define a static SilcClientOperations variable,
 * fill it and pass its pointer to silc_client_alloc function.
 */
typedef struct {
  void (*say)(SilcClient client, SilcClientConnection conn, char *msg, ...);
  void (*channel_message)(SilcClient client, SilcClientConnection conn, 
			  char *sender, char *channel_name, char *msg);
  void (*private_message)(SilcClient client, SilcClientConnection conn,
			  char *sender, char *msg);
  void (*notify)(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyPayload notify_payload);
  void (*command)(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command);
  void (*command_reply)(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommandStatus status, SilcCommand command, ...);
  void (*connect)(SilcClient client, SilcClientConnection conn, int success);
  void (*disconnect)(SilcClient client, SilcClientConnection conn);
  int (*get_auth_method)(SilcClient client, SilcClientConnection conn,
			 char *hostname, unsigned short port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 unsigned int *auth_data_len);
  int (*verify_server_key)(SilcClient client, SilcClientConnection conn,
			   unsigned char *pk, unsigned int pk_len,
			   SilcSKEPKType pk_type);
  unsigned char *(*ask_passphrase)(SilcClient client, 
				   SilcClientConnection conn);
} SilcClientOperations;

/* 
   Descriptions of above operation functions:

   void (*say)(SilcClient client, SilcClientConnection conn, char *msg, ...);

   Message sent to the application by library. `conn' associates the
   message to a specific connection.  `conn', however, may be NULL.


   void (*channel_message)(client, SilcClientConnection conn, 
			   char *sender, char *channel_name, char *msg);

   Message for a channel. The `sender' is the nickname of the sender 
   received in the packet. The `channel_name' is the name of the channel. 


   void (*private_message)(client, SilcClientConnection conn,
	 		   char *sender, char *msg);

   Private message to the client. The `sender' is the nickname of the
   sender received in the packet.


   void (*notify)(SilcClient client, SilcClientConnection conn, 
		  SilcNotifyPayload notify_payload);

   Notify message to the client.  The `notify_payload' is the Notify
   Payload received from server.  Client library may parse it to cache
   some data received from the payload but it is the application's 
   responsiblity to retrieve the message and arguments from the payload.
   The message in the payload sent by server is implementation specific
   thus it is recommended that application will generate its own message.


   void (*command)(SilcClient client, SilcClientConnection conn, 
		   SilcClientCommandContext cmd_context, int success,
		   SilcCommand command);

   Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occured
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed.


   void (*command_reply)(SilcClient client, SilcClientConnection conn,
			 SilcCommandPayload cmd_payload, int success,
			 SilcCommandStatus status, SilcCommand command, ...);

   Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application. 

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occured.
   In this case arguments are not sent to the application. The `status' is
   the command reply status server returned. The `command' is the command
   reply being processed. The function has variable argument list and each
   command defines the number and type of arguments it passes to the
   application (on error they are not sent).


   void (*connect)(SilcClient client, SilcClientConnection conn, int success);

   Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere.


   void (*disconnect)(SilcClient client, SilcClientConnection conn);

   Called to indicate that connection was disconnected to the server.


   int (*get_auth_method)(SilcClient client, SilcClientConnection conn,
			  char *hostname, unsigned short port,
			  SilcProtocolAuthMeth *auth_meth,
			  unsigned char **auth_data,
			  unsigned int *auth_data_len);

   Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. The found authentication
   method and authentication data is returned to `auth_meth', `auth_data'
   and `auth_data_len'. The function returns TRUE if authentication method
   is found and FALSE if not. `conn' may be NULL.


   int (*verify_server_key)(SilcClient client, SilcClientConnection conn,
			    unsigned char *pk, unsigned int pk_len,
			    SilcSKEPKType pk_type);

   Verifies received public key. The public key has been received from
   a server. If user decides to trust the key may be saved as trusted
   server key for later use. If user does not trust the key this returns
   FALSE. If everything is Ok this returns TRUE. 


   unsigned char *(*ask_passphrase)(SilcClient client, 
				    SilcClientConnection conn);

   Ask (interact, that is) a passphrase from user. Returns the passphrase
   or NULL on error. 

*/

#endif
