/*

  silcmap_client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
#include "silcclient.h"
#include "silcmap.h"

/******* Map Client Routines *************************************************/

SILC_TASK_CALLBACK(silc_map_process_done)
{
  SilcMap map = context;

  /* Program stops */
  silc_schedule_stop(map->client->schedule);
}

/* This function processes the data that was gathered from the server
   and producess the outputs and the map. */

void silc_map_process_data(SilcMap map, SilcMapConnection mapconn)
{
  SilcMapCommand cmd;
  SilcMap ret_map;
  SilcInt16 r, g, b, lr, lg, lb;
  int i;

  map->conn_num++;

  SILC_LOG_DEBUG(("Processing the data from server (%d/%d)",
		  map->conn_num, map->conns_num));

  if (map->conn_num != map->conns_num)
    return;

  /* Load the map image to be processed */
  silc_free(map->bitmap);
  if (!map->loadmap.loadmap || !map->loadmap.filename) {
    silc_schedule_task_add(map->client->schedule, 0,
			   silc_map_process_done, map, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  if (!silc_map_load_ppm(map, map->loadmap.filename)) {
    silc_schedule_task_add(map->client->schedule, 0,
			   silc_map_process_done, map, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Now process all received data one by one */
  silc_dlist_start(map->conns);
  while ((mapconn = silc_dlist_get(map->conns)) != SILC_LIST_END) {

    /* Change colors according to server status */
    silc_map_parse_color(mapconn->up_color, &r, &g, &b);
    silc_map_parse_color(mapconn->up_text_color, &lr, &lg, &lb);
    if (mapconn->down) {
      silc_map_parse_color(mapconn->down_color, &r, &g, &b);
      silc_map_parse_color(mapconn->down_text_color, &lr, &lg, &lb);
    }

    /* Execute the map commands */
    silc_dlist_start(mapconn->commands);
    while ((cmd = silc_dlist_get(mapconn->commands)) != SILC_LIST_END) {
      if (cmd->alon && cmd->alat) {
	cmd->x = silc_map_lon2x(map, cmd->alon);
	cmd->y = silc_map_lat2y(map, cmd->alat);
	if (cmd->blon && cmd->blat) {
	  cmd->x2 = silc_map_lon2x(map, cmd->blon);
	  cmd->y2 = silc_map_lat2y(map, cmd->blat);
	}
      }

      if (cmd->cut) {
	if (silc_map_cut(map, cmd->x, cmd->y, cmd->width,
		         cmd->height, &ret_map)) {
	  silc_map_write_ppm(ret_map, cmd->filename);
	  silc_map_free(ret_map);
	}
	continue;
      }

      if (cmd->draw_line) {
	if (cmd->color_set) {
	  r = cmd->r;
	  g = cmd->g;
	  b = cmd->b;
	}
	silc_map_draw_line(map, cmd->width, cmd->x, cmd->y, cmd->x2, cmd->y2,
			   r, g, b);
	continue;
      }

      if (cmd->draw_text) {
	if (cmd->color_set) {
	  lr = cmd->r;
	  lg = cmd->g;
	  lb = cmd->b;
	}
	silc_map_draw_text(map, cmd->text, cmd->x, cmd->y, lr, lg, lb);
	continue;
      }

      if (cmd->draw_circle) {
	if (cmd->color_set) {
	  r = cmd->r;
	  g = cmd->g;
	  b = cmd->b;
	}
	if (cmd->lcolor_set) {
	  lr = cmd->lr;
	  lg = cmd->lg;
	  lb = cmd->lb;
	}
	silc_map_draw_circle(map, cmd->x, cmd->y, r, g, b,
			     cmd->text, cmd->lposx, cmd->lposy, lr, lg, lb);
	continue;
      }

      if (cmd->draw_rectangle) {
	if (cmd->color_set) {
	  r = cmd->r;
	  g = cmd->g;
	  b = cmd->b;
	}
	if (cmd->lcolor_set) {
	  lr = cmd->lr;
	  lg = cmd->lg;
	  lb = cmd->lb;
	}
	silc_map_draw_rectangle(map, cmd->x, cmd->y, r, g, b,
				cmd->text, cmd->lposx, cmd->lposy, lr, lg, lb);
	continue;
      }
    }

    /* Write the html data file */
    if (map->writehtml.writehtml)
      silc_map_writehtml(map, mapconn);

    /* Write uptime reliability data */
    if (map->writerel.writerel)
      silc_map_writerel(map, mapconn);
  }

  SILC_LOG_DEBUG(("All connections processed"));

  /* Produce output */
  if (map->writemap.writemap)
    silc_map_write_ppm(map, map->writemap.filename);
  for (i = 0; i < map->cut_count; i++) {
    if (map->cut[i].alon && map->cut[i].alat) {
      map->cut[i].x = silc_map_lon2x(map, map->cut[i].alon);
      map->cut[i].y = silc_map_lat2y(map, map->cut[i].alat);
    }
    if (silc_map_cut(map, map->cut[i].x, map->cut[i].y, map->cut[i].width,
		     map->cut[i].height, &ret_map)) {
      silc_map_write_ppm(ret_map, map->cut[i].filename);
      silc_map_free(ret_map);
    }
  }

  /* Write the HTML index file */
  if (map->writehtml.writehtml)
    silc_map_writehtml_index(map);

  /* Write the HTML map file(s) */
  silc_map_writemaphtml(map);

  /* Write uptime reliability graph */
  if (map->writerel.writerel)
    silc_map_writerelhtml(map);

  /* Schedule to stop */
  silc_schedule_task_add(map->client->schedule, 0,
			 silc_map_process_done, map, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* Timeout callback to detect if server is down. */

SILC_TASK_CALLBACK(silc_map_connect_timeout)
{
  SilcMapConnection mapconn = context;

  SILC_LOG_DEBUG(("Connection timeout"));

  silc_schedule_task_del_by_context(mapconn->map->client->schedule, mapconn);

  /* The server is down. */
  mapconn->down = TRUE;

  /* Continue to produce the data and the map. */
  silc_map_process_data(mapconn->map, mapconn);
}

/* Timeout callback to detect if server is down. */

SILC_TASK_CALLBACK(silc_map_data_timeout)
{
  SilcMapConnection mapconn = context;

  SILC_LOG_DEBUG(("data timeout"));

  silc_schedule_task_del_by_context(mapconn->map->client->schedule, mapconn);

  /* The server is down. */
  mapconn->down = TRUE;

  /* Close connection, we didn't get any data. */
  SILC_LOG_DEBUG(("Closing connection to %s:%d", mapconn->conn->remote_host,
		  mapconn->conn->remote_port));
  silc_client_close_connection(mapconn->conn->client, mapconn->conn);

  /* Continue to produce the data and the map. */
  silc_map_process_data(mapconn->map, mapconn);
}

/* Close connection to server */

SILC_TASK_CALLBACK(silc_map_connect_close)
{
  SilcMapConnection mapconn = context;

  SILC_LOG_DEBUG(("Closing connection to %s:%d", mapconn->conn->remote_host,
		  mapconn->conn->remote_port));

  silc_client_close_connection(mapconn->conn->client, mapconn->conn);

  /* Continue to produce the data and the map. */
  silc_map_process_data(mapconn->map, mapconn);
}

/* Create connection to remote server to gather information about it. */

void silc_map_connect(SilcMap map, SilcMapConnection mapconn)
{
  char *ip;

  if (!mapconn->connect) {
    silc_schedule_task_add(map->client->schedule, 0,
			   silc_map_connect_timeout, mapconn, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  /* First configure IP is used to connect. */
  silc_dlist_start(mapconn->ips);
  ip = silc_dlist_get(mapconn->ips);

  SILC_LOG_DEBUG(("Creating connection to server %s:%d", ip, mapconn->port));

  /* Create connection.  We'll continue in the silc_connected after
     connection is created. */
  silc_client_connect_to_server(map->client, NULL,
				mapconn->port, ip, mapconn);

  /* Set connect timeout to detect if the server is down. */
  silc_schedule_task_add(map->client->schedule, 0,
			 silc_map_connect_timeout, mapconn,
			 mapconn->connect_timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}


/******* SILC Client Operations **********************************************/

/* "say" client operation is a message from the client library to the
   application.  It may include error messages or something else.  We
   just dump them to screen. */

static void
silc_say(SilcClient client, SilcClientConnection conn,
	 SilcClientMessageType type, char *msg, ...)
{

}


/* Message for a channel. The `sender' is the sender of the message
   The `channel' is the channel. The `message' is the message.  Note
   that `message' maybe NULL.  The `flags' indicates message flags
   and it is used to determine how the message can be interpreted
   (like it may tell the message is multimedia message). */

static void
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessagePayload payload,
		     SilcChannelPrivateKey key, SilcMessageFlags flags,
		     const unsigned char *message,
		     SilcUInt32 message_len)
{

}


/* Private message to the client. The `sender' is the sender of the
   message. The message is `message'and maybe NULL.  The `flags'
   indicates message flags  and it is used to determine how the message
   can be interpreted (like it may tell the message is multimedia
   message). */

static void
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessagePayload payload,
		     SilcMessageFlags flags,
		     const unsigned char *message,
		     SilcUInt32 message_len)
{

}


/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it because client library gets the channel entry from
   the Channel ID in the packet's header). */

static void
silc_notify(SilcClient client, SilcClientConnection conn,
	    SilcNotifyType type, ...)
{

}


/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occurred
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

static void
silc_command(SilcClient client, SilcClientConnection conn,
	     SilcClientCommandContext cmd_context, bool success,
	     SilcCommand command, SilcStatus status)
{

}


/* Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application.

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occurred.
   In this case arguments are not sent to the application. The `status' is
   the command reply status server returned. The `command' is the command
   reply being processed. The function has variable argument list and each
   command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

static void
silc_command_reply(SilcClient client, SilcClientConnection conn,
		   SilcCommandPayload cmd_payload, bool success,
		   SilcCommand command, SilcStatus status, ...)
{
  SilcMapConnection mapconn = conn->context;
  va_list va;

  /* If error occurred in client library with our command, print the error */
  if (status != SILC_STATUS_OK)
    fprintf(stderr, "COMMAND REPLY %s: %s\n",
	    silc_get_command_name(command),
	    silc_get_status_message(status));

  if (!success)
    return;

  va_start(va, status);

  switch (command) {
  case SILC_COMMAND_STATS:
    {
      unsigned char *stats = va_arg(va, unsigned char *);
      SilcUInt32 stats_len = va_arg(va, SilcUInt32);
      SilcBufferStruct buf;

      SILC_LOG_DEBUG(("STATS command reply from %s", conn->sock->hostname));

      /* Get statistics structure */
      silc_buffer_set(&buf, stats, stats_len);
      silc_buffer_unformat(&buf,
			   SILC_STR_UI_INT(&mapconn->data.starttime),
			   SILC_STR_UI_INT(&mapconn->data.uptime),
			   SILC_STR_UI_INT(&mapconn->data.clients),
			   SILC_STR_UI_INT(&mapconn->data.channels),
			   SILC_STR_UI_INT(&mapconn->data.server_ops),
			   SILC_STR_UI_INT(&mapconn->data.router_ops),
			   SILC_STR_UI_INT(&mapconn->data.cell_clients),
			   SILC_STR_UI_INT(&mapconn->data.cell_channels),
			   SILC_STR_UI_INT(&mapconn->data.cell_servers),
			   SILC_STR_UI_INT(&mapconn->data.all_clients),
			   SILC_STR_UI_INT(&mapconn->data.all_channels),
			   SILC_STR_UI_INT(&mapconn->data.all_servers),
			   SILC_STR_UI_INT(&mapconn->data.all_routers),
			   SILC_STR_UI_INT(&mapconn->data.all_server_ops),
			   SILC_STR_UI_INT(&mapconn->data.all_router_ops),
			   SILC_STR_END);

      mapconn->stats_received = TRUE;
    }
    break;

  case SILC_COMMAND_MOTD:
    {
      char *motd = va_arg(va, char *);

      SILC_LOG_DEBUG(("MOTD command reply"));

      mapconn->data.motd = motd ? strdup(motd) : NULL;
      mapconn->motd_received = motd ? TRUE : FALSE;
    }
    break;

  default:
    SILC_LOG_DEBUG(("Unsupported command reply"));
    break;
  };

  va_end(va);

  if (mapconn->motd && !mapconn->motd_received)
    return;
  if (!mapconn->stats_received)
    return;

  silc_schedule_task_del_by_context(client->schedule, mapconn);

  /* All data is gathered, time to disconnect from the server. */
  silc_schedule_task_add(client->schedule, 0,
			 silc_map_connect_close, mapconn, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}


/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere.
   If the `success' is FALSE the application must always call the function
   silc_client_close_connection. */

static void
silc_connected(SilcClient client, SilcClientConnection conn,
	       SilcClientConnectionStatus status)
{
  SilcMapConnection mapconn = conn->context;
  SilcMap map = mapconn->map;

  silc_schedule_task_del_by_context(client->schedule, mapconn);

  if (status != SILC_CLIENT_CONN_SUCCESS) {
    fprintf(stderr, "Could not connect to server %s\n",
		     conn->remote_host ? conn->remote_host : "");
    silc_client_close_connection(client, conn);

    /* Mark that this server is down. */
    silc_schedule_task_add(map->client->schedule, 0,
			   silc_map_connect_timeout, mapconn, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  if (mapconn->down) {
    /* Already timeouted */
    SILC_LOG_DEBUG(("Connection already timedout"));
    silc_client_close_connection(client, conn);
    return;
  }

  SILC_LOG_DEBUG(("Connected to server %s:%d", conn->remote_host,
		  conn->remote_port));

  mapconn->conn = conn;

  /* Get statistics */
  silc_client_command_call(client, conn, "STATS");

  /* Get motd if requested */
  if (mapconn->motd) {
    char motd[256];
    char *hostname;
    silc_dlist_start(mapconn->hostnames);
    hostname = silc_dlist_get(mapconn->hostnames);
    memset(motd, 0, sizeof(motd));
    silc_strncat(motd, sizeof(motd), "MOTD ", 5);
    silc_strncat(motd, sizeof(motd), hostname, strlen(hostname));
    silc_client_command_call(client, conn, motd);
  }

  /* Set data timeout to detect if the server is down. */
  silc_schedule_task_add(map->client->schedule, 0,
			 silc_map_data_timeout, mapconn,
			 mapconn->connect_timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}


/* Called to indicate that connection was disconnected to the server.
   The `status' may tell the reason of the disconnection, and if the
   `message' is non-NULL it may include the disconnection message
   received from server. */

static void
silc_disconnected(SilcClient client, SilcClientConnection conn,
		  SilcStatus status, const char *message)
{
  SilcMapConnection mapconn = conn->context;

  silc_schedule_task_del_by_context(client->schedule, mapconn);

  SILC_LOG_DEBUG(("Disconnected from server %s:%d", conn->remote_host,
		  conn->remote_port));

  mapconn->conn = NULL;
}


/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. When the authentication
   method has been resolved the `completion' callback with the found
   authentication method and authentication data is called. The `conn'
   may be NULL. */

static void
silc_get_auth_method(SilcClient client, SilcClientConnection conn,
		     char *hostname, SilcUInt16 port,
		     SilcGetAuthMeth completion,
		     void *context)
{
  /* No auth */
  completion(TRUE, SILC_AUTH_NONE, NULL, 0, context);
}


/* Verifies received public key. The `conn_type' indicates which entity
   (server, client etc.) has sent the public key. If user decides to trust
   the application may save the key as trusted public key for later
   use. The `completion' must be called after the public key has been
   verified. */

static void
silc_verify_public_key(SilcClient client, SilcClientConnection conn,
		       SilcSocketType conn_type, unsigned char *pk,
		       SilcUInt32 pk_len, SilcSKEPKType pk_type,
		       SilcVerifyPublicKey completion, void *context)
{
  /* Accept all keys without verification */
  completion(TRUE, context);
}


/* Ask (interact, that is) a passphrase from user. The passphrase is
   returned to the library by calling the `completion' callback with
   the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
   if not then the library will attempt to encode. */

static void
silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
		    SilcAskPassphrase completion, void *context)
{
  completion(NULL, 0, context);
}


/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and
   application must explicitly cast it to correct type.  Usually `failure'
   is 32 bit failure type (see protocol specs for all protocol failure
   types). */

static void
silc_failure(SilcClient client, SilcClientConnection conn,
	     SilcProtocol protocol, void *failure)
{
  fprintf(stderr, "Connecting failed (protocol failure)\n");
}


/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). If TRUE is returned also the
   `completion' and `context' arguments must be set by the application. */

static bool
silc_key_agreement(SilcClient client, SilcClientConnection conn,
		   SilcClientEntry client_entry, const char *hostname,
		   SilcUInt16 port, SilcKeyAgreementCallback *completion,
		   void **context)
{
  return FALSE;
}


/* Notifies application that file transfer protocol session is being
   requested by the remote client indicated by the `client_entry' from
   the `hostname' and `port'. The `session_id' is the file transfer
   session and it can be used to either accept or reject the file
   transfer request, by calling the silc_client_file_receive or
   silc_client_file_close, respectively. */

static void
silc_ftp(SilcClient client, SilcClientConnection conn,
	 SilcClientEntry client_entry, SilcUInt32 session_id,
	 const char *hostname, SilcUInt16 port)
{

}


/* Delivers SILC session detachment data indicated by `detach_data' to the
   application.  If application has issued SILC_COMMAND_DETACH command
   the client session in the SILC network is not quit.  The client remains
   in the network but is detached.  The detachment data may be used later
   to resume the session in the SILC Network.  The appliation is
   responsible of saving the `detach_data', to for example in a file.

   The detachment data can be given as argument to the functions
   silc_client_connect_to_server, or silc_client_add_connection when
   creating connection to remote server, inside SilcClientConnectionParams
   structure.  If it is provided the client library will attempt to resume
   the session in the network.  After the connection is created
   successfully, the application is responsible of setting the user
   interface for user into the same state it was before detaching (showing
   same channels, channel modes, etc).  It can do this by fetching the
   information (like joined channels) from the client library. */

static void
silc_detach(SilcClient client, SilcClientConnection conn,
	    const unsigned char *detach_data, SilcUInt32 detach_data_len)
{

}

/* This structure and all the functions were taken from the
   lib/silcclient/client_ops_example.c. */
SilcClientOperations silc_map_client_ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_connected,
  silc_disconnected,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_failure,
  silc_key_agreement,
  silc_ftp,
  silc_detach
};
