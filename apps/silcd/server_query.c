/*

  server_query.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

typedef struct {
  void *id;
  SilcIdType id_type;
} *SilcServerQueryID;

typedef struct {
  SilcUInt32 index;		    /* Index to IDs */
  bool from_cmd;		    /* TRUE if `index' is from command args,
				       otherwise from query->ids */
  SilcStatus error;		    /* The actual error */
} *SilcServerQueryError;

typedef struct {
  SilcCommand querycmd;		    /* Query command */
  SilcServerCommandContext cmd;	    /* Command context for query */

  char *nickname;		    /* Queried nickname */
  char *nick_server;		    /* Queried nickname's server */
  char *server_name;		    /* Queried server name */
  char *channel_name;		    /* Queried channel name */
  SilcServerQueryID ids;	    /* Queried IDs */
  SilcUInt32 ids_count;		    /* number of queried IDs */
  SilcUInt32 reply_count;	    /* Requested reply count */
  SilcDList attrs;		    /* Requested Attributes in WHOIS */

  SilcServerQueryError errors;	    /* Query errors */
  SilcUInt32 errors_count;	    /* number of errors */
} *SilcServerQuery;

void silc_server_query_free(SilcServerQuery query);
bool silc_server_query_check_error(SilcServer server,
				   SilcServerQuery query,
				   SilcServerCommandReplyContext cmdr);
void silc_server_query_send_error(SilcServer server,
				  SilcServerQuery query,
				  SilcStatus error, ...);
void silc_server_query_add_error(SilcServer server,
				 SilcServerQuery query,
				 bool from_cmd,
				 SilcUInt32 index,
				 SilcStatus error);
void silc_server_query_send_router(SilcServer server, SilcServerQuery query);
void silc_server_query_send_router_reply(void *context, void *reply);
void silc_server_query_parse(SilcServer server, SilcServerQuery query);
void silc_server_query_process(SilcServer server, SilcServerQuery query);


/* Free the query context structure and all allocated resources. */

void silc_server_query_free(SilcServerQuery query)
{
  int i;

  silc_server_command_free(query->cmd);

  silc_free(query->nickname);
  silc_free(query->nick_server);
  silc_free(query->server_name);
  silc_free(query->channel_name);

  for (i = 0; i < query->ids_count; i++)
    silc_free(query->ids[i].id);
  silc_free(query->ids);

  if (query->attrs)
    silc_attribute_payload_list_free(query->attrs);

  silc_free(query->errors);

  memset(query, 'F', sizeof(*query));
  silc_free(query);
}

/* Check whether command reply contained error, and reply the error to
   the original sender if it occurred. */

bool silc_server_query_check_error(SilcServer server,
				   SilcServerQuery query,
				   SilcServerCommandReplyContext cmdr)
{
  if (!cmdr)
    return FALSE;

  if (!silc_command_get_status(cmdr->payload, NULL, NULL)) {
    SilcBuffer buffer;

    /* Send the same command reply payload which contains the error */
    silc_command_set_command(cmdr->payload, query->querycmd);
    silc_command_set_ident(cmdr->payload,
			   silc_command_get_ident(query->cmd->payload));
    buffer = silc_command_payload_encode_payload(cmdr->payload);
    silc_server_packet_send(server, query->cmd->sock,
			    SILC_PACKET_COMMAND_REPLY, 0, 
			    buffer->data, buffer->len, FALSE);
    silc_buffer_free(buffer);
    return TRUE;
  }

  return FALSE;
}

/* Send error reply indicated by the `error' to the original sender of
   the query. */

void silc_server_query_send_error(SilcServer server,
				  SilcServerQuery query,
				  SilcStatus error, ...)
{
  va_list va;
  SilcBuffer packet;
  unsigned char *data = NULL;
  SilcUInt32 data_len = 0, data_type = 0, argc = 0;

  va_start(va, error);
  data_type = va_arg(va, SilcUInt32);
  if (data_type) {
    argc = 1;
    data = va_arg(va, unsigned char *);
    data_len = va_arg(va, SilcUInt32);
  }

  /* Send the command reply with error */
  packet = silc_command_reply_payload_encode_va(
			       query->querycmd, error, 0,
			       silc_command_get_ident(query->cmd->payload),
			       argc, data_type, data, data_len);
  silc_server_packet_send(server, query->cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  va_end(va);
}

/* Add error to error list.  Multiple errors may occur during the query
   processing and this function can be used to add one error.  The
   `type_index' is the index to the command context which includes the
   argument which caused the error. */

void silc_server_query_add_error(SilcServer server,
				 SilcServerQuery query,
				 bool from_cmd,
				 SilcUInt32 index,
				 SilcStatus error)
{
  query->errors = silc_realloc(query->errors, sizeof(*query->errors) *
			       (query->errors_count + 1));
  if (!query->errors)
    return;
  query->errors[query->errors_count].index = index;
  query->errors[query->errors_count].from_cmd = from_cmd;
  query->errors[query->errors_count].error = error;
  query->errors_count++;
}

/* Processes query as command.  The `query' is the command that is
   being processed indicated by the `cmd'.  The `query' can be one of
   the following: SILC_COMMAND_WHOIS, SILC_COMMAND_WHOWAS or
   SILC_COMMAND_IDENTIFY.  This function handles the reply sending
   to the entity who sent this query to us automatically.  Returns
   TRUE if the query is being processed or FALSE on error. */

bool silc_server_query_command(SilcServer server, SilcCommand querycmd,
			       SilcServerCommandContext cmd)
{
  SilcServerQuery query;

  switch (querycmd) {

  case SILC_COMMAND_WHOIS:
    {
      query = silc_calloc(1, sizeof(*query));
      query->querycmd = querycmd;
      query->cmd = silc_server_command_dup(cmd);

      /* If we are normal server and query contains nickname, send it
	 directly to router. */
      if (server->server_type == SILC_SERVER && !server->standalone &&
	  silc_argument_get_arg_type(cmd->args, 1, NULL)) {
	silc_server_query_send_router(server, query);
	break;
      }

      /* Now parse the WHOIS query */
      silc_server_query_parse(server, query);
    }
    break;

  case SILC_COMMAND_WHOWAS:
    {
      query = silc_calloc(1, sizeof(*query));
      query->querycmd = querycmd;
      query->cmd = silc_server_command_dup(cmd);

      /* WHOWAS query is always sent to router if we are normal server */
      if (server->server_type == SILC_SERVER && !server->standalone) {
	silc_server_query_send_router(server, query);
	break;
      }

      /* Now parse the WHOWAS query */
      silc_server_query_parse(server, query);
    }
    break;

  case SILC_COMMAND_IDENTIFY:
    {
      query = silc_calloc(1, sizeof(*query));
      query->querycmd = querycmd;
      query->cmd = silc_server_command_dup(cmd);

      /* If we are normal server and query does not contain IDs, send it
	 directly to router (it contains nickname, server name or channel
	 name). */
      if (server->server_type == SILC_SERVER && !server->standalone &&
	  !silc_argument_get_arg_type(cmd->args, 5, NULL)) {
	silc_server_query_send_router(server, query);
	break;
      }

      /* Now parse the IDENTIFY query */
      silc_server_query_parse(server, query);
    }
    break;

  default:
    SILC_LOG_ERROR(("Bad query using %d command", querycmd));
    return FALSE;
  }

  return TRUE;
}

/* Send the received query to our primary router since we could not
   handle the query directly.  We will reprocess the query after our
   router replies back. */

void silc_server_query_send_router(SilcServer server, SilcServerQuery query)
{
  SilcBuffer tmpbuf;
  SilcUInt16 old_ident;

  /* Send WHOIS command to our router */
  old_ident = silc_command_get_ident(query->cmd->payload);
  silc_command_set_ident(query->cmd->payload, ++server->cmd_ident);
  tmpbuf = silc_command_payload_encode_payload(query->cmd->payload);
  silc_server_packet_send(server, 
			  SILC_PRIMARY_ROUTE(server),
			  SILC_PACKET_COMMAND, 0,
			  tmpbuf->data, tmpbuf->len, TRUE);
  silc_command_set_ident(query->cmd->payload, old_ident);
  silc_buffer_free(tmpbuf);

  /* Continue parsing the query after received reply from router */
  silc_server_command_pending(server, query->querycmd, server->cmd_ident,
			      silc_server_query_send_router_reply, query);
}

/* Reply callback called after primary router has replied to our initial
   sending of the query to it.  We will proceed the query in this function. */

void silc_server_query_send_router_reply(void *context, void *reply)
{
  SilcServerQuery query = context;
  SilcServer server = query->cmd->server;

  /* Check if router sent error reply */
  if (!silc_server_query_check_error(server, query, reply)) {
    silc_server_query_free(query);
    return;
  }

  /* Continue with parsing */
  silc_server_query_parse(server, query);
}

/* Parse the command query and start processing the queries in detail. */

void silc_server_query_parse(SilcServer server, SilcServerQuery query)
{
  SilcServerCommandContext cmd = query->cmd;
  unsigned char *tmp;
  SilcUInt32 tmp_len, argc = silc_argument_get_arg_num(cmd->args);
  void *id;
  SilcIdType id_type;
  int i;

  switch (query->querycmd) {

  case SILC_COMMAND_WHOIS:
    {
      /* Get Client IDs if present. Take IDs always instead of nickname. */
      tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
      if (!tmp) {

	/* Get nickname */
	tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
	if (!tmp) {
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	  silc_server_query_free(query);
	  return;
	}

	/* Get the nickname@server string and parse it */
	if (!silc_parse_userfqdn(tmp, &query->nickname, &query->nick_server)) {
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_BAD_NICKNAME, 0);
	  silc_server_query_free(query);
	  return;
	}

      } else {
	/* Parse the IDs included in the query */
	query->ids = silc_calloc(argc, sizeof(*query->ids));

	for (i = 0; i < argc; i++) {
	  tmp = silc_argument_get_arg_type(cmd->args, i + 4, &tmp_len);
	  if (!tmp)
	    continue;

	  id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
	  if (!id) {
	    silc_server_query_add_error(server, query, TRUE, i + 4,
					SILC_STATUS_ERR_BAD_CLIENT_ID);
	    continue;
	  }

	  query->ids[query->ids_count].id = id;
	  query->ids[query->ids_count].id_type = SILC_ID_CLIENT;
	  query->ids_count++;
	}
      }

      /* Get the max count of reply messages allowed */
      tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
      if (tmp && tmp_len == sizeof(SilcUInt32))
	SILC_GET32_MSB(query->reply_count, tmp);

      /* Get requested attributes if set */
      tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
      if (tmp)
	query->attrs = silc_attribute_payload_parse_list(tmp, tmp_len);
    }
    break;

  case SILC_COMMAND_WHOWAS:
    {
      /* Get nickname */
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      if (!tmp) {
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	silc_server_query_free(query);
	return;
      }

      /* Get the nickname@server string and parse it */
      if (!silc_parse_userfqdn(tmp, &query->nickname, &query->nick_server)) {
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_BAD_NICKNAME, 0);
	silc_server_query_free(query);
	return;
      }

      /* Get the max count of reply messages allowed */
      tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
      if (tmp && tmp_len == sizeof(SilcUInt32))
	SILC_GET32_MSB(query->reply_count, tmp);
    }
    break;

  case SILC_COMMAND_IDENTIFY:
    {
      /* Get IDs if present. Take IDs always instead of names. */
      tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
      if (!tmp) {

	/* Try get nickname */
	tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
	if (tmp) {
	  /* Get the nickname@server string and parse it */
	  if (!silc_parse_userfqdn(tmp, &query->nickname, &query->nick_server))
	    silc_server_query_add_error(server, query, TRUE, 1,
					SILC_STATUS_ERR_BAD_NICKNAME);
	}

	/* Try get server name */
	tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
	if (tmp)
	  query->server_name = silc_memdup(tmp, tmp_len);

	/* Get channel name */
	tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
	if (tmp)
	  query->channel_name = silc_memdup(tmp, tmp_len);

      } else {
	/* Parse the IDs included in the query */
	query->ids = silc_calloc(argc, sizeof(*query->ids));

	for (i = 0; i < argc; i++) {
	  tmp = silc_argument_get_arg_type(cmd->args, i + 5, &tmp_len);
	  if (!tmp)
	    continue;

	  id = silc_id_payload_parse_id(tmp, tmp_len, &id_type);
	  if (!id) {
	    silc_server_query_add_error(server, query, TRUE, i + 5,
					SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    continue;
	  }

	  query->ids[query->ids_count].id = id;
	  query->ids[query->ids_count].id_type = id_type;
	  query->ids_count++;
	}
      }

      /* Get the max count of reply messages allowed */
      tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
      if (tmp && tmp_len == sizeof(SilcUInt32))
	SILC_GET32_MSB(query->reply_count, tmp);
    }
    break;
  }

  /* Start processing the query information */
  silc_server_query_process(server, query);
}

/* Processes the parsed query.  This does the actual finding of the
   queried information and prepares for sending reply to the original
   sender of the query command.  It is guaranteed that this function
   (which may be slow) is called only once for entire query. */

void silc_server_query_process(SilcServer server, SilcServerQuery query)
{
  SilcServerCommandContext cmd = query->cmd;
  bool check_global = FALSE;
  void *entry;
  SilcClientEntry *clients = NULL;
  SilcChannelEntry *channels = NULL;
  SilcServerEntry *servers = NULL;
  SilcUInt32 clients_count = 0, channels_count = 0, servers_count = 0;
  int i;

  /* Check global lists if query is coming from client or we are not
     normal server (we know global information). */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    check_global = TRUE;
  else if (server->server_type != SILC_SERVER)
    check_global = TRUE;

  if (query->nickname) {
    /* Get all clients matching nickname from local list */
    if (!silc_idlist_get_clients_by_hash(server->local_list, 
					 query->nickname, server->md5hash,
					 &clients, &clients_count))
      silc_idlist_get_clients_by_nickname(server->local_list, 
					  query->nickname,
					  query->nick_server,
					  &clients, &clients_count);

    /* Check global list as well */
    if (check_global) {
      if (!silc_idlist_get_clients_by_hash(server->global_list, 
					   query->nickname, server->md5hash,
					   &clients, &clients_count))
	silc_idlist_get_clients_by_nickname(server->global_list, 
					    query->nickname,
					    query->nick_server,
					    &clients, &clients_count);
    }

    if (!clients)
      silc_server_query_add_error(server, query, TRUE, 1,
				  SILC_STATUS_ERR_NO_SUCH_NICK);
  }

  if (query->server_name) {
    /* Find server by name */
    entry = silc_idlist_find_server_by_name(server->local_list,
					    query->server_name, TRUE, NULL);
    if (!entry && check_global)
      entry = silc_idlist_find_server_by_name(server->global_list,
					      query->server_name, TRUE, NULL);
    if (entry) {
      servers = silc_realloc(servers, sizeof(*servers) * (servers_count + 1));
      servers[servers_count++] = (SilcServerEntry)entry;
    }

    if (!servers)
      silc_server_query_add_error(server, query, TRUE, 2,
				  SILC_STATUS_ERR_NO_SUCH_SERVER);
  }

  if (query->channel_name) {
    /* Find channel by name */
    entry = silc_idlist_find_channel_by_name(server->local_list,
					     query->channel_name, NULL);
    if (!entry && check_global)
      entry = silc_idlist_find_channel_by_name(server->global_list,
					       query->channel_name, NULL);
    if (entry) {
      channels = silc_realloc(channels, sizeof(*channels) * 
			      (channels_count + 1));
      channels[channels_count++] = (SilcChannelEntry)entry;
    }

    if (!channels)
      silc_server_query_add_error(server, query, TRUE, 3,
				  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
  }

  if (query->ids_count) {
    /* Find entries by the queried IDs */
    for (i = 0; i < query->ids_count; i++) {
      void *id = query->ids[i].id;
      if (!id)
	continue;

      switch (query->ids[i].id_type) {

      case SILC_ID_CLIENT:
	/* Get client entry */
	entry = silc_idlist_find_client_by_id(server->local_list, 
					      id, TRUE, NULL);
	if (!entry && check_global)
	  entry = silc_idlist_find_client_by_id(server->global_list, 
						id, TRUE, NULL);
	if (!entry) {
	  silc_server_query_add_error(server, query, FALSE, i,
				      SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
	  continue;
	}

	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = (SilcClientEntry)entry;
	break;

      case SILC_ID_SERVER:
	/* Get server entry */
	entry = silc_idlist_find_server_by_id(server->local_list, 
					      id, TRUE, NULL);
	if (!entry && check_global)
	  entry = silc_idlist_find_server_by_id(server->global_list, 
						id, TRUE, NULL);
	if (!entry) {
	  silc_server_query_add_error(server, query, FALSE, i,
				      SILC_STATUS_ERR_NO_SUCH_SERVER_ID);
	  continue;
	}

	servers = silc_realloc(servers, sizeof(*servers) * 
			       (servers_count + 1));
	servers[servers_count++] = (SilcServerEntry)entry;
	break;

      case SILC_ID_CHANNEL:
	/* Get channel entry */
	entry = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
	if (!entry && check_global)
	  entry = silc_idlist_find_channel_by_id(server->global_list, id,
						 NULL);
	if (!entry) {
	  silc_server_query_add_error(server, query, FALSE, i,
				      SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID);
	  continue;
	}

	channels = silc_realloc(channels, sizeof(*channels) * 
				(channels_count + 1));
	channels[channels_count++] = (SilcChannelEntry)entry;
	break;

      default:
	break;
      }
    }
  }

  /* If nothing was found, then just send the errors */
  if (!clients && !channels && !servers) {

    silc_server_query_free(query);
    return;
  }

  /* Now process all found information and if necessary do some more
     querying. */

}

/* Find client by the Client ID indicated by the `client_id', and if not
   found then query it by using WHOIS command.  The client information
   is also resolved if the cached information is incomplete or if the
   `always_resolve' is set to TRUE.  The indication whether requested
   client was being resolved is saved into `resolved'.  If the client
   is not being resolved its entry is returned by this function.  NULL
   is returned if client is resolved. */

SilcClientEntry silc_server_query_client(SilcServer server,
					 const SilcClientID *client_id,
					 bool always_resolve,
					 bool *resolved)
{
  SilcClientEntry client;

  if (resolved)
    *resolved = FALSE;

  client = silc_idlist_find_client_by_id(server->local_list,
					 (SilcClientID *)client_id,
					 TRUE, NULL);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list,
					   (SilcClientID *)client_id,
					   TRUE, NULL);
    if (!client && server->server_type == SILC_ROUTER)
      return NULL;
  }

  if (!client && server->standalone)
    return NULL;

  if (!client || !client->nickname || !client->username ||
      always_resolve) {
    SilcBuffer buffer, idp;

    if (client) {
      client->data.status |= SILC_IDLIST_STATUS_RESOLVING;
      client->data.status &= ~SILC_IDLIST_STATUS_RESOLVED;
      client->resolve_cmd_ident = ++server->cmd_ident;
    }

    idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_WHOIS,
					    server->cmd_ident, 1,
					    4, idp->data, idp->len);
    silc_server_packet_send(server, client ? client->router->connection :
			    SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, 0,
			    buffer->data, buffer->len, FALSE);
    silc_buffer_free(idp);
    silc_buffer_free(buffer);

    if (resolved)
      *resolved = TRUE;

    return NULL;
  }

  return client;
}
