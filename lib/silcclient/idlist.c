/*

  idlist.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

/******************************************************************************

                         Client Searching Locally

******************************************************************************/

/* Same as silc_client_get_clients function but does not resolve anything
   from the server. This checks local cache and returns all matching
   clients from the local cache. If none was found this returns NULL.
   The `nickname' is the real nickname of the client, and the `format'
   is the formatted nickname to find exact match from multiple found
   entries. The format must be same as given in the SilcClientParams
   structure to the client library. If the `format' is NULL all found
   clients by `nickname' are returned. */

SilcClientEntry *silc_client_get_clients_local(SilcClient client,
					       SilcClientConnection conn,
					       const char *nickname,
					       const char *format,
					       SilcUInt32 *clients_count)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list = NULL;
  SilcClientEntry entry, *clients;
  int i = 0;
  bool found = FALSE;

  assert(client && conn);
  if (!nickname)
    return NULL;

  /* Find ID from cache */
  if (!silc_idcache_find_by_name(conn->internal->client_cache,
				 (char *)nickname, &list))
    return NULL;

  if (!silc_idcache_list_count(list)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  clients = silc_calloc(silc_idcache_list_count(list), sizeof(*clients));
  *clients_count = silc_idcache_list_count(list);

  if (!format) {
    /* Take all without any further checking */
    silc_idcache_list_first(list, &id_cache);
    while (id_cache) {
      clients[i++] = id_cache->context;
      found = TRUE;
      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  } else {
    /* Check multiple cache entries for match */
    silc_idcache_list_first(list, &id_cache);
    while (id_cache) {
      entry = (SilcClientEntry)id_cache->context;
      if (strcasecmp(entry->nickname, format)) {
	if (!silc_idcache_list_next(list, &id_cache)) {
	  break;
	} else {
	  continue;
	}
      }

      clients[i++] = id_cache->context;
      found = TRUE;
      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  }

  if (list)
    silc_idcache_list_free(list);

  if (!found) {
    *clients_count = 0;
    if (clients)
      silc_free(clients);
    return NULL;
  }

  return clients;
}


/******************************************************************************

                        Client Resolving from Server

******************************************************************************/

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcGetClientCallback completion;
  void *context;
  char *nickname;
  char *server;
} *GetClientInternal;

SILC_CLIENT_CMD_FUNC(get_client_callback)
{
  GetClientInternal i = (GetClientInternal)context;
  SilcClientEntry *clients;
  SilcUInt32 clients_count;

  /* Get the clients */
  clients = silc_client_get_clients_local(i->client, i->conn,
					  i->nickname, i->server,
					  &clients_count);
  if (clients) {
    i->completion(i->client, i->conn, clients, clients_count, i->context);
    silc_free(clients);
  } else {
    i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  silc_free(i->nickname);
  silc_free(i->server);
  silc_free(i);
}

/* Finds client entry or entries by the `nickname' and `server'. The
   completion callback will be called when the client entries has been found.

   Note: this function is always asynchronous and resolves the client
   information from the server. Thus, if you already know the client
   information then use the silc_client_get_client_by_id function to
   get the client entry since this function may be very slow and should
   be used only to initially get the client entries. */

void silc_client_get_clients(SilcClient client,
			     SilcClientConnection conn,
			     const char *nickname,
			     const char *server,
			     SilcGetClientCallback completion,
			     void *context)
{
  GetClientInternal i;
  int len;
  char *userhost;

  assert(client && conn);

  if (!nickname)
    return;

  i = silc_calloc(1, sizeof(*i));
  i->client = client;
  i->conn = conn;
  i->nickname = strdup(nickname);
  i->server = server ? strdup(server) : NULL;
  i->completion = completion;
  i->context = context;

  if (nickname && server) {
    len = strlen(nickname) + strlen(server) + 3;
    userhost = silc_calloc(len, sizeof(*userhost));
    silc_strncat(userhost, len, nickname, strlen(nickname));
    silc_strncat(userhost, len, "@", 1);
    silc_strncat(userhost, len, server, strlen(server));
  } else {
    userhost = silc_memdup(nickname, strlen(nickname));
  }

  /* Register our own command reply for this command */
  silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
			       silc_client_command_reply_identify_i, 0,
			       ++conn->cmd_ident);

  /* Send the command */
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
			   conn->cmd_ident, 1, 1, userhost,
			   strlen(userhost));

  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident,
			      silc_client_command_get_client_callback,
			      (void *)i);

  silc_free(userhost);
}

/* The old style function to find client entry. This is used by the
   library internally. If `query' is TRUE then the client information is
   requested by the server. The pending command callback must be set
   by the caller. */
/* XXX This function should be removed */

SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       const char *nickname,
				       const char *format,
				       bool query)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list = NULL;
  SilcClientEntry entry = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Find ID from cache */
  if (!silc_idcache_find_by_name(conn->internal->client_cache,
				 (char *)nickname, &list)) {
  identify:

    if (query) {
      SILC_LOG_DEBUG(("Requesting Client ID from server"));

      /* Register our own command reply for this command */
      silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
				   silc_client_command_reply_identify_i, 0,
				   ++conn->cmd_ident);

      /* Send the command */
      silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
			       conn->cmd_ident, 1, 1, nickname,
			       strlen(nickname));

      if (list)
	silc_idcache_list_free(list);

      return NULL;
    }
    return NULL;
  }

  if (!format) {
    /* Take first found cache entry */
    if (!silc_idcache_list_first(list, &id_cache))
      goto identify;

    entry = (SilcClientEntry)id_cache->context;
  } else {
    /* Check multiple cache entries for match */
    silc_idcache_list_first(list, &id_cache);
    while (id_cache) {
      entry = (SilcClientEntry)id_cache->context;

      if (strcasecmp(entry->nickname, format)) {
	if (!silc_idcache_list_next(list, &id_cache)) {
	  entry = NULL;
	  break;
	} else {
	  entry = NULL;
	  continue;
	}
      }

      break;
    }

    /* If match weren't found, request it */
    if (!entry)
      goto identify;
  }

  if (list)
    silc_idcache_list_free(list);

  return entry;
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcUInt32 list_count;
  SilcBuffer client_id_list;
  SilcGetClientCallback completion;
  void *context;
  int res_count;
} *GetClientsByListInternal;

SILC_CLIENT_CMD_FUNC(get_clients_list_callback)
{
  GetClientsByListInternal i = (GetClientsByListInternal)context;
  SilcIDCacheEntry id_cache = NULL;
  SilcBuffer client_id_list = i->client_id_list;
  SilcClientEntry *clients = NULL;
  SilcUInt32 clients_count = 0;
  bool found = FALSE;
  int c;

  SILC_LOG_DEBUG(("Start"));

  if (i->res_count) {
    i->res_count--;
    if (i->res_count)
      return;
  }

  SILC_LOG_DEBUG(("Resolved all clients"));

  clients = silc_calloc(i->list_count, sizeof(*clients));

  for (c = 0; c < i->list_count; c++) {
    SilcUInt16 idp_len;
    SilcClientID *client_id;

    /* Get Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len, NULL);
    if (!client_id) {
      silc_buffer_pull(client_id_list, idp_len);
      continue;
    }

    /* Get the client entry */
    if (silc_idcache_find_by_id_one_ext(i->conn->internal->client_cache,
					(void *)client_id,
					NULL, NULL,
					silc_hash_client_id_compare, NULL,
					&id_cache)) {
      clients[clients_count] = (SilcClientEntry)id_cache->context;
      clients_count++;
      found = TRUE;
    }

    silc_free(client_id);
    silc_buffer_pull(client_id_list, idp_len);
  }

  if (found) {
    i->completion(i->client, i->conn, clients, clients_count, i->context);
    silc_free(clients);
  } else {
    i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  if (i->client_id_list)
    silc_buffer_free(i->client_id_list);
  silc_free(i);
}

/* Gets client entries by the list of client ID's `client_id_list'. This
   always resolves those client ID's it does not know yet from the server
   so this function might take a while. The `client_id_list' is a list
   of ID Payloads added one after other.  JOIN command reply and USERS
   command reply for example returns this sort of list. The `completion'
   will be called after the entries are available. */

void silc_client_get_clients_by_list(SilcClient client,
				     SilcClientConnection conn,
				     SilcUInt32 list_count,
				     SilcBuffer client_id_list,
				     SilcGetClientCallback completion,
				     void *context)
{
  SilcIDCacheEntry id_cache = NULL;
  int i;
  unsigned char **res_argv = NULL;
  SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;
  GetClientsByListInternal in;
  bool wait_res = FALSE;

  assert(client && conn && client_id_list);

  SILC_LOG_DEBUG(("Start"));

  in = silc_calloc(1, sizeof(*in));
  in->client = client;
  in->conn = conn;
  in->list_count = list_count;
  in->client_id_list = silc_buffer_copy(client_id_list);
  in->completion = completion;
  in->context = context;

  for (i = 0; i < list_count; i++) {
    SilcUInt16 idp_len;
    SilcClientID *client_id;
    SilcClientEntry entry;
    bool ret;

    /* Get Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len, NULL);
    if (!client_id) {
      silc_buffer_pull(client_id_list, idp_len);
      continue;
    }

    /* Check if we have this client cached already. */
    ret =
      silc_idcache_find_by_id_one_ext(conn->internal->client_cache,
				      (void *)client_id, NULL, NULL,
				      silc_hash_client_id_compare, NULL,
				      &id_cache);

    /* If we don't have the entry or it has incomplete info, then resolve
       it from the server. */
    if (!ret || !((SilcClientEntry)id_cache->context)->nickname) {
      entry = ret ? (SilcClientEntry)id_cache->context : NULL;

      if (entry) {
	if (entry->status & SILC_CLIENT_STATUS_RESOLVING) {
	  /* Attach to this resolving and wait until it finishes */
	  silc_client_command_pending(
			    conn, SILC_COMMAND_NONE,
			    entry->resolve_cmd_ident,
			    silc_client_command_get_clients_list_callback,
			    (void *)in);
	  wait_res = TRUE;
	  in->res_count++;

	  silc_free(client_id);
	  silc_buffer_pull(client_id_list, idp_len);
	  continue;
	}

	entry->status |= SILC_CLIENT_STATUS_RESOLVING;
	entry->resolve_cmd_ident = conn->cmd_ident + 1;
      }

      /* No we don't have it, query it from the server. Assemble argument
	 table that will be sent for the IDENTIFY command later. */
      res_argv = silc_realloc(res_argv, sizeof(*res_argv) *
			      (res_argc + 1));
      res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				   (res_argc + 1));
      res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				    (res_argc + 1));
      res_argv[res_argc] = client_id_list->data;
      res_argv_lens[res_argc] = idp_len;
      res_argv_types[res_argc] = res_argc + 5;
      res_argc++;
    }

    silc_free(client_id);
    silc_buffer_pull(client_id_list, idp_len);
  }

  silc_buffer_push(client_id_list, client_id_list->data -
		   client_id_list->head);

  /* Query the client information from server if the list included clients
     that we don't know about. */
  if (res_argc) {
    SilcBuffer res_cmd;

    /* Send the IDENTIFY command to server */
    res_cmd = silc_command_payload_encode(SILC_COMMAND_IDENTIFY,
					  res_argc, res_argv, res_argv_lens,
					  res_argv_types, ++conn->cmd_ident);
    silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND,
			    NULL, 0, NULL, NULL, res_cmd->data, res_cmd->len,
			    TRUE);

    /* Register our own command reply for this command */
    silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
				 silc_client_command_reply_identify_i, 0,
				 conn->cmd_ident);

    /* Process the applications request after reply has been received  */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident,
				silc_client_command_get_clients_list_callback,
				(void *)in);
    in->res_count++;

    silc_buffer_free(res_cmd);
    silc_free(res_argv);
    silc_free(res_argv_lens);
    silc_free(res_argv_types);
    return;
  }

  if (wait_res)
    return;

  /* We have the clients in cache, get them and call the completion */
  silc_client_command_get_clients_list_callback((void *)in, NULL);
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcChannelID channel_id;
  SilcGetClientCallback completion;
  void *context;
  int res_count;
} *GetClientsByChannelInternal;

SILC_CLIENT_CMD_FUNC(get_clients_by_channel_cb)
{
  GetClientsByChannelInternal i = context;
  SilcClientEntry *clients = NULL;
  SilcUInt32 clients_count = 0;
  bool found = FALSE;
  SilcChannelEntry channel;
  SilcHashTableList htl;
  SilcChannelUser chu;

  channel = silc_client_get_channel_by_id(i->client, i->conn, &i->channel_id);
  if (channel && !silc_hash_table_count(channel->user_list)) {
    clients = silc_calloc(silc_hash_table_count(channel->user_list),
			  sizeof(*clients));
    silc_hash_table_list(channel->user_list, &htl);
    while (silc_hash_table_get(&htl, NULL, (void *)&chu))
      clients[clients_count++] = chu->client;
    silc_hash_table_list_reset(&htl);
    found = TRUE;
  }

  if (found) {
    i->completion(i->client, i->conn, clients, clients_count, i->context);
    silc_free(clients);
  } else {
    i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  silc_free(i);
}

/* Gets client entries by the channel entry indicated by `channel'.  Thus,
   it resolves the clients currently on that channel. */

void silc_client_get_clients_by_channel(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					SilcGetClientCallback completion,
					void *context)
{
  GetClientsByChannelInternal in;
  SilcHashTableList htl;
  SilcChannelUser chu;
  SilcClientEntry entry;
  unsigned char **res_argv = NULL;
  SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;
  SilcBuffer idp;
  bool wait_res = FALSE;

  assert(client && conn && channel);

  SILC_LOG_DEBUG(("Start"));

  in = silc_calloc(1, sizeof(*in));
  in->client = client;
  in->conn = conn;
  in->channel_id = *channel->id;
  in->completion = completion;
  in->context = context;

  /* If user list does not exist, send USERS command. */
  if (!channel->user_list || !silc_hash_table_count(channel->user_list)) {
    SILC_LOG_DEBUG(("Sending USERS"));
    silc_client_command_register(client, SILC_COMMAND_USERS, NULL, NULL,
				 silc_client_command_reply_users_i, 0,
				 ++conn->cmd_ident);
    silc_client_command_send(client, conn, SILC_COMMAND_USERS,
			     conn->cmd_ident, 1, 2, channel->channel_name,
			     strlen(channel->channel_name));
    silc_client_command_pending(conn, SILC_COMMAND_USERS, conn->cmd_ident,
				silc_client_command_get_clients_by_channel_cb,
				in);
    return;
  }

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
    entry = chu->client;

    /* If the entry has incomplete info, then resolve it from the server. */
    if (!entry->nickname || !entry->realname) {
      if (entry->status & SILC_CLIENT_STATUS_RESOLVING) {
	/* Attach to this resolving and wait until it finishes */
	silc_client_command_pending(
			    conn, SILC_COMMAND_NONE,
			    entry->resolve_cmd_ident,
			    silc_client_command_get_clients_by_channel_cb,
			    (void *)in);
	wait_res = TRUE;
	in->res_count++;
	continue;
      }
      entry->status |= SILC_CLIENT_STATUS_RESOLVING;
      entry->resolve_cmd_ident = conn->cmd_ident + 1;

      idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);

      /* No we don't have it, query it from the server. Assemble argument
	 table that will be sent for the WHOIS command later. */
      res_argv = silc_realloc(res_argv, sizeof(*res_argv) *
			      (res_argc + 1));
      res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				   (res_argc + 1));
      res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				    (res_argc + 1));
      res_argv[res_argc] = silc_memdup(idp->data, idp->len);
      res_argv_lens[res_argc] = idp->len;
      res_argv_types[res_argc] = res_argc + 4;
      res_argc++;

      silc_buffer_free(idp);
    }
  }
  silc_hash_table_list_reset(&htl);

  /* Query the client information from server if the list included clients
     that we don't know about. */
  if (res_argc) {
    SilcBuffer res_cmd;

    /* Send the WHOIS command to server */
    res_cmd = silc_command_payload_encode(SILC_COMMAND_WHOIS,
					  res_argc, res_argv, res_argv_lens,
					  res_argv_types, ++conn->cmd_ident);
    silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND,
			    NULL, 0, NULL, NULL, res_cmd->data, res_cmd->len,
			    TRUE);

    /* Register our own command reply for this command */
    silc_client_command_register(client, SILC_COMMAND_WHOIS, NULL, NULL,
				 silc_client_command_reply_whois_i, 0,
				 conn->cmd_ident);

    /* Process the applications request after reply has been received  */
    silc_client_command_pending(
			   conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			   silc_client_command_get_clients_by_channel_cb,
			   (void *)in);
    in->res_count++;

    silc_buffer_free(res_cmd);
    silc_free(res_argv);
    silc_free(res_argv_lens);
    silc_free(res_argv_types);
    return;
  }

  if (wait_res)
    return;

  /* We have the clients in cache, get them and call the completion */
  silc_client_command_get_clients_by_channel_cb((void *)in, NULL);
}

/* Finds entry for client by the client's ID. Returns the entry or NULL
   if the entry was not found. */

SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id)
{
  SilcIDCacheEntry id_cache;

  assert(client && conn);
  if (!client_id)
    return NULL;

  SILC_LOG_DEBUG(("Finding client by ID (%s)",
		  silc_id_render(client_id, SILC_ID_CLIENT)));

  /* Find ID from cache */
  if (!silc_idcache_find_by_id_one_ext(conn->internal->client_cache,
				       (void *)client_id, NULL, NULL,
				       silc_hash_client_id_compare, NULL,
				       &id_cache))
    return NULL;

  SILC_LOG_DEBUG(("Found"));

  return (SilcClientEntry)id_cache->context;
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcClientID *client_id;
  SilcGetClientCallback completion;
  void *context;
} *GetClientByIDInternal;

SILC_CLIENT_CMD_FUNC(get_client_by_id_callback)
{
  GetClientByIDInternal i = (GetClientByIDInternal)context;
  SilcClientEntry entry;

  /* Get the client */
  entry = silc_client_get_client_by_id(i->client, i->conn, i->client_id);
  if (entry) {
    if (i->completion)
      i->completion(i->client, i->conn, &entry, 1, i->context);
  } else {
    if (i->completion)
      i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  silc_free(i->client_id);
  silc_free(i);
}

/* Same as above but will always resolve the information from the server.
   Use this only if you know that you don't have the entry and the only
   thing you know about the client is its ID. */

void silc_client_get_client_by_id_resolve(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientID *client_id,
					  SilcBuffer attributes,
					  SilcGetClientCallback completion,
					  void *context)
{
  SilcBuffer idp;
  GetClientByIDInternal i = silc_calloc(1, sizeof(*i));

  assert(client && conn && client_id);

  SILC_LOG_DEBUG(("Start"));

  i->client = client;
  i->conn = conn;
  i->client_id = silc_id_dup(client_id, SILC_ID_CLIENT);
  i->completion = completion;
  i->context = context;

  /* Register our own command reply for this command */
  silc_client_command_register(client, SILC_COMMAND_WHOIS, NULL, NULL,
			       silc_client_command_reply_whois_i, 0,
			       ++conn->cmd_ident);

  /* Send the command */
  idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  silc_client_command_send(client, conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			   2, 3, attributes ? attributes->data : NULL,
			   attributes ? attributes->len : 0,
			   4, idp->data, idp->len);
  silc_buffer_free(idp);

  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			      silc_client_command_get_client_by_id_callback,
			      (void *)i);
}


/******************************************************************************

                Client, Channel and Server entry manipulation

******************************************************************************/


/* Creates new client entry and adds it to the ID cache. Returns pointer
   to the new entry. */

SilcClientEntry
silc_client_add_client(SilcClient client, SilcClientConnection conn,
		       char *nickname, char *username,
		       char *userinfo, SilcClientID *id, SilcUInt32 mode)
{
  SilcClientEntry client_entry;
  char *nick = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Save the client infos */
  client_entry = silc_calloc(1, sizeof(*client_entry));
  client_entry->id = id;
  client_entry->valid = TRUE;
  silc_parse_userfqdn(nickname, &nick, &client_entry->server);
  silc_parse_userfqdn(username, &client_entry->username,
		      &client_entry->hostname);
  if (userinfo)
    client_entry->realname = strdup(userinfo);
  client_entry->mode = mode;
  if (nick)
    client_entry->nickname = strdup(nick);
  client_entry->channels = silc_hash_table_alloc(1, silc_hash_ptr, NULL, NULL,
						 NULL, NULL, NULL, TRUE);

  /* Format the nickname */
  silc_client_nickname_format(client, conn, client_entry);

  /* Add client to cache, the non-formatted nickname is saved to cache */
  if (!silc_idcache_add(conn->internal->client_cache, nick, client_entry->id,
			(void *)client_entry, 0, NULL)) {
    silc_free(client_entry->nickname);
    silc_free(client_entry->username);
    silc_free(client_entry->hostname);
    silc_free(client_entry->server);
    silc_hash_table_free(client_entry->channels);
    silc_free(client_entry);
    return NULL;
  }

  return client_entry;
}

/* Updates the `client_entry' with the new information sent as argument. */

void silc_client_update_client(SilcClient client,
			       SilcClientConnection conn,
			       SilcClientEntry client_entry,
			       const char *nickname,
			       const char *username,
			       const char *userinfo,
			       SilcUInt32 mode)
{
  char *nick = NULL;

  SILC_LOG_DEBUG(("Start"));

  if ((!client_entry->username || !client_entry->hostname) && username) {
    silc_free(client_entry->username);
    silc_free(client_entry->hostname);
    client_entry->username = NULL;
    client_entry->hostname = NULL;
    silc_parse_userfqdn(username, &client_entry->username,
			&client_entry->hostname);
  }
  if (!client_entry->realname && userinfo)
    client_entry->realname = strdup(userinfo);
  if (!client_entry->nickname && nickname) {
    silc_parse_userfqdn(nickname, &nick, &client_entry->server);
    client_entry->nickname = strdup(nick);
    silc_client_nickname_format(client, conn, client_entry);
  }
  client_entry->mode = mode;

  if (nick) {
    /* Remove the old cache entry and create a new one */
    silc_idcache_del_by_context(conn->internal->client_cache, client_entry);
    silc_idcache_add(conn->internal->client_cache, nick, client_entry->id,
		     client_entry, 0, NULL);
  }
}

/* Deletes the client entry and frees all memory. */

void silc_client_del_client_entry(SilcClient client,
				  SilcClientConnection conn,
				  SilcClientEntry client_entry)
{
  SILC_LOG_DEBUG(("Start"));

  silc_free(client_entry->nickname);
  silc_free(client_entry->username);
  silc_free(client_entry->realname);
  silc_free(client_entry->hostname);
  silc_free(client_entry->server);
  silc_free(client_entry->id);
  silc_free(client_entry->fingerprint);
  silc_hash_table_free(client_entry->channels);
  if (client_entry->send_key)
    silc_cipher_free(client_entry->send_key);
  if (client_entry->receive_key)
    silc_cipher_free(client_entry->receive_key);
  silc_free(client_entry->key);
  silc_client_ftp_session_free_client(conn, client_entry);
  if (client_entry->ke)
    silc_client_abort_key_agreement(client, conn, client_entry);
  silc_free(client_entry);
}

/* Removes client from the cache by the client entry. */

bool silc_client_del_client(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry client_entry)
{
  bool ret = silc_idcache_del_by_context(conn->internal->client_cache,
					 client_entry);

  if (ret) {
    /* Remove from channels */
    silc_client_remove_from_channels(client, conn, client_entry);

    /* Free the client entry data */
    silc_client_del_client_entry(client, conn, client_entry);
  }

  return ret;
}

/* Add new channel entry to the ID Cache */

SilcChannelEntry silc_client_add_channel(SilcClient client,
					 SilcClientConnection conn,
					 const char *channel_name,
					 SilcUInt32 mode,
					 SilcChannelID *channel_id)
{
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Start"));

  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = strdup(channel_name);
  channel->id = channel_id;
  channel->mode = mode;
  channel->user_list = silc_hash_table_alloc(1, silc_hash_ptr, NULL, NULL,
					     NULL, NULL, NULL, TRUE);

  /* Put it to the ID cache */
  if (!silc_idcache_add(conn->internal->channel_cache, channel->channel_name,
			(void *)channel->id, (void *)channel, 0, NULL)) {
    silc_free(channel->channel_name);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    return NULL;
  }

  return channel;
}

/* Foreach callbcak to free all users from the channel when deleting a
   channel entry. */

static void silc_client_del_channel_foreach(void *key, void *context,
					    void *user_context)
{
  SilcChannelUser chu = (SilcChannelUser)context;

  SILC_LOG_DEBUG(("Start"));

  /* Remove the context from the client's channel hash table as that
     table and channel's user_list hash table share this same context. */
  silc_hash_table_del(chu->client->channels, chu->channel);
  silc_free(chu);
}

/* Removes channel from the cache by the channel entry. */

bool silc_client_del_channel(SilcClient client, SilcClientConnection conn,
			     SilcChannelEntry channel)
{
  bool ret = silc_idcache_del_by_context(conn->internal->channel_cache,
					 channel);

  SILC_LOG_DEBUG(("Start"));

  /* Free all client entrys from the users list. The silc_hash_table_free
     will free all the entries so they are not freed at the foreach
     callback. */
  silc_hash_table_foreach(channel->user_list, silc_client_del_channel_foreach,
			  NULL);
  silc_hash_table_free(channel->user_list);

  silc_free(channel->channel_name);
  silc_free(channel->topic);
  silc_free(channel->id);
  silc_free(channel->key);
  if (channel->channel_key)
    silc_cipher_free(channel->channel_key);
  if (channel->hmac)
    silc_hmac_free(channel->hmac);
  if (channel->old_channel_keys) {
    SilcCipher key;
    silc_dlist_start(channel->old_channel_keys);
    while ((key = silc_dlist_get(channel->old_channel_keys)) != SILC_LIST_END)
      silc_cipher_free(key);
    silc_dlist_uninit(channel->old_channel_keys);
  }
  if (channel->old_hmacs) {
    SilcHmac hmac;
    silc_dlist_start(channel->old_hmacs);
    while ((hmac = silc_dlist_get(channel->old_hmacs)) != SILC_LIST_END)
      silc_hmac_free(hmac);
    silc_dlist_uninit(channel->old_hmacs);
  }
  silc_schedule_task_del_by_context(conn->client->schedule, channel);
  silc_client_del_channel_private_keys(client, conn, channel);
  silc_free(channel);
  return ret;
}

/* Replaces the channel ID of the `channel' to `new_id'. Returns FALSE
   if the ID could not be changed. */

bool silc_client_replace_channel_id(SilcClient client,
				    SilcClientConnection conn,
				    SilcChannelEntry channel,
				    SilcChannelID *new_id)
{
  if (!new_id)
    return FALSE;

  SILC_LOG_DEBUG(("Old Channel ID id(%s)",
		  silc_id_render(channel->id, SILC_ID_CHANNEL)));
  SILC_LOG_DEBUG(("New Channel ID id(%s)",
		  silc_id_render(new_id, SILC_ID_CHANNEL)));

  silc_idcache_del_by_id(conn->internal->channel_cache, channel->id);
  silc_free(channel->id);
  channel->id = new_id;
  return silc_idcache_add(conn->internal->channel_cache,
			  channel->channel_name,
			  (void *)channel->id, (void *)channel, 0, NULL);

}

/* Finds entry for channel by the channel name. Returns the entry or NULL
   if the entry was not found. It is found only if the client is joined
   to the channel. */

SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel)
{
  SilcIDCacheEntry id_cache;
  SilcChannelEntry entry;

  assert(client && conn);
  if (!channel)
    return NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_name_one(conn->internal->channel_cache, channel,
				     &id_cache))
    return NULL;

  entry = (SilcChannelEntry)id_cache->context;

  SILC_LOG_DEBUG(("Found"));

  return entry;
}

/* Finds entry for channel by the channel ID. Returns the entry or NULL
   if the entry was not found. It is found only if the client is joined
   to the channel. */

SilcChannelEntry silc_client_get_channel_by_id(SilcClient client,
					       SilcClientConnection conn,
					       SilcChannelID *channel_id)
{
  SilcIDCacheEntry id_cache;
  SilcChannelEntry entry;

  assert(client && conn);
  if (!channel_id)
    return NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_id_one(conn->internal->channel_cache, channel_id,
				   &id_cache))
    return NULL;

  entry = (SilcChannelEntry)id_cache->context;

  SILC_LOG_DEBUG(("Found"));

  return entry;
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  union {
    SilcChannelID *channel_id;
    char *channel_name;
  } u;
  SilcGetChannelCallback completion;
  void *context;
} *GetChannelInternal;

SILC_CLIENT_CMD_FUNC(get_channel_resolve_callback)
{
  GetChannelInternal i = (GetChannelInternal)context;
  SilcChannelEntry entry;

  SILC_LOG_DEBUG(("Start"));

  /* Get the channel */
  entry = silc_client_get_channel(i->client, i->conn, i->u.channel_name);
  if (entry) {
    i->completion(i->client, i->conn, &entry, 1, i->context);
  } else {
    i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  silc_free(i->u.channel_name);
  silc_free(i);
}

/* Resolves channel entry from the server by the channel name. */

void silc_client_get_channel_resolve(SilcClient client,
				     SilcClientConnection conn,
				     char *channel_name,
				     SilcGetChannelCallback completion,
				     void *context)
{
  GetChannelInternal i = silc_calloc(1, sizeof(*i));

  assert(client && conn && channel_name);

  SILC_LOG_DEBUG(("Start"));

  i->client = client;
  i->conn = conn;
  i->u.channel_name = strdup(channel_name);
  i->completion = completion;
  i->context = context;

  /* Register our own command reply for this command */
  silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
			       silc_client_command_reply_identify_i, 0,
			       ++conn->cmd_ident);

  /* Send the command */
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
			   conn->cmd_ident,
			   1, 3, channel_name, strlen(channel_name));

  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident,
			      silc_client_command_get_channel_resolve_callback,
			      (void *)i);
}

SILC_CLIENT_CMD_FUNC(get_channel_by_id_callback)
{
  GetChannelInternal i = (GetChannelInternal)context;
  SilcChannelEntry entry;

  SILC_LOG_DEBUG(("Start"));

  /* Get the channel */
  entry = silc_client_get_channel_by_id(i->client, i->conn, i->u.channel_id);
  if (entry) {
    i->completion(i->client, i->conn, &entry, 1, i->context);
  } else {
    i->completion(i->client, i->conn, NULL, 0, i->context);
  }

  silc_free(i->u.channel_id);
  silc_free(i);
}

/* Resolves channel information from the server by the channel ID. */

void silc_client_get_channel_by_id_resolve(SilcClient client,
					   SilcClientConnection conn,
					   SilcChannelID *channel_id,
					   SilcGetChannelCallback completion,
					   void *context)
{
  SilcBuffer idp;
  GetChannelInternal i = silc_calloc(1, sizeof(*i));

  assert(client && conn && channel_id);

  SILC_LOG_DEBUG(("Start"));

  i->client = client;
  i->conn = conn;
  i->u.channel_id = silc_id_dup(channel_id, SILC_ID_CHANNEL);
  i->completion = completion;
  i->context = context;

  /* Register our own command reply for this command */
  silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
			       silc_client_command_reply_identify_i, 0,
			       ++conn->cmd_ident);

  /* Send the command */
  idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
			   conn->cmd_ident,
			   1, 5, idp->data, idp->len);
  silc_buffer_free(idp);

  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident,
			      silc_client_command_get_channel_by_id_callback,
			      (void *)i);
}

/* Finds entry for server by the server name. */

SilcServerEntry silc_client_get_server(SilcClient client,
				       SilcClientConnection conn,
				       char *server_name)
{
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;

  assert(client && conn);
  if (!server_name)
    return NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_name_one(conn->internal->server_cache,
				     server_name, &id_cache))
    return NULL;

  entry = (SilcServerEntry)id_cache->context;

  return entry;
}

/* Finds entry for server by the server ID. */

SilcServerEntry silc_client_get_server_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcServerID *server_id)
{
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;

  assert(client && conn);
  if (!server_id)
    return NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_id_one(conn->internal->server_cache,
				   (void *)server_id, &id_cache))
    return NULL;

  entry = (SilcServerEntry)id_cache->context;

  return entry;
}

/* Add new server entry */

SilcServerEntry silc_client_add_server(SilcClient client,
				       SilcClientConnection conn,
				       const char *server_name,
				       const char *server_info,
				       SilcServerID *server_id)
{
  SilcServerEntry server_entry;

  SILC_LOG_DEBUG(("Start"));

  server_entry = silc_calloc(1, sizeof(*server_entry));
  if (!server_entry || !server_id)
    return NULL;

  server_entry->server_id = server_id;
  if (server_name)
    server_entry->server_name = strdup(server_name);
  if (server_info)
    server_entry->server_info = strdup(server_info);

  /* Add server to cache */
  if (!silc_idcache_add(conn->internal->server_cache,
			server_entry->server_name,
			server_entry->server_id, server_entry, 0, NULL)) {
    silc_free(server_entry->server_id);
    silc_free(server_entry->server_name);
    silc_free(server_entry->server_info);
    silc_free(server_entry);
    return NULL;
  }

  return server_entry;
}

/* Removes server from the cache by the server entry. */

bool silc_client_del_server(SilcClient client, SilcClientConnection conn,
			    SilcServerEntry server)
{
  bool ret = silc_idcache_del_by_context(conn->internal->server_cache, server);
  silc_free(server->server_name);
  silc_free(server->server_info);
  silc_free(server->server_id);
  silc_free(server);
  return ret;
}

/* Updates the `server_entry' with the new information sent as argument. */

void silc_client_update_server(SilcClient client,
			       SilcClientConnection conn,
			       SilcServerEntry server_entry,
			       const char *server_name,
			       const char *server_info)
{
  SILC_LOG_DEBUG(("Start"));

  if (server_name && (!server_entry->server_name ||
		      strcmp(server_entry->server_name, server_name))) {

    silc_idcache_del_by_context(conn->internal->server_cache, server_entry);
    silc_free(server_entry->server_name);
    server_entry->server_name = strdup(server_name);
    silc_idcache_add(conn->internal->server_cache, server_entry->server_name,
		     server_entry->server_id,
		     server_entry, 0, NULL);
  }

  if (server_info && (!server_entry->server_info ||
		      strcmp(server_entry->server_info, server_info))) {
    silc_free(server_entry->server_info);
    server_entry->server_info = strdup(server_info);
  }
}

/* Formats the nickname of the client specified by the `client_entry'.
   If the format is specified by the application this will format the
   nickname and replace the old nickname in the client entry. If the
   format string is not specified then this function has no effect. */

void silc_client_nickname_format(SilcClient client,
				 SilcClientConnection conn,
				 SilcClientEntry client_entry)
{
  char *cp;
  char *newnick = NULL;
  int i, off = 0, len;
  bool freebase;
  SilcClientEntry *clients;
  SilcUInt32 clients_count = 0;
  SilcClientEntry unformatted = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!client->internal->params->nickname_format[0])
    return;

  if (!client_entry->nickname)
    return;

  /* Get all clients with same nickname. Do not perform the formatting
     if there aren't any clients with same nickname unless the application
     is forcing us to do so. */
  clients = silc_client_get_clients_local(client, conn,
					  client_entry->nickname, NULL,
					  &clients_count);
  if (!clients && !client->internal->params->nickname_force_format)
    return;

  len = 0;
  freebase = TRUE;
  for (i = 0; i < clients_count; i++) {
    if (clients[i]->valid && clients[i] != client_entry)
      len++;
    if (clients[i]->valid && clients[i] != client_entry &&
	!strcasecmp(clients[i]->nickname, client_entry->nickname))
      freebase = FALSE;
  }
  if (!len || freebase)
    return;

  if (clients_count == 1)
    unformatted = clients[0];
  else
    for (i = 0; i < clients_count; i++)
      if (!strncasecmp(clients[i]->nickname, client_entry->nickname,
		       strlen(clients[i]->nickname)))
	unformatted = clients[i];

  /* If we are changing nickname of our local entry we'll enforce
     that we will always get the unformatted nickname.  Give our
     format number to the one that is not formatted now. */
  if (unformatted && client_entry == conn->local_entry)
    client_entry = unformatted;

  cp = client->internal->params->nickname_format;
  while (*cp) {
    if (*cp == '%') {
      cp++;
      continue;
    }

    switch(*cp) {
    case 'n':
      /* Nickname */
      if (!client_entry->nickname)
	break;
      len = strlen(client_entry->nickname);
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
      memcpy(&newnick[off], client_entry->nickname, len);
      off += len;
      break;
    case 'h':
      /* Stripped hostname */
      if (!client_entry->hostname)
	break;
      len = strcspn(client_entry->hostname, ".");
      i = strcspn(client_entry->hostname, "-");
      if (i < len)
        len = i;
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
      memcpy(&newnick[off], client_entry->hostname, len);
      off += len;
      break;
    case 'H':
      /* Full hostname */
      if (!client_entry->hostname)
	break;
      len = strlen(client_entry->hostname);
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
      memcpy(&newnick[off], client_entry->hostname, len);
      off += len;
      break;
    case 's':
      /* Stripped server name */
      if (!client_entry->server)
	break;
      len = strcspn(client_entry->server, ".");
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
      memcpy(&newnick[off], client_entry->server, len);
      off += len;
      break;
    case 'S':
      /* Full server name */
      if (!client_entry->server)
	break;
      len = strlen(client_entry->server);
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
      memcpy(&newnick[off], client_entry->server, len);
      off += len;
      break;
    case 'a':
      /* Ascending number */
      {
	char tmp[6];
	int num, max = 1;

	if (clients_count == 1)
	  break;

	for (i = 0; i < clients_count; i++) {
	  if (strncasecmp(clients[i]->nickname, newnick, off))
	    continue;
	  if (strlen(clients[i]->nickname) <= off)
	    continue;
	  num = atoi(&clients[i]->nickname[off]);
	  if (num > max)
	    max = num;
	}

	memset(tmp, 0, sizeof(tmp));
	snprintf(tmp, sizeof(tmp) - 1, "%d", ++max);
	len = strlen(tmp);
	newnick = silc_realloc(newnick, sizeof(*newnick) * (off + len));
	memcpy(&newnick[off], tmp, len);
	off += len;
      }
      break;
    default:
      /* Some other character in the string */
      newnick = silc_realloc(newnick, sizeof(*newnick) * (off + 1));
      memcpy(&newnick[off], cp, 1);
      off++;
      break;
    }

    cp++;
  }

  newnick = silc_realloc(newnick, sizeof(*newnick) * (off + 1));
  newnick[off] = 0;

  silc_free(client_entry->nickname);
  client_entry->nickname = newnick;
  silc_free(clients);
}
