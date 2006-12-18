/*

  client_entry.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************ Client Searching Locally **************************/

/* Finds entry for client by the client's ID. Returns the entry or NULL
   if the entry was not found. */

SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id)
{
  SilcIDCacheEntry id_cache;
  SilcClientEntry client_entry;

  if (!client || !conn || !client_id)
    return NULL;

  SILC_LOG_DEBUG(("Finding client by ID (%s)",
		  silc_id_render(client_id, SILC_ID_CLIENT)));

  silc_mutex_lock(conn->internal->lock);

  /* Find ID from cache */
  if (!silc_idcache_find_by_id_one(conn->internal->client_cache, client_id,
				   &id_cache)) {
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  client_entry = id_cache->context;

  /* Reference */
  silc_client_ref_client(client, conn, client_entry);
  silc_mutex_unlock(conn->internal->lock);

  SILC_LOG_DEBUG(("Found"));

  return client_entry;
}

/* Finds clients by nickname from local cache. */

SilcDList silc_client_get_clients_local(SilcClient client,
					SilcClientConnection conn,
					const char *nickname,
					const char *format)
{
  SilcIDCacheEntry id_cache;
  SilcList list;
  SilcDList clients;
  SilcClientEntry entry;
  char *nicknamec;

  if (!client || !conn || !nickname)
    return NULL;

  SILC_LOG_DEBUG(("Find clients by nickname %s", nickname));

  /* Normalize nickname for search */
  nicknamec = silc_identifier_check(nickname, strlen(nickname),
				    SILC_STRING_UTF8, 128, NULL);
  if (!nicknamec)
    return NULL;

  clients = silc_dlist_init();
  if (!clients) {
    silc_free(nicknamec);
    return NULL;
  }

  silc_mutex_lock(conn->internal->lock);

  /* Find from cache */
  silc_list_init(list, struct SilcIDCacheEntryStruct, next);
  if (!silc_idcache_find_by_name(conn->internal->client_cache, nicknamec,
				 &list)) {
    silc_mutex_unlock(conn->internal->lock);
    silc_free(nicknamec);
    silc_dlist_uninit(clients);
    return NULL;
  }

  if (!format) {
    /* Take all without any further checking */
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      silc_client_ref_client(client, conn, id_cache->context);
      silc_dlist_add(clients, id_cache->context);
    }
  } else {
    /* Check multiple cache entries for exact match */
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      entry = id_cache->context;
      if (silc_utf8_strcasecmp(entry->nickname, format)) {
	silc_client_ref_client(client, conn, entry);
	silc_dlist_add(clients, entry);
      }
    }
  }

  silc_mutex_unlock(conn->internal->lock);

  silc_dlist_start(clients);

  silc_free(nicknamec);
  return clients;
}

/********************** Client Resolving from Server ************************/

/* Resolving context */
typedef struct {
  SilcDList clients;
  SilcGetClientCallback completion;
  void *context;
} *SilcClientGetClientInternal;

/* Resolving command callback */

static SilcBool silc_client_get_clients_cb(SilcClient client,
					   SilcClientConnection conn,
					   SilcCommand command,
					   SilcStatus status,
					   SilcStatus error,
					   void *context,
					   va_list ap)
{
  SilcClientGetClientInternal i = context;
  SilcClientEntry client_entry;

  if (error != SILC_STATUS_OK) {
    SILC_LOG_DEBUG(("Resolving failed: %s", silc_get_status_message(error)));
    if (i->completion)
      i->completion(client, conn, error, NULL, i->context);
    goto out;
  }

  /* Add the returned client to list */
  if (i->completion) {
    client_entry = va_arg(ap, SilcClientEntry);
    silc_client_ref_client(client, conn, client_entry);
    silc_dlist_add(i->clients, client_entry);
    client_entry->internal.resolve_cmd_ident = 0;
  }

  if (status == SILC_STATUS_OK || status == SILC_STATUS_LIST_END) {
    /* Deliver the clients to the caller */
    if (i->completion) {
      SILC_LOG_DEBUG(("Resolved %d clients", silc_dlist_count(i->clients)));
      silc_dlist_start(i->clients);
      i->completion(client, conn, SILC_STATUS_OK, i->clients, i->context);
    }
    goto out;
  }

  return TRUE;

 out:
  silc_client_list_free(client, conn, i->clients);
  silc_free(i);
  return FALSE;
}

/* Resolves client information from server by the client ID. */

SilcUInt16
silc_client_get_client_by_id_resolve(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientID *client_id,
				     SilcBuffer attributes,
				     SilcGetClientCallback completion,
				     void *context)
{
  SilcClientGetClientInternal i;
  SilcClientEntry client_entry;
  SilcBuffer idp;
  SilcUInt16 cmd_ident;

  if (!client || !conn | !client_id)
    return 0;

  SILC_LOG_DEBUG(("Resolve client by ID (%s)",
		  silc_id_render(client_id, SILC_ID_CLIENT)));

  i = silc_calloc(1, sizeof(*i));
  if (!i)
    return 0;
  i->completion = completion;
  i->context = context;
  i->clients = silc_dlist_init();
  if (!i->clients) {
    silc_free(i);
    return 0;
  }

  /* Attach to resolving, if on going */
  client_entry = silc_client_get_client_by_id(client, conn, client_id);
  if (client_entry && client_entry->internal.resolve_cmd_ident) {
    SILC_LOG_DEBUG(("Attach to existing resolving"));
    silc_client_unref_client(client, conn, client_entry);
    silc_client_command_pending(conn, SILC_COMMAND_NONE,
				client_entry->internal.resolve_cmd_ident,
				silc_client_get_clients_cb, i);
    return client_entry->internal.resolve_cmd_ident;
  }

  /* Send the command */
  idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  cmd_ident = silc_client_command_send(client, conn, SILC_COMMAND_WHOIS,
				       silc_client_get_clients_cb, i,
				       2, 3, silc_buffer_datalen(attributes),
				       4, silc_buffer_datalen(idp));
  if (!cmd_ident && completion)
    completion(client, conn, SILC_STATUS_ERR_RESOURCE_LIMIT, NULL, context);

  if (client_entry && cmd_ident)
    client_entry->internal.resolve_cmd_ident = cmd_ident;

  silc_client_unref_client(client, conn, client_entry);
  silc_buffer_free(idp);

  return cmd_ident;
}

/* Finds client entry or entries by the `nickname' and `server'. The
   completion callback will be called when the client entries has been
   found.  Used internally by the library. */

static SilcUInt16 silc_client_get_clients_i(SilcClient client,
					    SilcClientConnection conn,
					    SilcCommand command,
					    const char *nickname,
					    const char *server,
					    SilcBuffer attributes,
					    SilcGetClientCallback completion,
					    void *context)
{
  SilcClientGetClientInternal i;
  char userhost[768 + 1];
  int len;

  SILC_LOG_DEBUG(("Resolve client by %s command",
		  silc_get_command_name(command)));

  if (!client || !conn)
    return 0;
  if (!nickname && !attributes)
    return 0;

  i = silc_calloc(1, sizeof(*i));
  if (!i)
    return 0;
  i->clients = silc_dlist_init();
  if (!i->clients) {
    silc_free(i);
    return 0;
  }
  i->completion = completion;
  i->context = context;

  memset(userhost, 0, sizeof(userhost));
  if (nickname && server) {
    len = strlen(nickname) + strlen(server) + 3;
    silc_strncat(userhost, len, nickname, strlen(nickname));
    silc_strncat(userhost, len, "@", 1);
    silc_strncat(userhost, len, server, strlen(server));
  } else if (nickname) {
    silc_strncat(userhost, sizeof(userhost) - 1, nickname, strlen(nickname));
  }

  /* Send the command */
  if (command == SILC_COMMAND_IDENTIFY)
    return silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
				    silc_client_get_clients_cb, i,
				    1, 1, userhost, strlen(userhost));
  return silc_client_command_send(client, conn, SILC_COMMAND_WHOIS,
				  silc_client_get_clients_cb, i,
				  2, 1, userhost, strlen(userhost),
				  3, silc_buffer_datalen(attributes));
}

/* Get clients from server with IDENTIFY command */

SilcUInt16 silc_client_get_clients(SilcClient client,
				   SilcClientConnection conn,
				   const char *nickname,
				   const char *server,
				   SilcGetClientCallback completion,
				   void *context)
{
  return silc_client_get_clients_i(client, conn, SILC_COMMAND_IDENTIFY,
				   nickname, server, NULL,
				   completion, context);
}

/* Get clients from server with WHOIS command */

SilcUInt16 silc_client_get_clients_whois(SilcClient client,
					 SilcClientConnection conn,
					 const char *nickname,
					 const char *server,
					 SilcBuffer attributes,
					 SilcGetClientCallback completion,
					 void *context)
{
  return silc_client_get_clients_i(client, conn, SILC_COMMAND_WHOIS,
				   nickname, server, attributes,
				   completion, context);
}

/* ID list resolving context */
typedef struct {
  SilcGetClientCallback completion;
  void *context;
  SilcBuffer client_id_list;
  SilcUInt32 list_count;
} *GetClientsByListInternal;

static SilcBool silc_client_get_clients_list_cb(SilcClient client,
						SilcClientConnection conn,
						SilcCommand command,
						SilcStatus status,
						SilcStatus error,
						void *context,
						va_list ap)
{
  GetClientsByListInternal i = context;
  SilcClientEntry client_entry;
  SilcDList clients;
  SilcUInt16 idp_len;
  SilcID id;
  int c;

  /* Process the list after all replies have been received */
  if (status != SILC_STATUS_OK && !SILC_STATUS_IS_ERROR(status) &&
      status != SILC_STATUS_LIST_END)
    return TRUE;

  SILC_LOG_DEBUG(("Resolved all clients"));

  clients = silc_dlist_init();
  if (!clients) {
    status = SILC_STATUS_ERR_RESOURCE_LIMIT;
    goto out;
  }

  for (c = 0; c < i->list_count; c++) {
    /* Get Client ID */
    SILC_GET16_MSB(idp_len, i->client_id_list->data + 2);
    idp_len += 4;
    if (!silc_id_payload_parse_id(i->client_id_list->data, idp_len, &id)) {
      status = SILC_STATUS_ERR_BAD_CLIENT_ID;
      goto out;
    }

    /* Get client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (client_entry)
      silc_dlist_add(clients, client_entry);

    if (!silc_buffer_pull(i->client_id_list, idp_len)) {
      status = SILC_STATUS_ERR_BAD_CLIENT_ID;
      goto out;
    }
  }

  silc_dlist_start(clients);
  status = SILC_STATUS_OK;
  if (i->completion)
    i->completion(client, conn, status, clients, i->context);

 out:
  if (status != SILC_STATUS_OK && i->completion)
    i->completion(client, conn, status, NULL, i->context);

  silc_client_list_free(client, conn, clients);
  silc_buffer_free(i->client_id_list);
  silc_free(i);

  return FALSE;
}

/* Gets client entries by the list of client ID's `client_id_list'. This
   always resolves those client ID's it does not know yet from the server
   so this function might take a while. The `client_id_list' is a list
   of ID Payloads added one after other.  JOIN command reply and USERS
   command reply for example returns this sort of list. The `completion'
   will be called after the entries are available. */

SilcUInt16 silc_client_get_clients_by_list(SilcClient client,
					   SilcClientConnection conn,
					   SilcUInt32 list_count,
					   SilcBuffer client_id_list,
					   SilcGetClientCallback completion,
					   void *context)
{
  GetClientsByListInternal in;
  SilcClientEntry entry;
  unsigned char **res_argv = NULL;
  SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;
  SilcUInt16 idp_len, cmd_ident;
  SilcID id;
  int i;

  SILC_LOG_DEBUG(("Resolve clients from Client ID list"));

  if (!client || !conn || !client_id_list)
    return 0;

  in = silc_calloc(1, sizeof(*in));
  if (!in)
    return 0;
  in->completion = completion;
  in->context = context;
  in->list_count = list_count;
  in->client_id_list = silc_buffer_copy(client_id_list);
  if (!in->client_id_list)
    goto err;

  for (i = 0; i < list_count; i++) {
    /* Get Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    if (!silc_id_payload_parse_id(client_id_list->data, idp_len, &id))
      goto err;

    /* Check if we have this client cached already.  If we don't have the
       entry or it has incomplete info, then resolve it from the server. */
    entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!entry || !entry->nickname[0] || !entry->username[0] ||
	!entry->realname) {
      if (!res_argv) {
	res_argv = silc_calloc(list_count, sizeof(*res_argv));
	res_argv_lens = silc_calloc(list_count, sizeof(*res_argv_lens));
	res_argv_types = silc_calloc(list_count, sizeof(*res_argv_types));
	if (!res_argv || !res_argv_lens || !res_argv_types) {
	  silc_client_unref_client(client, conn, entry);
	  goto err;
	}
      }

      res_argv[res_argc] = client_id_list->data;
      res_argv_lens[res_argc] = idp_len;
      res_argv_types[res_argc] = res_argc + 4;
      res_argc++;
    }
    silc_client_unref_client(client, conn, entry);

    if (!silc_buffer_pull(client_id_list, idp_len))
      goto err;
  }
  silc_buffer_start(client_id_list);

  /* Query the unknown client information from server */
  if (res_argc) {
    cmd_ident = silc_client_command_send_argv(client,
					      conn, SILC_COMMAND_WHOIS,
					      silc_client_get_clients_list_cb,
					      in, res_argc, res_argv,
					      res_argv_lens,
					      res_argv_types);
    silc_free(res_argv);
    silc_free(res_argv_lens);
    silc_free(res_argv_types);
    return cmd_ident;
  }

  /* We have the clients in cache, get them and call the completion */
  silc_client_get_clients_list_cb(client, conn, SILC_COMMAND_WHOIS,
				  SILC_STATUS_OK, SILC_STATUS_OK, in, NULL);
  return 0;

 err:
  silc_buffer_free(in->client_id_list);
  silc_free(in);
  silc_free(res_argv);
  silc_free(res_argv_lens);
  silc_free(res_argv_types);
  return 0;
}

#if 0
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
  SilcBool found = FALSE;
  SilcChannelEntry channel;
  SilcHashTableList htl;
  SilcChannelUser chu;

  if (i->res_count) {
    i->res_count--;
    if (i->res_count)
      return;
  }

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
  SilcBool wait_res = FALSE;

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
    if (!entry->nickname[0] || !entry->realname) {
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
#endif /* 0 */


/************************** Client Entry Routines ***************************/

/* Creates new client entry and adds it to the ID cache. Returns pointer
   to the new entry. */

SilcClientEntry silc_client_add_client(SilcClient client,
				       SilcClientConnection conn,
				       char *nickname, char *username,
				       char *userinfo, SilcClientID *id,
				       SilcUInt32 mode)
{
  SilcClientEntry client_entry;
  char *nick = NULL;

  SILC_LOG_DEBUG(("Adding new client entry"));

  /* Save the client infos */
  client_entry = silc_calloc(1, sizeof(*client_entry));
  if (!client_entry)
    return NULL;

  silc_atomic_init8(&client_entry->internal.refcnt, 0);
  client_entry->id = *id;
  client_entry->internal.valid = TRUE;
  client_entry->mode = mode;
  client_entry->realname = userinfo ? strdup(userinfo) : NULL;
  silc_parse_userfqdn(nickname, client_entry->nickname,
		      sizeof(client_entry->nickname),
		      client_entry->server,
		      sizeof(client_entry->server));
  silc_parse_userfqdn(username, client_entry->username,
		      sizeof(client_entry->username),
		      client_entry->hostname,
		      sizeof(client_entry->hostname));
  client_entry->channels = silc_hash_table_alloc(1, silc_hash_ptr, NULL, NULL,
						 NULL, NULL, NULL, TRUE);
  if (!client_entry->channels) {
    silc_free(client_entry->realname);
    silc_free(client_entry);
    return NULL;
  }

  /* Normalize nickname */
  if (client_entry->nickname[0]) {
    nick = silc_identifier_check(client_entry->nickname,
				 strlen(client_entry->nickname),
				 SILC_STRING_UTF8, 128, NULL);
    if (!nick) {
      silc_free(client_entry->realname);
      silc_hash_table_free(client_entry->channels);
      silc_free(client_entry);
      return NULL;
    }
  }

  /* Format the nickname */
  silc_client_nickname_format(client, conn, client_entry);

  silc_mutex_lock(conn->internal->lock);

  /* Add client to cache, the normalized nickname is saved to cache */
  if (!silc_idcache_add(conn->internal->client_cache, nick,
			&client_entry->id, client_entry)) {
    silc_free(nick);
    silc_free(client_entry->realname);
    silc_hash_table_free(client_entry->channels);
    silc_free(client_entry);
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  client_entry->nickname_normalized = nick;

  silc_mutex_unlock(conn->internal->lock);
  silc_client_ref_client(client, conn, client_entry);

  SILC_LOG_DEBUG(("Added %p", client_entry));

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

  SILC_LOG_DEBUG(("Update client entry"));

  if (!client_entry->realname && userinfo)
    client_entry->realname = strdup(userinfo);
  if ((!client_entry->username[0] || !client_entry->hostname[0]) && username)
    silc_parse_userfqdn(username, client_entry->username,
			sizeof(client_entry->username),
			client_entry->hostname,
			sizeof(client_entry->username));
  if (!client_entry->nickname[0] && nickname) {
    silc_parse_userfqdn(nickname, client_entry->nickname,
			sizeof(client_entry->nickname),
			client_entry->server,
			sizeof(client_entry->server));

    /* Normalize nickname */
    nick = silc_identifier_check(client_entry->nickname,
				 strlen(client_entry->nickname),
				 SILC_STRING_UTF8, 128, NULL);
    if (!nick)
      return;

    /* Format nickname */
    silc_client_nickname_format(client, conn, client_entry);

    /* Update cache entry */
    silc_mutex_lock(conn->internal->lock);
    silc_idcache_update_by_context(conn->internal->client_cache,
				   client_entry, NULL, nick, TRUE);
    silc_mutex_unlock(conn->internal->lock);
    client_entry->nickname_normalized = nick;
  }
  client_entry->mode = mode;
}

/* Change a client's nickname */

SilcBool silc_client_change_nickname(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry,
				     const char *new_nick,
				     SilcClientID *new_id,
				     const unsigned char *idp,
				     SilcUInt32 idp_len)
{
  char *tmp;

  SILC_LOG_DEBUG(("Change nickname %s to %s", client_entry->nickname,
		  new_nick));

  /* Normalize nickname */
  tmp = silc_identifier_check(new_nick, strlen(new_nick),
			      SILC_STRING_UTF8, 128, NULL);
  if (!tmp)
    return FALSE;

  /* Update the client entry */
  silc_mutex_lock(conn->internal->lock);
  if (!silc_idcache_update_by_context(conn->internal->client_cache,
				      client_entry, new_id, tmp, TRUE)) {
    silc_free(tmp);
    silc_mutex_unlock(conn->internal->lock);
    return FALSE;
  }
  silc_mutex_unlock(conn->internal->lock);

  memset(client_entry->nickname, 0, sizeof(client_entry->nickname));
  memcpy(client_entry->nickname, new_nick, strlen(new_nick));
  client_entry->nickname_normalized = tmp;
  silc_client_nickname_format(client, conn, client_entry);

  /* For my client entry, update ID and set new ID to packet stream */
  if (client_entry == conn->local_entry) {
    if (idp && idp_len) {
      silc_buffer_enlarge(conn->internal->local_idp, idp_len);
      silc_buffer_put(conn->internal->local_idp, idp, idp_len);
    }
    if (new_id)
      silc_packet_set_ids(conn->stream, SILC_ID_CLIENT, conn->local_id,
			  0, NULL);
  }

  return TRUE;
}

/* Deletes the client entry and frees all memory. */

void silc_client_del_client_entry(SilcClient client,
				  SilcClientConnection conn,
				  SilcClientEntry client_entry)
{
  silc_free(client_entry->realname);
  silc_free(client_entry->nickname_normalized);
  silc_free(client_entry->internal.key);
  if (client_entry->public_key)
    silc_pkcs_public_key_free(client_entry->public_key);
  silc_hash_table_free(client_entry->channels);
  if (client_entry->internal.send_key)
    silc_cipher_free(client_entry->internal.send_key);
  if (client_entry->internal.receive_key)
    silc_cipher_free(client_entry->internal.receive_key);
  if (client_entry->internal.hmac_send)
    silc_hmac_free(client_entry->internal.hmac_send);
  if (client_entry->internal.hmac_receive)
    silc_hmac_free(client_entry->internal.hmac_receive);
#if 0
  silc_client_ftp_session_free_client(conn, client_entry);
  if (client_entry->internal->ke)
    silc_client_abort_key_agreement(client, conn, client_entry);
#endif /* 0 */
  silc_atomic_uninit8(&client_entry->internal.refcnt);
  silc_free(client_entry);
}

/* Removes client from the cache by the client entry. */

SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
				SilcClientEntry client_entry)
{
  SilcBool ret;

  if (!client_entry)
    return FALSE;

  if (silc_atomic_sub_int8(&client_entry->internal.refcnt, 1) > 0)
    return FALSE;

  SILC_LOG_DEBUG(("Deleting client %p", client_entry));

  silc_mutex_lock(conn->internal->lock);
  ret = silc_idcache_del_by_context(conn->internal->client_cache,
				    client_entry, NULL);
  silc_mutex_unlock(conn->internal->lock);

  if (ret) {
    /* Remove from channels */
    silc_client_remove_from_channels(client, conn, client_entry);

    /* Free the client entry data */
    silc_client_del_client_entry(client, conn, client_entry);
  }

  return ret;
}

/* Take reference of client entry */

void silc_client_ref_client(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry client_entry)
{
  silc_atomic_add_int8(&client_entry->internal.refcnt, 1);
  SILC_LOG_DEBUG(("Client %p refcnt %d->%d", client_entry,
		  silc_atomic_get_int8(&client_entry->internal.refcnt) - 1,
		  silc_atomic_get_int8(&client_entry->internal.refcnt)));
}

/* Release reference of client entry */

void silc_client_unref_client(SilcClient client, SilcClientConnection conn,
			      SilcClientEntry client_entry)
{
  if (client_entry) {
    SILC_LOG_DEBUG(("Client %p refcnt %d->%d", client_entry,
		    silc_atomic_get_int8(&client_entry->internal.refcnt),
		    silc_atomic_get_int8(&client_entry->internal.refcnt) - 1));
    silc_client_del_client(client, conn, client_entry);
  }
}

/* Free client entry list */

void silc_client_list_free(SilcClient client, SilcClientConnection conn,
			   SilcDList client_list)
{
  SilcClientEntry client_entry;

  if (client_list) {
    silc_dlist_start(client_list);
    while ((client_entry = silc_dlist_get(client_list)))
      silc_client_unref_client(client, conn, client_entry);

    silc_dlist_uninit(client_list);
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
  char newnick[128 + 1];
  int i, off = 0, len;
  SilcBool freebase;
  SilcDList clients;
  SilcClientEntry entry, unformatted = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!client->internal->params->nickname_format[0])
    return;

  if (!client_entry->nickname[0])
    return;

  /* Get all clients with same nickname. Do not perform the formatting
     if there aren't any clients with same nickname unless the application
     is forcing us to do so. */
  clients = silc_client_get_clients_local(client, conn,
					  client_entry->nickname, NULL);
  if (!clients && !client->internal->params->nickname_force_format)
    return;

  if (clients) {
    len = 0;
    freebase = TRUE;
    while ((entry = silc_dlist_get(clients))) {
      if (entry->internal.valid && entry != client_entry)
	len++;
      if (entry->internal.valid && entry != client_entry &&
	  silc_utf8_strcasecmp(entry->nickname, client_entry->nickname)) {
	freebase = FALSE;
	unformatted = entry;
      }
    }
    if (!len || freebase) {
      silc_client_list_free(client, conn, clients);
      return;
    }
  }

  /* If we are changing nickname of our local entry we'll enforce
     that we will always get the unformatted nickname.  Give our
     format number to the one that is not formatted now. */
  if (unformatted && client_entry == conn->local_entry)
    client_entry = unformatted;

  memset(newnick, 0, sizeof(newnick));
  cp = client->internal->params->nickname_format;
  while (cp && *cp) {
    if (*cp == '%') {
      cp++;
      continue;
    }

    switch(*cp) {
    case 'n':
      /* Nickname */
      if (!client_entry->nickname[0])
	break;
      len = strlen(client_entry->nickname);
      memcpy(&newnick[off], client_entry->nickname, len);
      off += len;
      break;
    case 'h':
      /* Stripped hostname */
      if (!client_entry->hostname[0])
	break;
      len = strcspn(client_entry->hostname, ".");
      i = strcspn(client_entry->hostname, "-");
      if (i < len)
        len = i;
      memcpy(&newnick[off], client_entry->hostname, len);
      off += len;
      break;
    case 'H':
      /* Full hostname */
      if (!client_entry->hostname[0])
	break;
      len = strlen(client_entry->hostname);
      memcpy(&newnick[off], client_entry->hostname, len);
      off += len;
      break;
    case 's':
      /* Stripped server name */
      if (!client_entry->server)
	break;
      len = strcspn(client_entry->server, ".");
      memcpy(&newnick[off], client_entry->server, len);
      off += len;
      break;
    case 'S':
      /* Full server name */
      if (!client_entry->server)
	break;
      len = strlen(client_entry->server);
      memcpy(&newnick[off], client_entry->server, len);
      off += len;
      break;
    case 'a':
      /* Ascending number */
      {
	char tmp[6];
	int num, max = 1;

	if (clients && silc_dlist_count(clients) == 1)
	  break;

	if (clients) {
	  silc_dlist_start(clients);
	  while ((entry = silc_dlist_get(clients))) {
	    if (!silc_utf8_strncasecmp(entry->nickname, newnick, off))
	      continue;
	    if (strlen(entry->nickname) <= off)
	      continue;
	    num = atoi(&entry->nickname[off]);
	    if (num > max)
	      max = num;
	  }
	}

	memset(tmp, 0, sizeof(tmp));
	snprintf(tmp, sizeof(tmp) - 1, "%d", ++max);
	len = strlen(tmp);
	memcpy(&newnick[off], tmp, len);
	off += len;
      }
      break;
    default:
      /* Some other character in the string */
      memcpy(&newnick[off], cp, 1);
      off++;
      break;
    }

    cp++;
  }

  newnick[off] = 0;
  memcpy(client_entry->nickname, newnick, strlen(newnick));
  silc_client_list_free(client, conn, clients);
}

/************************ Channel Searching Locally *************************/

/* Finds entry for channel by the channel name. Returns the entry or NULL
   if the entry was not found. It is found only if the client is joined
   to the channel. */

SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel)
{
  SilcIDCacheEntry id_cache;
  SilcChannelEntry entry;

  if (!client || !conn || !channel)
    return NULL;

  SILC_LOG_DEBUG(("Find channel %s", channel));

  /* Normalize name for search */
  channel = silc_channel_name_check(channel, strlen(channel), SILC_STRING_UTF8,
				    256, NULL);
  if (!channel)
    return NULL;

  silc_mutex_lock(conn->internal->lock);

  if (!silc_idcache_find_by_name_one(conn->internal->channel_cache, channel,
				     &id_cache)) {
    silc_mutex_unlock(conn->internal->lock);
    silc_free(channel);
    return NULL;
  }

  SILC_LOG_DEBUG(("Found"));

  entry = id_cache->context;

  /* Reference */
  silc_client_ref_channel(client, conn, entry);
  silc_mutex_unlock(conn->internal->lock);

  silc_free(channel);

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

  if (!client || !conn || !channel_id)
    return NULL;

  SILC_LOG_DEBUG(("Find channel by id %s",
		  silc_id_render(channel_id, SILC_ID_CHANNEL)));

  silc_mutex_lock(conn->internal->lock);

  if (!silc_idcache_find_by_id_one(conn->internal->channel_cache, channel_id,
				   &id_cache)) {
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  SILC_LOG_DEBUG(("Found"));

  entry = id_cache->context;

  /* Reference */
  silc_client_ref_channel(client, conn, entry);
  silc_mutex_unlock(conn->internal->lock);

  return entry;
}

/********************** Channel Resolving from Server ***********************/

/* Channel resolving context */
typedef struct {
  SilcDList channels;
  SilcGetChannelCallback completion;
  void *context;
} *SilcClientGetChannelInternal;

/* Resolving command callback */

static SilcBool silc_client_get_channel_cb(SilcClient client,
					   SilcClientConnection conn,
					   SilcCommand command,
					   SilcStatus status,
					   SilcStatus error,
					   void *context,
					   va_list ap)
{
  SilcClientGetChannelInternal i = context;
  SilcChannelEntry entry;

  if (error != SILC_STATUS_OK) {
    SILC_LOG_DEBUG(("Resolving failed: %s", silc_get_status_message(error)));
    if (i->completion)
      i->completion(client, conn, error, NULL, i->context);
    goto out;
  }

  /* Add the returned channel to list */
  if (i->completion) {
    entry = va_arg(ap, SilcChannelEntry);
    silc_client_ref_channel(client, conn, entry);
    silc_dlist_add(i->channels, entry);
  }

  if (status == SILC_STATUS_OK || status == SILC_STATUS_LIST_END) {
    /* Deliver the channels to the caller */
    if (i->completion) {
      SILC_LOG_DEBUG(("Resolved %d channels", silc_dlist_count(i->channels)));
      silc_dlist_start(i->channels);
      i->completion(client, conn, SILC_STATUS_OK, i->channels, i->context);
    }
    goto out;
  }

  return TRUE;

 out:
  silc_client_list_free_channels(client, conn, i->channels);
  silc_free(i);
  return FALSE;
}

/* Resolves channel entry from the server by the channel name. */

void silc_client_get_channel_resolve(SilcClient client,
				     SilcClientConnection conn,
				     char *channel_name,
				     SilcGetChannelCallback completion,
				     void *context)
{
  SilcClientGetChannelInternal i;

  if (!client || !conn || !channel_name || !completion)
    return;

  SILC_LOG_DEBUG(("Resolve channel %s", channel_name));

  i = silc_calloc(1, sizeof(*i));
  if (!i)
    return;
  i->completion = completion;
  i->context = context;
  i->channels = silc_dlist_init();
  if (!i->channels) {
    silc_free(i);
    return;
  }

  /* Send the command */
  if (!silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
				silc_client_get_channel_cb, i, 1,
				3, channel_name, strlen(channel_name))) {
    if (completion)
      completion(client, conn, SILC_STATUS_ERR_RESOURCE_LIMIT, NULL, context);
  }
}

/* Resolves channel information from the server by the channel ID. */

SilcUInt16
silc_client_get_channel_by_id_resolve(SilcClient client,
				      SilcClientConnection conn,
				      SilcChannelID *channel_id,
				      SilcGetChannelCallback completion,
				      void *context)
{
  SilcClientGetChannelInternal i;
  SilcBuffer idp;
  SilcUInt16 cmd_ident;

  if (!client || !conn || !channel_id || !completion)
    return 0;

  SILC_LOG_DEBUG(("Resolve channel by id %s",
		  silc_id_render(channel_id, SILC_ID_CHANNEL)));

  i = silc_calloc(1, sizeof(*i));
  if (!i)
    return 0;
  i->completion = completion;
  i->context = context;
  i->channels = silc_dlist_init();
  if (!i->channels) {
    silc_free(i);
    return 0;
  }

  /* Send the command */
  idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
  cmd_ident = silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
				       silc_client_get_channel_cb, i, 1,
				       5, silc_buffer_datalen(idp));
  silc_buffer_free(idp);
  if (!cmd_ident && completion)
    completion(client, conn, SILC_STATUS_ERR_RESOURCE_LIMIT, NULL, context);

  return cmd_ident;
}

/************************* Channel Entry Routines ***************************/

/* Add new channel entry to the ID Cache */

SilcChannelEntry silc_client_add_channel(SilcClient client,
					 SilcClientConnection conn,
					 const char *channel_name,
					 SilcUInt32 mode,
					 SilcChannelID *channel_id)
{
  SilcChannelEntry channel;
  char *channel_namec;

  SILC_LOG_DEBUG(("Start"));

  channel = silc_calloc(1, sizeof(*channel));
  if (!channel)
    return NULL;

  silc_atomic_init16(&channel->internal.refcnt, 0);
  channel->id = *channel_id;
  channel->mode = mode;

  channel->channel_name = strdup(channel_name);
  if (!channel->channel_name) {
    silc_free(channel);
    return NULL;
  }

  channel->user_list = silc_hash_table_alloc(1, silc_hash_ptr, NULL, NULL,
					     NULL, NULL, NULL, TRUE);
  if (!channel->user_list) {
    silc_free(channel->channel_name);
    silc_free(channel);
    return NULL;
  }

  /* Normalize channel name */
  channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					  SILC_STRING_UTF8, 256, NULL);
  if (!channel_namec) {
    silc_free(channel->channel_name);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    return NULL;
  }

  silc_mutex_lock(conn->internal->lock);

  /* Add channel to cache, the normalized channel name is saved to cache */
  if (!silc_idcache_add(conn->internal->channel_cache, channel_namec,
			&channel->id, channel)) {
    silc_free(channel_namec);
    silc_free(channel->channel_name);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  silc_mutex_unlock(conn->internal->lock);
  silc_client_ref_channel(client, conn, channel);

  SILC_LOG_DEBUG(("Added %p", channel));

  return channel;
}

/* Removes channel from the cache by the channel entry. */

SilcBool silc_client_del_channel(SilcClient client, SilcClientConnection conn,
				 SilcChannelEntry channel)
{
  SilcBool ret;
  SilcCipher key;
  SilcHmac hmac;

  if (!channel)
    return FALSE;

  if (silc_atomic_sub_int16(&channel->internal.refcnt, 1) > 0)
    return FALSE;

  SILC_LOG_DEBUG(("Deleting channel %p", channel));

  silc_mutex_lock(conn->internal->lock);
  ret = silc_idcache_del_by_context(conn->internal->channel_cache,
				    channel, NULL);
  silc_mutex_unlock(conn->internal->lock);

  if (!ret)
    return FALSE;

  silc_client_empty_channel(client, conn, channel);
  silc_hash_table_free(channel->user_list);
  silc_free(channel->channel_name);
  silc_free(channel->topic);
  if (channel->founder_key)
    silc_pkcs_public_key_free(channel->founder_key);
  if (channel->internal.channel_key)
    silc_cipher_free(channel->internal.channel_key);
  if (channel->internal.hmac)
    silc_hmac_free(channel->internal.hmac);
  if (channel->internal.old_channel_keys) {
    silc_dlist_start(channel->internal.old_channel_keys);
    while ((key = silc_dlist_get(channel->internal.old_channel_keys)))
      silc_cipher_free(key);
    silc_dlist_uninit(channel->internal.old_channel_keys);
  }
  if (channel->internal.old_hmacs) {
    silc_dlist_start(channel->internal.old_hmacs);
    while ((hmac = silc_dlist_get(channel->internal.old_hmacs)))
      silc_hmac_free(hmac);
    silc_dlist_uninit(channel->internal.old_hmacs);
  }
  if (channel->channel_pubkeys)
    silc_argument_list_free(channel->channel_pubkeys,
			    SILC_ARGUMENT_PUBLIC_KEY);
  silc_client_del_channel_private_keys(client, conn, channel);
  silc_atomic_uninit16(&channel->internal.refcnt);
  silc_schedule_task_del_by_context(conn->client->schedule, channel);
  silc_free(channel);

  return ret;
}

/* Replaces the channel ID of the `channel' to `new_id'. Returns FALSE
   if the ID could not be changed. */

SilcBool silc_client_replace_channel_id(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					SilcChannelID *new_id)
{
  SilcBool ret = FALSE;

  if (!new_id)
    return FALSE;

  SILC_LOG_DEBUG(("Old Channel ID id(%s)",
		  silc_id_render(&channel->id, SILC_ID_CHANNEL)));
  SILC_LOG_DEBUG(("New Channel ID id(%s)",
		  silc_id_render(new_id, SILC_ID_CHANNEL)));

  /* Update the ID */
  silc_mutex_lock(conn->internal->lock);
  silc_idcache_update_by_context(conn->internal->channel_cache, channel,
				 new_id, NULL, FALSE);
  silc_mutex_unlock(conn->internal->lock);

  return ret;
}

/* Take reference of channel entry */

void silc_client_ref_channel(SilcClient client, SilcClientConnection conn,
			     SilcChannelEntry channel_entry)
{
  silc_atomic_add_int16(&channel_entry->internal.refcnt, 1);
  SILC_LOG_DEBUG(("Channel %p refcnt %d->%d", channel_entry,
		  silc_atomic_get_int16(&channel_entry->internal.refcnt) - 1,
		  silc_atomic_get_int16(&channel_entry->internal.refcnt)));
}

/* Release reference of channel entry */

void silc_client_unref_channel(SilcClient client, SilcClientConnection conn,
			       SilcChannelEntry channel_entry)
{
  if (channel_entry) {
    SILC_LOG_DEBUG(("Channel %p refcnt %d->%d", channel_entry,
		    silc_atomic_get_int16(&channel_entry->internal.refcnt),
		    silc_atomic_get_int16(&channel_entry->internal.refcnt)
		    - 1));
    silc_client_del_channel(client, conn, channel_entry);
  }
}

/* Free channel entry list */

void silc_client_list_free_channels(SilcClient client,
				    SilcClientConnection conn,
				    SilcDList channel_list)
{
  SilcChannelEntry channel_entry;

  if (channel_list) {
    silc_dlist_start(channel_list);
    while ((channel_entry = silc_dlist_get(channel_list)))
      silc_client_unref_channel(client, conn, channel_entry);

    silc_dlist_uninit(channel_list);
  }
}

/************************* Server Searching Locally *************************/

/* Finds entry for server by the server name. */

SilcServerEntry silc_client_get_server(SilcClient client,
				       SilcClientConnection conn,
				       char *server_name)
{
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;

  if (!client || !conn || !server_name)
    return NULL;

  SILC_LOG_DEBUG(("Find server by name %s", server_name));

  /* Normalize server name for search */
  server_name = silc_identifier_check(server_name, strlen(server_name),
				      SILC_STRING_UTF8, 256, NULL);
  if (!server_name)
    return NULL;

  silc_mutex_lock(conn->internal->lock);

  if (!silc_idcache_find_by_name_one(conn->internal->server_cache,
				     server_name, &id_cache)) {
    silc_free(server_name);
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  SILC_LOG_DEBUG(("Found"));

  /* Reference */
  entry = id_cache->context;
  silc_client_ref_server(client, conn, entry);

  silc_mutex_unlock(conn->internal->lock);

  silc_free(server_name);

  return entry;
}

/* Finds entry for server by the server ID. */

SilcServerEntry silc_client_get_server_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcServerID *server_id)
{
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;

  if (!client || !conn || !server_id)
    return NULL;

  SILC_LOG_DEBUG(("Find server by id %s",
		  silc_id_render(server_id, SILC_ID_SERVER)));

  silc_mutex_lock(conn->internal->lock);

  if (!silc_idcache_find_by_id_one(conn->internal->server_cache,
				   server_id, &id_cache)) {
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  SILC_LOG_DEBUG(("Found"));

  /* Reference */
  entry = id_cache->context;
  silc_client_ref_server(client, conn, entry);

  silc_mutex_unlock(conn->internal->lock);

  return entry;
}

/*********************** Server Resolving from Server ***********************/

/* Resolving context */
typedef struct {
  SilcDList servers;
  SilcGetServerCallback completion;
  void *context;
} *SilcClientGetServerInternal;

/* Resolving command callback */

static SilcBool silc_client_get_server_cb(SilcClient client,
					  SilcClientConnection conn,
					  SilcCommand command,
					  SilcStatus status,
					  SilcStatus error,
					  void *context,
					  va_list ap)
{
  SilcClientGetServerInternal i = context;
  SilcServerEntry server;

  if (error != SILC_STATUS_OK) {
    SILC_LOG_DEBUG(("Resolving failed: %s", silc_get_status_message(error)));
    if (i->completion)
      i->completion(client, conn, error, NULL, i->context);
    goto out;
  }

  /* Add the returned servers to list */
  if (i->completion) {
    server = va_arg(ap, SilcServerEntry);
    silc_client_ref_server(client, conn, server);
    silc_dlist_add(i->servers, server);
    server->internal.resolve_cmd_ident = 0;
  }

  if (status == SILC_STATUS_OK || status == SILC_STATUS_LIST_END) {
    /* Deliver the servers to the caller */
    if (i->completion) {
      SILC_LOG_DEBUG(("Resolved %d servers", silc_dlist_count(i->servers)));
      silc_dlist_start(i->servers);
      i->completion(client, conn, SILC_STATUS_OK, i->servers, i->context);
    }
    goto out;
  }

  return TRUE;

 out:
  silc_client_list_free_servers(client, conn, i->servers);
  silc_free(i);
  return FALSE;
}

/* Resolve server by server ID */

SilcUInt16
silc_client_get_server_by_id_resolve(SilcClient client,
				     SilcClientConnection conn,
				     SilcServerID *server_id,
				     SilcGetServerCallback completion,
				     void *context)
{
  SilcClientGetServerInternal i;
  SilcServerEntry server;
  SilcBuffer idp;
  SilcUInt16 cmd_ident;

  if (!client || !conn || !server_id || !completion)
    return 0;

  SILC_LOG_DEBUG(("Resolve server by id %s",
		  silc_id_render(server_id, SILC_ID_SERVER)));

  i = silc_calloc(1, sizeof(*i));
  if (!i)
    return 0;
  i->completion = completion;
  i->context = context;
  i->servers = silc_dlist_init();
  if (!i->servers) {
    silc_free(i);
    return 0;
  }

  /* Attach to resolving, if on going */
  server = silc_client_get_server_by_id(client, conn, server_id);
  if (server && server->internal.resolve_cmd_ident) {
    SILC_LOG_DEBUG(("Attach to existing resolving"));
    silc_client_unref_server(client, conn, server);
    silc_client_command_pending(conn, SILC_COMMAND_NONE,
				server->internal.resolve_cmd_ident,
				silc_client_get_server_cb, i);
    return server->internal.resolve_cmd_ident;
  }

  /* Send the command */
  idp = silc_id_payload_encode(server_id, SILC_ID_SERVER);
  cmd_ident = silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
				       silc_client_get_server_cb, i, 1,
				       5, silc_buffer_datalen(idp));
  silc_buffer_free(idp);
  if (!cmd_ident && completion)
    completion(client, conn, SILC_STATUS_ERR_RESOURCE_LIMIT, NULL, context);

  if (server && cmd_ident)
    server->internal.resolve_cmd_ident = cmd_ident;

  silc_client_unref_server(client, conn, server);

  return cmd_ident;
}

/************************** Server Entry Routines ***************************/

/* Add new server entry */

SilcServerEntry silc_client_add_server(SilcClient client,
				       SilcClientConnection conn,
				       const char *server_name,
				       const char *server_info,
				       SilcServerID *server_id)
{
  SilcServerEntry server_entry;
  char *server_namec = NULL;

  if (!server_id)
    return NULL;

  SILC_LOG_DEBUG(("Adding new server %s", server_name));

  server_entry = silc_calloc(1, sizeof(*server_entry));
  if (!server_entry)
    return NULL;

  silc_atomic_init8(&server_entry->internal.refcnt, 0);
  server_entry->id = *server_id;
  if (server_name)
    server_entry->server_name = strdup(server_name);
  if (server_info)
    server_entry->server_info = strdup(server_info);

  /* Normalize server name */
  if (server_name) {
    server_namec = silc_identifier_check(server_name, strlen(server_name),
					 SILC_STRING_UTF8, 256, NULL);
    if (!server_namec) {
      silc_free(server_entry->server_name);
      silc_free(server_entry->server_info);
      silc_free(server_entry);
      return NULL;
    }
  }

  silc_mutex_lock(conn->internal->lock);

  /* Add server to cache */
  if (!silc_idcache_add(conn->internal->server_cache, server_namec,
			&server_entry->id, server_entry)) {
    silc_free(server_namec);
    silc_free(server_entry->server_name);
    silc_free(server_entry->server_info);
    silc_free(server_entry);
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  silc_mutex_unlock(conn->internal->lock);
  silc_client_ref_server(client, conn, server_entry);

  SILC_LOG_DEBUG(("Added %p", server_entry));

  return server_entry;
}

/* Removes server from the cache by the server entry. */

SilcBool silc_client_del_server(SilcClient client, SilcClientConnection conn,
				SilcServerEntry server)
{
  SilcBool ret;

  if (!server)
    return FALSE;

  if (silc_atomic_sub_int8(&server->internal.refcnt, 1) > 0)
    return FALSE;

  SILC_LOG_DEBUG(("Deleting server %p", server));

  silc_mutex_lock(conn->internal->lock);
  ret = silc_idcache_del_by_context(conn->internal->server_cache,
				    server, NULL);
  silc_mutex_unlock(conn->internal->lock);

  silc_free(server->server_name);
  silc_free(server->server_info);
  if (server->public_key)
    silc_pkcs_public_key_free(server->public_key);
  silc_atomic_uninit8(&server->internal.refcnt);
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
  char *server_namec = NULL;

  SILC_LOG_DEBUG(("Updating server %p", server_entry));

  if (server_name &&
      (!server_entry->server_name ||
       !silc_utf8_strcasecmp(server_entry->server_name, server_name))) {

    server_namec = silc_identifier_check(server_name, strlen(server_name),
					 SILC_STRING_UTF8, 256, NULL);
    if (!server_namec)
      return;

    silc_free(server_entry->server_name);
    server_entry->server_name = strdup(server_name);
    if (!server_entry->server_name)
      return;

    /* Update cache entry */
    silc_mutex_lock(conn->internal->lock);
    silc_idcache_update_by_context(conn->internal->server_cache, server_entry,
				   NULL, server_namec, TRUE);
    silc_mutex_unlock(conn->internal->lock);
  }

  if (server_info &&
      (!server_entry->server_info ||
       !silc_utf8_strcasecmp(server_entry->server_info, server_info))) {
    silc_free(server_entry->server_info);
    server_entry->server_info = strdup(server_info);
  }
}

/* Take reference of server entry */

void silc_client_ref_server(SilcClient client, SilcClientConnection conn,
			    SilcServerEntry server_entry)
{
  silc_atomic_add_int8(&server_entry->internal.refcnt, 1);
  SILC_LOG_DEBUG(("Server %p refcnt %d->%d", server_entry,
		  silc_atomic_get_int8(&server_entry->internal.refcnt) - 1,
		  silc_atomic_get_int8(&server_entry->internal.refcnt)));
}

/* Release reference of server entry */

void silc_client_unref_server(SilcClient client, SilcClientConnection conn,
			      SilcServerEntry server_entry)
{
  if (server_entry) {
    SILC_LOG_DEBUG(("Server %p refcnt %d->%d", server_entry,
		    silc_atomic_get_int8(&server_entry->internal.refcnt),
		    silc_atomic_get_int8(&server_entry->internal.refcnt)
		    - 1));
    silc_client_del_server(client, conn, server_entry);
  }
}

/* Free server entry list */

void silc_client_list_free_servers(SilcClient client,
				   SilcClientConnection conn,
				   SilcDList server_list)
{
  SilcServerEntry server_entry;

  if (server_list) {
    silc_dlist_start(server_list);
    while ((server_entry = silc_dlist_get(server_list)))
      silc_client_unref_server(client, conn, server_entry);

    silc_dlist_uninit(server_list);
  }
}
