/*

  server_st_accept.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/************************ Static utility functions **************************/

/* SKE public key verification callback */

static void
silc_server_accept_verify_key(SilcSKE ske,
			      SilcSKEPKType pk_type,
			      SilcPublicKey public_key,
			      void *context,
			      SilcSKEVerifyCbCompletion completion,
			      void *completion_context)
{
  SilcServerAccept ac = context;

  SILC_LOG_DEBUG(("Verifying public key"));

  if (pk_type != SILC_SKE_PK_TYPE_SILC) {
    SILC_LOG_WARNING(("We don't support %s (%s) port %d public key type %d",
		      ac->hostname, ac->ip, ac->port, pk_type));
    completion(ac->data.ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }

  /* We accept all keys without explicit verification */
  completion(ac->data.ske, SILC_SKE_STATUS_OK, completion_context);
}

/* SKE completion callback */

static void
silc_server_accept_completed(SilcSKE ske, SilcSKEStatus status,
			     SilcSKESecurityProperties prop,
			     SilcSKEKeyMaterial keymat,
			     SilcSKERekeyMaterial rekey,
			     void *context)
{
  SilcServerAccept ac = context;

  ac->status = status;
  ac->prop = prop;
  ac->keymat = keymat;
  ac->rekey = rekey;

  /* Continue synchronously to take keys into use immediately */
  SILC_FSM_CALL_CONTINUE_SYNC(&ac->t);
}

/* Authentication data callback */

static SilcBool
silc_server_accept_get_auth(SilcConnAuth connauth,
			    SilcConnectionType conn_type,
			    unsigned char **passphrase,
			    SilcUInt32 *passphrase_len,
			    SilcSKR *repository,
			    void *context)
{
  SilcServerAccept ac = context;

  SILC_LOG_DEBUG(("Remote connection type %d", conn_type));

  /* Remote end is client */
  if (conn_type == SILC_CONN_CLIENT) {
    if (!ac->cconfig)
      return FALSE;

    *passphrase = ac->cconfig->passphrase;
    *passphrase_len = ac->cconfig->passphrase_len;
    if (ac->cconfig->pubkey_auth)
      *repository = ac->thread->server->repository;
  }

  /* Remote end is server */
  if (conn_type == SILC_CONN_SERVER) {
    if (!ac->sconfig)
      return FALSE;

    *passphrase = ac->sconfig->passphrase;
    *passphrase_len = ac->sconfig->passphrase_len;
    if (ac->sconfig->pubkey_auth)
      *repository = ac->thread->server->repository;
  }

  /* Remote end is router */
  if (conn_type == SILC_CONN_ROUTER) {
    if (!ac->rconfig)
      return FALSE;

    *passphrase = ac->rconfig->passphrase;
    *passphrase_len = ac->rconfig->passphrase_len;
    if (ac->rconfig->pubkey_auth)
      *repository = ac->thread->server->repository;
  }

  ac->data.type = conn_type;

  return TRUE;
}

/* Authentication completion callback */

static void
silc_server_accept_auth_compl(SilcConnAuth connauth, SilcBool success,
			      void *context)
{
  SilcServerAccept ac = context;
  ac->auth_success = success;
  SILC_FSM_CALL_CONTINUE(&ac->t);
}

/* Free context */

static void silc_server_accept_free(SilcServerAccept ac)
{
  if (ac->connauth)
    silc_connauth_free(ac->connauth);
  silc_free(ac->error_string);
  silc_free(ac);
}

void silc_server_accept_connection_dest(SilcFSM fsm, void *fsm_context,
					void *destructor_context)
{
  SilcServerAccept ac = fsm_context;
  silc_server_accept_free(ac);
}


/********************* Accepting new connection thread **********************/

SILC_FSM_STATE(silc_server_st_accept_connection)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;
  SilcServerParamDeny deny;
  SilcSKESecurityPropertyFlag flags = 0;

  SILC_LOG_DEBUG(("Accepting new connection"));

  /* Create packet stream */
  ac->packet_stream = silc_packet_stream_create(ac->thread->packet_engine,
						silc_fsm_get_schedule(fsm),
						ac->stream);
  if (!ac->packet_stream) {
    /** Cannot create packet stream */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  silc_packet_set_context(ac->packet_stream, ac);

  /* Set source ID to packet stream */
  if (!silc_packet_set_ids(ac->packet_stream, SILC_ID_SERVER, &server->id,
			   0, NULL)) {
    /** Out of memory */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  if (!silc_socket_stream_get_info(ac->stream, NULL, &ac->hostname,
				   &ac->ip, &ac->port)) {
    /** Bad socket stream */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check whether this connection is denied to connect to us. */
  deny = silc_server_params_find_denied(server, ac->ip, ac->hostname);
  if (deny) {
    /** Connection is denied */
    SILC_LOG_INFO(("Connection %s (%s) is denied", ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_BANNED_FROM_SERVER;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  server->params->refcnt++;

  /* Check whether we have configured this sort of connection at all. We
     have to check all configurations since we don't know what type of
     connection this is. */
  ac->cconfig = silc_server_params_find_client(server, ac->ip, ac->hostname);
  ac->sconfig = silc_server_params_find_server(server, ac->ip, ac->hostname);
  if (server->server_type == SILC_ROUTER)
    ac->rconfig = silc_server_params_find_router(server, ac->ip,
						 ac->hostname, ac->port);
  if (!ac->cconfig && !ac->sconfig && !ac->rconfig) {
    /** Connection not configured */
    SILC_LOG_INFO(("Connection %s (%s) not configured", ac->hostname,
		   ac->ip));
    ac->error = SILC_STATUS_ERR_BANNED_FROM_SERVER;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_INFO(("Incoming connection %s (%s)", ac->hostname, ac->ip));

  /* Take flags for key exchange. Since we do not know what type of connection
     this is, we go through all found configurations and use the global ones
     as well. This will result always into strictest key exchange flags. */
  SILC_GET_SKE_FLAGS(ac->cconfig, flags);
  SILC_GET_SKE_FLAGS(ac->sconfig, flags);
  SILC_GET_SKE_FLAGS(ac->rconfig, flags);
  if (server->params->param.key_exchange_pfs)
    flags |= SILC_SKE_SP_FLAG_PFS;

  server->stat.conn_attempts++;

  /* Start SILC Key Exchange protocol */
  SILC_LOG_DEBUG(("Starting key exchange protocol"));
  ac->data.ske = silc_ske_alloc(server->rng, silc_fsm_get_schedule(fsm),
				server->public_key, server->private_key, ac);
  if (!ac->data.ske) {
    /** Out of memory */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }
  silc_ske_set_callbacks(ac->data.ske, silc_server_accept_verify_key,
			 silc_server_accept_completed, ac);

  /** Waiting for SKE completion */
  silc_fsm_next(fsm, silc_server_st_accept_set_keys);
  SILC_FSM_CALL((ac->op = silc_ske_responder(ac->data.ske, ac->packet_stream,
					     silc_version_string, flags)));
}

SILC_FSM_STATE(silc_server_st_accept_set_keys)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;
  SilcCipher send_key, receive_key;
  SilcHmac hmac_send, hmac_receive;

  if (ac->status != SILC_SKE_STATUS_OK) {
    /** SKE failed */
    SILC_LOG_ERROR(("Error (%s) during Key Exchange protocol with %s (%s)",
		    silc_ske_map_status(ac->status), ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_KEY_EXCHANGE_FAILED;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Setting keys into use"));

  /* Set the keys into use.  The data will be encrypted after this. */
  if (!silc_ske_set_keys(ac->data.ske, ac->keymat, ac->prop, &send_key,
			 &receive_key, &hmac_send, &hmac_receive,
			 &ac->hash)) {
    /** Error setting keys */
    ac->error = SILC_STATUS_ERR_KEY_EXCHANGE_FAILED;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }
  silc_packet_set_ciphers(ac->packet_stream, send_key, receive_key);
  silc_packet_set_hmacs(ac->packet_stream, hmac_send, hmac_receive);

  SILC_LOG_DEBUG(("Starting connection authentication"));
  server->stat.auth_attempts++;

  ac->connauth = silc_connauth_alloc(silc_fsm_get_schedule(fsm), ac->data.ske,
				     server->params->conn_auth_timeout);
  if (!ac->connauth) {
    /** Error allocating auth protocol */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /** Waiting authentication completion */
  silc_fsm_next(fsm, silc_server_st_accept_authenticated);
  SILC_FSM_CALL((ac->op = silc_connauth_responder(
					  ac->connauth,
					  silc_server_accept_get_auth,
					  silc_server_accept_auth_compl,
					  ac)));
}

SILC_FSM_STATE(silc_server_st_accept_authenticated)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;
  SilcUInt32 conn_number, num_sockets, max_hosts, max_per_host;
  SilcUInt32 r_protocol_version, l_protocol_version;
  SilcUInt32 r_software_version, l_software_version;
  char *r_vendor_version = NULL, *l_vendor_version;
  SilcServerParamConnParams params, global;
  SilcBool backup_router = FALSE;

  if (ac->auth_success == FALSE) {
    /** Authentication failed */
    SILC_LOG_INFO(("Authentication failed for %s (%s) [%s]",
		   ac->hostname, ac->ip,
		   SILC_CONNTYPE_STRING(ac->data.type)));
    ac->error = SILC_STATUS_ERR_AUTH_FAILED;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Checking whether connection is allowed"));

  global = &server->params->param;

  if (ac->data.type == SILC_CONN_CLIENT) {
    /** Accept client connection */
    silc_fsm_next(fsm, silc_server_st_accept_client);
    params = ac->cconfig->param;
    conn_number = server->stat.my_clients;
  } else if (ac->data.type == SILC_CONN_SERVER) {
    /** Accept server connection */
    silc_fsm_next(fsm, silc_server_st_accept_server);
    params = ac->sconfig->param;
    backup_router = ac->sconfig->backup_router;
    conn_number = server->stat.my_servers;
  } else {
    /** Accept router connection */
    silc_fsm_next(fsm, silc_server_st_accept_server);
    params = ac->rconfig->param;
    backup_router = ac->rconfig->backup_router;
    conn_number = server->stat.my_routers;
  }

  silc_fsm_event_init(&ac->wait_register, silc_fsm_get_machine(fsm), 0);

  /* Check version */
  l_protocol_version = silc_version_to_num(params && params->version_protocol ?
					   params->version_protocol :
					   global->version_protocol);
  l_software_version = silc_version_to_num(params && params->version_software ?
					   params->version_software :
					   global->version_software);
  l_vendor_version = (params && params->version_software_vendor ?
		      params->version_software_vendor :
		      global->version_software_vendor);

  silc_ske_parse_version(ac->data.ske, &r_protocol_version, NULL,
			 &r_software_version, NULL, &r_vendor_version);

  /* Match protocol version */
  if (l_protocol_version && r_protocol_version &&
      r_protocol_version < l_protocol_version) {
    /** Protocol version mismatch */
    SILC_LOG_INFO(("Connection %s (%s) is too old version", ac->hostname,
		   ac->ip));
    ac->error = SILC_STATUS_ERR_BAD_VERSION;
    ac->error_string = strdup("You support too old protocol version");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Match software version */
  if (l_software_version && r_software_version &&
      r_software_version < l_software_version) {
    /** Software version mismatch */
    SILC_LOG_INFO(("Connection %s (%s) is too old version", ac->hostname,
		   ac->ip));
    ac->error = SILC_STATUS_ERR_BAD_VERSION;
    ac->error_string = strdup("You support too old software version");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Regex match vendor version */
  if (l_vendor_version && r_vendor_version &&
      !silc_string_match(l_vendor_version, r_vendor_version)) {
    /** Vendor version mismatch */
    SILC_LOG_INFO(("Connection %s (%s) is unsupported version", ac->hostname,
		   ac->ip));
    ac->error = SILC_STATUS_ERR_BAD_VERSION;
    ac->error_string = strdup("Your software is not supported");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }
  silc_free(r_vendor_version);

  /* Check for maximum connections limit */
  //  num_sockets = silc_server_num_sockets_by_ip(server, sock->ip, type);
  max_hosts = (params ? params->connections_max : global->connections_max);
  max_per_host = (params ? params->connections_max_per_host :
		  global->connections_max_per_host);

  if (max_hosts && conn_number >= max_hosts) {
    /** Server is full */
    SILC_LOG_INFO(("Server is full, closing %s (%s) connection", ac->hostname,
		   ac->ip));
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    ac->error_string = strdup("Server is full, try again later");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* XXX */
  num_sockets = 0;
  if (num_sockets >= max_per_host) {
    /** Too many connections */
    SILC_LOG_INFO(("Too many connections from %s (%s), closing connection",
		   ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    ac->error_string = strdup("Too many connections from your host");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* If we are waiting backup router connection, do not accept any other
     connections. */
  if (server->wait_backup && !backup_router) {
    /** No backup established */
    SILC_LOG_INFO(("Will not accept connections because we do "
		   "not have backup router connection established"));
    ac->error = SILC_STATUS_ERR_PERM_DENIED;
    ac->error_string = strdup("We do not have connection to backup router "
			      "established, try later");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* If we are backup router and this is incoming server connection
     and we do not have connection to primary router, do not allow
     the connection. */
  if (server->server_type == SILC_BACKUP_ROUTER &&
      ac->data.type == SILC_CONN_SERVER &&
      !SILC_PRIMARY_ROUTE(server)) {
    /** No primary established */
    SILC_LOG_INFO(("Will not accept server connection because we do "
		   "not have primary router connection established"));
    ac->error = SILC_STATUS_ERR_PERM_DENIED;
    ac->error_string = strdup("We do not have connection to primary router "
			      "established, try later");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_server_st_accept_client)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;
  SilcServerParamClient conn = ac->cconfig;
  SilcServerParamConnParams param = &server->params->param;
  SilcClientEntry client;
  SilcClientID client_id;
  SilcBool timedout;
  char *username = NULL, *realname = NULL;
  SilcUInt16 username_len;
  SilcUInt32 id_len, mode = 0;
  char n[128], u[384], h[256];
  int ret;

  /* Wait here for the NEW_CLIENT or RESUME_CLIENT packet */
  SILC_FSM_EVENT_TIMEDWAIT(&ac->wait_register, 20, 0, &timedout);

  if (!ac->register_packet || timedout) {
    /** Client did not register */
    SILC_LOG_INFO(("Client connection %s (%s) did not register",
		   ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_NOT_REGISTERED;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Connection %s (%s) is client", ac->hostname, ac->ip));
  SILC_LOG_INFO(("Connection %s (%s) is client", ac->hostname, ac->ip));

  /* Handle resuming separately */
  if (ac->register_packet->type == SILC_PACKET_RESUME_CLIENT) {
    /** Resume client connection */
    silc_fsm_next(fsm, silc_server_st_accept_resume_client);
    return SILC_FSM_CONTINUE;
  }

  /* Get connection parameters */
  if (conn->param) {
    param = conn->param;

    if (!param->keepalive_secs)
      param->keepalive_secs = server->params->param.keepalive_secs;

    if (!param->qos && server->params->param.qos) {
      param->qos = server->params->param.qos;
      param->qos_rate_limit = server->params->param.qos_rate_limit;
      param->qos_bytes_limit = server->params->param.qos_bytes_limit;
      param->qos_limit_sec = server->params->param.qos_limit_sec;
      param->qos_limit_usec = server->params->param.qos_limit_usec;
    }

    /* Check if to be anonymous connection */
    if (param->anonymous)
      mode |= SILC_UMODE_ANONYMOUS;
  }

  /* Parse NEW_CLIENT packet */
  ret = silc_buffer_unformat(&ac->register_packet->buffer,
			     SILC_STR_UI16_NSTRING(&username,
						   &username_len),
			     SILC_STR_UI16_STRING(&realname),
			     SILC_STR_END);
  if (ret < 0) {
    /** Bad NEW_CLIENT packet */
    SILC_LOG_ERROR(("Client %s (%s) sent incomplete information",
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
    ac->error_string = strdup("Bad NEW_CLIENT packet");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  if (!username) {
    /** Client did not send username */
    SILC_LOG_ERROR(("Client %s (%s) did not send its username",
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
    ac->error_string = strdup("You did not send username");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  if (username_len > 128) {
    username_len = 128;
    username[username_len - 1] = '\0';
  }

  memset(n, 0, sizeof(n));
  memset(u, 0, sizeof(u));
  memset(h, 0, sizeof(h));

  ret = silc_parse_userfqdn(username, u, 128, h, sizeof(h));
  if (ret < 2) {
    /* Hostname not present, add it */
    silc_snprintf(n, sizeof(n), "%s", u);
    silc_snprintf(u, sizeof(u) - 1, "%s@%s", n, ac->hostname);
  } else {
    /* Verify that hostname is same than resolved hostname */
    if (strcmp(ac->hostname, h)) {
      /** Wrong hostname string */
      SILC_LOG_ERROR(("Client %s (%s) sent wrong hostname string",
		      ac->hostname, ac->ip));
      ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
      ac->error_string = strdup("You sent wrong hostname string");
      silc_fsm_next(fsm, silc_server_st_accept_error);
      return SILC_FSM_CONTINUE;
    }
    silc_snprintf(n, sizeof(n), "%s", u);
    silc_snprintf(u, sizeof(u) - 1, "%s@%s", n, h);
  }

  /* If configured as anonymous, scramble the username and hostname */
  if (mode & SILC_UMODE_ANONYMOUS) {
    char *scramble;

    u[0] = silc_rng_get_byte_fast(server->rng);
    u[1] = silc_rng_get_byte_fast(server->rng);
    u[2] = silc_rng_get_byte_fast(server->rng);
    u[3] = silc_rng_get_byte_fast(server->rng);

    scramble = silc_hash_babbleprint(server->sha1hash, u, strlen(u));
    if (!scramble) {
      /** Out of memory */
      ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
      silc_fsm_next(fsm, silc_server_st_accept_error);
      return SILC_FSM_CONTINUE;
    }

    username_len = strlen(scramble);
    memset(u, 0, username_len);
    memcpy(u, scramble, username_len);
    u[5] = '@';
    u[11] = '.';
    memcpy(&u[16], ".silc", 5);
    u[21] = '\0';

    /* Get nickname from scrambled username */
    silc_parse_userfqdn(u, n, sizeof(n), NULL, 0);
    silc_free(scramble);
  }

  /* Create Client ID */
  if (!silc_server_create_client_id(server, n, &client_id)) {
    /** Could not create Client ID */
    SILC_LOG_ERROR(("Client %s (%s) sent bad nickname string",
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_BAD_NICKNAME;
    ac->error_string = strdup("Bad nickname");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Create client entry */
  client = silc_server_add_client(server, n, u, realname, &client_id,
				  mode, ac->packet_stream);
  if (!client) {
    /** Could not create client entry */
    SILC_LOG_ERROR(("Could not create new client entry"));
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Save entry data */
  client->data = ac->data;
  client->data.registered = TRUE;
  client->data.local = TRUE;
  silc_packet_set_context(ac->packet_stream, client);

  /* Set destination ID to packet stream */
  if (!silc_packet_set_ids(client->stream, 0, NULL, SILC_ID_CLIENT,
			   &client->id)) {
    /** Out of memory */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send the new client ID to the client. */
  silc_server_send_new_id(ac->packet_stream, FALSE, &client->id,
			  SILC_ID_CLIENT);

  /* Send nice welcome to the client */
  silc_server_send_welcome(ac, client);

  /* Notify our router about new client on the SILC network */
  silc_server_send_new_id(SILC_PRIMARY_ROUTE(server), SILC_BROADCAST(server),
			  &client->id, SILC_ID_CLIENT);

#if 0
  /* Distribute to backup routers */
  if (server->server_type == SILC_ROUTER) {
    SilcBuffer idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    silc_server_backup_send(server, sock->user_data, SILC_PACKET_NEW_ID, 0,
			    idp->data, idp->len, FALSE, TRUE);
    silc_buffer_free(idp);
  }
#endif /* 0 */

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL, 0);

  /* Statistics */
  /* XXX */

  silc_packet_free(ac->register_packet);

  /** Connection accepted */
  silc_fsm_next(fsm, silc_server_st_accept_finish);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_server_st_accept_resume_client)
{

  /** Connection accepted */
  silc_fsm_next(fsm, silc_server_st_accept_finish);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_server_st_accept_server)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;
  SilcBool initiator = FALSE;
  SilcBool backup_local = FALSE;
  SilcBool backup_router = FALSE;
  char *backup_replace_ip = NULL;
  SilcUInt16 backup_replace_port = 0;
  SilcServerParamServer sconn = ac->sconfig;
  SilcServerParamRouter rconn = ac->rconfig;
  SilcServerEntry server_entry;
  SilcServerID server_id;
  SilcBool timedout;
  unsigned char *server_name, *server_namec, *id_string;
  SilcUInt16 id_len, name_len;
  int ret;

#if 0

  /* Wait here for the NEW_SERVER packet */
  SILC_FSM_EVENT_TIMEDWAIT(&ac->wait_register, 20, 0, &timedout);

  if (!ac->register_packet || timedout) {
    /** Server did not register */
    SILC_LOG_INFO(("%s connection %s (%s) did not register",
		   SILC_CONNTYPE_STRING(ac->data.type),
		   ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_NOT_REGISTERED;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Get connection parameters */
  if (ac->data.type == SILC_CONN_ROUTER) {
    if (rconn) {
      if (rconn->param) {
	param = rconn->param;

	if (!param->keepalive_secs)
	  param->keepalive_secs = server->params->param.keepalive_secs;

	if (!param->qos && server->params->param.qos) {
	  param->qos = server->params->param.qos;
	  param->qos_rate_limit = server->params->param.qos_rate_limit;
	  param->qos_bytes_limit = server->params->param.qos_bytes_limit;
	  param->qos_limit_sec = server->params->param.qos_limit_sec;
	  param->qos_limit_usec = server->params->param.qos_limit_usec;
	}
      }

      initiator = rconn->initiator;
      backup_local = rconn->backup_local;
      backup_router = rconn->backup_router;
      backup_replace_ip = rconn->backup_replace_ip;
      backup_replace_port = rconn->backup_replace_port;
    }
  } else if (ac->data.type == SILC_CONN_SERVER) {
    if (sconn) {
      if (sconn->param) {
	param = sconn->param;

	if (!param->keepalive_secs)
	  param->keepalive_secs = server->params->param.keepalive_secs;

	if (!param->qos && server->params->param.qos) {
	  param->qos = server->params->param.qos;
	  param->qos_rate_limit = server->params->param.qos_rate_limit;
	  param->qos_bytes_limit = server->params->param.qos_bytes_limit;
	  param->qos_limit_sec = server->params->param.qos_limit_sec;
	  param->qos_limit_usec = server->params->param.qos_limit_usec;
	}
      }

      backup_router = sconn->backup_router;
    }
  }

  SILC_LOG_DEBUG(("Connection %s (%s) is %s", sock->hostname,
		  sock->ip, ac->data.type == SILC_CONN_SERVER ?
		  "server" : (backup_router ? "backup router" : "router")));
  SILC_LOG_INFO(("Connection %s (%s) is %s", sock->hostname,
		 sock->ip, ac->data.type == SILC_CONN_SERVER ?
		 "server" : (backup_router ? "backup router" : "router")));

  /* Parse NEW_SERVER packet */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING(&id_string, &id_len),
			     SILC_STR_UI16_NSTRING(&server_name, &name_len),
			     SILC_STR_END);
  if (ret < 0) {
    /** Bad NEW_SERVER packet */
    SILC_LOG_ERROR(("%s %s (%s) sent incomplete information",
		    SILC_CONNTYPE_STRING(ac->data.type),
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
    ac->error_string = strdup("Bad NEW_SERVER packet");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  if (name_len > 256) {
    name_len = 256;
    server_name[name_len - 1] = '\0';
  }

  /* Get server ID */
  if (!silc_id_str2id(id_string, id_len, SILC_ID_SERVER, &server_id,
		      sizeof(server_id))) {
    /** Bad Server ID */
    SILC_LOG_ERROR(("%s %s (%s) sent incomplete information",
		    SILC_CONNTYPE_STRING(ac->data.type),
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
    ac->error_string = strdup("Bad Server ID");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check for valid server ID */
  if (!silc_server_check_server_id(ac->ip, &server_id)) {
    /** Invalid Server ID */
    SILC_LOG_ERROR(("%s %s (%s) sent incomplete information",
		    SILC_CONNTYPE_STRING(ac->data.type),
		    ac->hostname, ac->ip));
    ac->error = SILC_STATUS_ERR_INCOMPLETE_INFORMATION;
    ac->error_string = strdup("Your Server ID is not based on your real "
			      "IP address.  Check your configuration.");
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Create server entry */
  server_entry =
    silc_server_add_server(server, server_name,
			   (ac->data.type == SILC_CONN_SERVER ?
			    SILC_SERVER : SILC_ROUTER), &server_id,
			   ac->stream);
  if (!server_entry) {
    /** Could not create server entry */
    SILC_LOG_ERROR(("Could not create new server entry"));
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* Save entry data */
  server_entry->data = ac->data;
  server_entry->data.registered = TRUE;
  server_entry->data.local = TRUE;
  silc_packet_set_context(ac->packet_stream, server_entry);

  /* Set source ID to packet stream */
  if (!silc_packet_set_ids(server_entry->stream, 0, NULL, SILC_ID_SERVER,
			   &server_entry->id)) {
    /** Out of memory */
    ac->error = SILC_STATUS_ERR_RESOURCE_LIMIT;
    silc_fsm_next(fsm, silc_server_st_accept_error);
    return SILC_FSM_CONTINUE;
  }

  /* If the incoming connection is router and marked as backup router
     then add it to be one of our backups */
  if (ac->data.type == SILC_CONN_ROUTER && backup_router) {
    /* Change it back to SERVER type since that's what it really is. */
    if (backup_local)
      server->data.type = SILC_CONN_SERVER;
    server_entry->thread->server_type = SILC_BACKUP_ROUTER;

    SILC_SERVER_SEND_OPERS(server, FALSE, TRUE, SILC_NOTIFY_TYPE_NONE,
			   ("Backup router %s is now online",
			    ac->hostname));
  }

  /* Check whether this connection is to be our primary router connection
     if we do not already have the primary route. */
  if (!backup_router && server->standalone &&
      server_entry->data.type == SILC_CONN_ROUTER) {
    if (silc_server_config_is_primary_route(server) && !initiator)
      break;

    SILC_LOG_DEBUG(("We are not standalone server anymore"));
    server->standalone = FALSE;
    if (!server->id_entry->router) {
      server->id_entry->router = id_entry;
      server->router = id_entry;
    }
  }



  /* Distribute the information about new server in the SILC network
     to our router. If we are normal server we won't send anything
     since this connection must be our router connection. */
  if (server->server_type == SILC_ROUTER && !server->standalone &&
      SILC_PRIMARY_ROUTE(server) != sock)
    silc_server_send_new_id(server, SILC_PRIMARY_ROUTE(server),
			    TRUE, new_server->id, SILC_ID_SERVER,
			    silc_id_get_len(server_id, SILC_ID_SERVER));

  if (server->server_type == SILC_ROUTER) {
    /* Distribute to backup routers */
    SilcBuffer idp = silc_id_payload_encode(new_server->id, SILC_ID_SERVER);
    silc_server_backup_send(server, sock->user_data, SILC_PACKET_NEW_ID, 0,
			    idp->data, idp->len, FALSE, TRUE);
    silc_buffer_free(idp);
  }

  /* Check whether this router connection has been replaced by an
     backup router. If it has been then we'll disable the server and will
     ignore everything it will send until the backup router resuming
     protocol has been completed. */
  if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
      silc_server_backup_replaced_get(server, server_id, NULL)) {
    /* Send packet to the router indicating that it cannot use this
       connection as it has been replaced by backup router. */
    SILC_LOG_DEBUG(("Remote router has been replaced by backup router, "
		    "disabling its connection"));

    silc_server_backup_send_replaced(server, sock);

    /* Mark the router disabled. The data sent earlier will go but nothing
       after this goes to this connection. */
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
  } else {
    /* If it is router announce our stuff to it. */
    if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
	server->server_type == SILC_ROUTER) {
      silc_server_announce_servers(server, FALSE, 0, sock);
      silc_server_announce_clients(server, 0, sock);
      silc_server_announce_channels(server, 0, sock);
    }

    /* Announce our information to backup router */
    if (new_server->thread->server_type == SILC_BACKUP_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_SERVER &&
	server->thread->server_type == SILC_ROUTER) {
      silc_server_announce_servers(server, TRUE, 0, sock);
      silc_server_announce_clients(server, 0, sock);
      silc_server_announce_channels(server, 0, sock);
    }

    /* If backup router, mark it as one of ours.  This server is considered
       to be backup router after this setting. */
    if (new_server->thread->server_type == SILC_BACKUP_ROUTER) {
      SilcServerParamRouter backup;
      backup = silc_server_params_find_backup(server, sock->ip,
					      sock->hostname);
      if (backup) {
	/* Add as our backup router */
	silc_server_backup_add(server, new_server, backup->backup_replace_ip,
			       backup->backup_replace_port,
			       backup->backup_local);
      }
    }

    /* By default the servers connected to backup router are disabled
       until backup router has become the primary */
    if (server->thread->server_type == SILC_BACKUP_ROUTER &&
	server_entry->data.type == SILC_CONN_SERVER)
      server_entry->data.disabled = TRUE;
  }

  /* Statistics */
  /* XXX */

  silc_packet_free(ac->register_packet);
#endif /* 0 */

  /** Connection accepted */
  silc_fsm_next(fsm, silc_server_st_accept_finish);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_server_st_accept_finish)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;

  SILC_LOG_DEBUG(("New connection accepted"));

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_accept_error)
{
  SilcServerAccept ac = fsm_context;
  SilcServer server = ac->thread->server;

  SILC_LOG_DEBUG(("Error accepting new connection"));

  /* Disconnect remote connection */
  if (ac->packet_stream)
    silc_server_disconnect(server, ac->packet_stream, ac->error,
			   ac->error_string);
  else
    silc_stream_destroy(ac->stream);

  /* Statistics */
  server->stat.conn_failures++;
  if (ac->connauth)
    server->stat.auth_failures++;

  return SILC_FSM_FINISH;
}
