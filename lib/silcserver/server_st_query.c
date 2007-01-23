/*

  server_st_query.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2006 Pekka Riikonen

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

/************************** Types and definitions ***************************/

/* Resolving entry */
typedef struct SilcServerQueryResolveStruct {
  struct SilcServerQueryResolveStruct *next;
  SilcFSMThreadStruct thread;	    /* FSM thread for waiting reply */
  SilcServerPending pending;	    /* Pending command context */
  SilcPacketStream stream;	    /* Resolving connection */
  SilcID *ids;			    /* Resolved IDs */
  unsigned int ids_count     : 30;  /* Number of resolved IDs */
  unsigned int attached      :  1;  /* Set if attached to a resolving */
  unsigned int local         :  1;  /* Set if client is local to us */
} *SilcServerQueryResolve;

/* Represents one error occurred during query */
typedef struct {
  SilcID id;			    /* ID */
  unsigned int index : 15;	    /* Index to IDs */
  unsigned int type : 2;   	    /* 0 = take from query->ids, 1 = take
				       from args, 2 = no args in error. */
  unsigned int error : 7;	    /* The actual error (SilcStatus) */
} *SilcServerQueryError;

/* Query session context */
typedef struct {
  /* Queried data */
  char *nickname;		    /* Queried nickname, normalized */
  char *nick_server;		    /* Queried nickname's server */
  char *server_name;		    /* Queried server name, normalized */
  char *channel_name;		    /* Queried channel name, normalized */
  SilcID *ids;			    /* Queried IDs */
  SilcUInt32 ids_count;		    /* number of queried IDs */
  SilcUInt32 reply_count;	    /* Requested reply count */
  SilcDList attrs;		    /* Requested Attributes in WHOIS */
  SilcFSMEventStruct wait_resolve;   /* Resolving signaller */

  /* Query session data */
  SilcServerComman cmd;		    /* Command context for query */
  SilcList clients;		    /* Found clients */
  SilcList servers;		    /* Found servers */
  SilcList channels;		    /* Found channels */
  SilcList resolve;		    /* Clients to resolve */
  SilcList resolvings;		    /* Ongoing resolvings */
  SilcServerQueryError errors;	    /* Query errors */
  SilcServerPending redirect;	    /* Pending redirect */
  SilcUInt16 errors_count;	    /* number of errors */
  SilcUInt8 resolve_retry;	    /* Resolving retry count */
  SilcCommand querycmd;		    /* Query command */
} *SilcServerQuery;


/************************ Static utility functions **************************/


/********************************* WHOIS ************************************/

SILC_FSM_STATE(silc_server_st_query_whois)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcServerQuery query;

  SILC_LOG_DEBUG(("WHOIS query"));

  query = silc_calloc(1, sizeof(*query));
  if (!query) {
    silc_server_command_free(cmd);
    return SILC_FSM_FINISH;
  }

  query->querycmd = SILC_COMMAND_WHOIS;
  query->cmd = cmd;

  silc_fsm_set_state_context(fsm, query);

  /* If we are normal server and query contains a nickname OR query
     doesn't contain nickname or ids BUT does contain user attributes,
     send it to the router */
  if (server->server_type != SILC_ROUTER && !server->standalone &&
      cmd->packet->stream != SILC_PRIMARY_ROUTE(server) &&
      (silc_argument_get_arg_type(args, 1, NULL) ||
       (!silc_argument_get_arg_type(args, 1, NULL) &&
	!silc_argument_get_arg_type(args, 4, NULL) &&
	silc_argument_get_arg_type(args, 3, NULL)))) {
    /** Send query to router */
    silc_fsm_next(fsm, silc_server_st_query_send_router);
    return SILC_FSM_CONTINUE;
  }

  /** Parse WHOIS query */
  silc_fsm_next(fsm, silc_server_st_query_parse);
  return SILC_FSM_CONTINUE;
}


/********************************* WHOWAS ***********************************/

SILC_FSM_STATE(silc_server_st_query_whowas)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;

  SILC_LOG_DEBUG(("WHOWAS query"));

  query = silc_calloc(1, sizeof(*query));
  if (!query) {
    silc_server_command_free(cmd);
    return SILC_FSM_FINISH;
  }

  query->querycmd = SILC_COMMAND_WHOWAS;
  query->cmd = cmd;

  silc_fsm_set_state_context(fsm, query);

  /* WHOWAS query is always sent to router if we are normal server */
  if (server->server_type == SILC_SERVER && !server->standalone &&
      cmd->packet->stream != SILC_PRIMARY_ROUTE(server)) {
    /** Send query to router */
    silc_fsm_next(fsm, silc_server_st_query_send_router);
    return SILC_FSM_CONTINUE;
  }

  /** Parse WHOWAS query */
  silc_fsm_next(fsm, silc_server_st_query_parse);
  return SILC_FSM_CONTINUE;
}


/******************************** IDENTIFY **********************************/

SILC_FSM_STATE(silc_server_st_query_identify)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_LOG_DEBUG(("IDENTIFY query"));

  query = silc_calloc(1, sizeof(*query));
  if (!query) {
    silc_server_command_free(cmd);
    return SILC_FSM_FINISH;
  }

  query->querycmd = SILC_COMMAND_IDENTIFY;
  query->cmd = cmd;

  silc_fsm_set_state_context(fsm, query);

  /* If we are normal server and query does not contain IDs, send it directly
     to router (it contains nickname, server name or channel name). */
  if (server->server_type == SILC_SERVER && !server->standalone &&
      cmd->packet->stream != SILC_PRIMARY_ROUTE(server) &&
      !silc_argument_get_arg_type(args, 5, NULL)) {
    /** Send query to router */
    silc_fsm_next(fsm, silc_server_st_query_send_router);
    return SILC_FSM_CONTINUE;
  }

  /** Parse IDENTIFY query */
  silc_fsm_next(fsm, silc_server_st_query_parse);
  return SILC_FSM_CONTINUE;
}


/**************************** Query redirecting *****************************/

/* Send the query to router for further processing */

SILC_FSM_STATE(silc_server_st_query_send_router)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcBuffer tmpbuf;
  SilcUInt16 cmd_ident, old_ident;

  SILC_LOG_DEBUG(("Redirecting query to router"));

  /* Send the command to our router */
  cmd_ident = silc_server_cmd_ident(server);
  old_ident = silc_command_get_ident(query->cmd->payload);
  silc_command_set_ident(query->cmd->payload, cmd_ident);

  tmpbuf = silc_command_payload_encode_payload(query->cmd->payload);
  if (!tmpbuf || !silc_packet_send(SILC_PRIMARY_ROUTE(server),
				   SILC_PACKET_COMMAND, 0,
				   tmpbuf->data, silc_buffer_len(tmpbuf))) {
    /** Error sending packet */
    silc_server_query_send_error(server, query,
				 SILC_STATUS_ERR_RESOURCE_LIMIT, 0);
    silc_fsm_next(fsm, silc_server_st_query_error);
    return SILC_FSM_CONTINUE;
  }

  silc_command_set_ident(query->cmd->payload, old_ident);
  silc_buffer_free(tmpbuf);

  /* Statistics */
  server->stat.commands_sent++;

  /* Continue parsing the query after receiving reply from router */
  query->redirect = silc_server_command_pending(thread, query->redirect_ident);
  if (!query->redirect) {
    /** No memory */
    silc_server_query_send_error(server, query,
				 SILC_STATUS_ERR_RESOURCE_LIMIT, 0);
    silc_fsm_next(fsm, silc_server_st_query_error);
    return SILC_FSM_CONTINUE;
  }

  /** Wait router reply */
  query->resolved = TRUE;
  silc_fsm_next(fsm, silc_server_st_query_router_reply)
  return SILC_FSM_CONTINUE;
}

/* Wait for router reply and process the reply when it arrives. */

SILC_FSM_STATE(silc_server_st_query_router_reply)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcServerPending pending = query->redirect;
  SilcBool timedout;

  /* Wait here for the reply */
  SILC_FSM_EVENT_TIMEDWAIT(&pending->wait_reply, 10, 0, &timedout);

  if (timedout) {
    /** Timeout waiting reply */
    silc_server_command_pending_free(thread, pending);
    silc_server_query_send_error(server, query, SILC_STATUS_ERR_TIMEDOUT, 0);
    silc_fsm_next(fsm, silc_server_st_query_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check if the query failed */
  if (!silc_command_get_status(pending->reply->payload, NULL, NULL)) {
    SilcBuffer buffer;

    SILC_LOG_DEBUG(("Sending error to original query"));

    /* Send the same command reply payload which contains the error */
    silc_command_set_command(pending->reply->payload, query->querycmd);
    silc_command_set_ident(pending->reply->payload,
			   silc_command_get_ident(query->cmd->payload));
    buffer = silc_command_payload_encode_payload(pending->reply->payload);
    if (buffer)
      silc_packet_send(query->cmd->packet->stream,
		       SILC_PACKET_COMMAND_REPLY, 0,
		       buffer->data, silc_buffer_len(buffer));
    silc_buffer_free(buffer);

    /* Statistics */
    server->stat.commands_sent++;

    /** Query error received */
    silc_server_command_pending_free(thread, pending);
    silc_fsm_next(fsm, silc_server_st_query_error);
    return SILC_FSM_CONTINUE;
  }

  silc_server_command_pending_free(thread, pending);

  /** Parse query command */
  silc_fsm_next(fsm, silc_server_st_query_parse);
  return SILC_FSM_CONTINUE;
}

/***************************** Query processing *****************************/

/* Parse the command query */

SILC_FSM_STATE(silc_server_st_query_parse)
{
  SilcServerThread thread = fsm_context;
  SilcServerQuery query = state_context;
  SilcServerCommand cmd = query->cmd;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcUInt32 tmp_len, argc = silc_argument_get_arg_num(args);
  unsigned char *tmp;
  SilcID id;
  int i;

  SILC_LOG_DEBUG(("Parsing %s query",
		  silc_get_command_name(query->querycmd)));

  switch (query->querycmd) {

  case SILC_COMMAND_WHOIS:
    /* Get requested attributes if set */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (tmp && !query->attrs && tmp_len <= SILC_ATTRIBUTE_MAX_REQUEST_LEN)
      query->attrs = silc_attribute_payload_parse(tmp, tmp_len);

    /* Get Client IDs if present. Take IDs always instead of nickname. */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (!tmp) {
      /* No IDs present */

      /* Get nickname */
      tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
      if (!tmp && !query->attrs) {
	/* No nickname, no ids and no attributes - send error */
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);

	/** Not enough arguments */
	silc_fsm_next(fsm, silc_server_st_query_error);
	return SILC_FSM_CONTINUE;
      }

      /* Get the nickname@server string and parse it */
      if (tmp && ((tmp_len > 128) ||
		  !silc_parse_userfqdn(tmp, &query->nickname,
				       &query->nick_server))) {
	/** Bad nickname */
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_BAD_NICKNAME, 0);
	silc_fsm_next(fsm, silc_server_st_query_error);
	return SILC_FSM_CONTINUE;
      }

      /* Check nickname */
      if (tmp) {
	tmp = silc_identifier_check(query->nickname, strlen(query->nickname),
				    SILC_STRING_UTF8, 128, &tmp_len);
	if (!tmp) {
	  /** Bad nickname */
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_BAD_NICKNAME, 0);
	  silc_fsm_next(fsm, silc_server_st_query_error);
	  return SILC_FSM_CONTINUE;
	}
	/* XXX why free nickname */
	silc_free(query->nickname);
	query->nickname = tmp;
      }

    } else {
      /* Parse the IDs included in the query */
      query->ids = silc_calloc(argc - 3, sizeof(*query->ids));
      if (!query->ids) {
	/** No memory */
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_RESOURCE_LIMIT, 0);
	silc_fsm_next(fsm, silc_server_st_query_error);
	return SILC_FSM_CONTINUE;
      }

      for (i = 0; i < argc - 3; i++) {
	tmp = silc_argument_get_arg_type(args, i + 4, &tmp_len);
	if (!tmp)
	  continue;

	if (!silc_id_payload_parse_id(tmp, tmp_len, &id) ||
	    id.type != SILC_ID_CLIENT) {
	  silc_server_query_add_error(server, query, 1, i + 4,
				      SILC_STATUS_ERR_BAD_CLIENT_ID);
	  continue;
	}

	/* Normal server must check whether this ID exist, and if not then
	   send the query to router, unless done so already */
	if (server->server_type == SILC_SERVER && !query->resolved &&
	    !silc_server_find_client_by_id(server, &client_id, TRUE, NULL)) {
	  /** Send query to router */
	  silc_free(query->ids);
	  query->ids = NULL;
	  query->ids_count = 0;
	  silc_fsm_next(fsm, silc_server_st_query_send_router);
	  return SILC_FSM_CONTINUE;
	}

	query->ids[query->ids_count] = id;
	query->ids_count++;
      }
    }

    /* Get the max count of reply messages allowed */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp && tmp_len == sizeof(SilcUInt32))
      SILC_GET32_MSB(query->reply_count, tmp);
    break

  case SILC_COMMAND_WHOWAS:
    /* Get nickname */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp) {
      /** Not enough arguments */
      silc_server_query_send_error(server, query,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
      silc_fsm_next(fsm, silc_server_st_query_error);
      return SILC_FSM_CONTINUE;
    }

    /* Get the nickname@server string and parse it */
    if (tmp_len > 128 ||
	!silc_parse_userfqdn(tmp, &query->nickname, &query->nick_server)) {
      /** Bad nickname */
      silc_server_query_send_error(server, query,
				   SILC_STATUS_ERR_BAD_NICKNAME, 0);
      silc_fsm_next(fsm, silc_server_st_query_error);
      return SILC_FSM_CONTINUE;
    }

    /* Check nickname */
    tmp = silc_identifier_check(query->nickname, strlen(query->nickname),
				SILC_STRING_UTF8, 128, &tmp_len);
    if (!tmp) {
      /** Bad nickname */
      silc_server_query_send_error(server, query,
				   SILC_STATUS_ERR_BAD_NICKNAME, 0);
      silc_fsm_next(fsm, silc_server_st_query_error);
      return SILC_FSM_CONTINUE;
    }
    /* XXX why free nickname */
    silc_free(query->nickname);
    query->nickname = tmp;

    /* Get the max count of reply messages allowed */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp && tmp_len == sizeof(SilcUInt32))
      SILC_GET32_MSB(query->reply_count, tmp);
    break;

  case SILC_COMMAND_IDENTIFY:
    /* Get IDs if present. Take IDs always instead of names. */
    tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
    if (!tmp) {
      /* No IDs present */

      /* Try get nickname */
      tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
      if (tmp) {
	/* Get the nickname@server string and parse it */
	if (tmp_len > 128 ||
	    !silc_parse_userfqdn(tmp, &query->nickname, &query->nick_server))
	  silc_server_query_add_error(server, query, 1, 1,
				      SILC_STATUS_ERR_BAD_NICKNAME);

	/* Check nickname */
	tmp = silc_identifier_check(query->nickname, strlen(query->nickname),
				    SILC_STRING_UTF8, 128, &tmp_len);
	if (!tmp) {
	  /** Bad nickname */
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_BAD_NICKNAME, 0);
	  silc_fsm_next(fsm, silc_server_st_query_error);
	  return SILC_FSM_CONTINUE;
	}
	/* XXX why free nickname */
	silc_free(query->nickname);
	query->nickname = tmp;
      }

      /* Try get server name */
      tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
      if (tmp) {
	/* Check server name */
	tmp = silc_identifier_check(tmp, tmp_len, SILC_STRING_UTF8,
				    256, &tmp_len);
	if (!tmp) {
	  /** Bad server name */
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_BAD_SERVER, 0);
	  silc_fsm_next(fsm, silc_server_st_query_error);
	  return SILC_FSM_CONTINUE;
	}
	query->server_name = tmp;
      }

      /* Get channel name */
      tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
      if (tmp && tmp_len <= 256) {
	/* Check channel name */
	tmp = silc_identifier_check(tmp, tmp_len, SILC_STRING_UTF8,
				    256, &tmp_len);
	if (!tmp) {
	  /** Bad channel name */
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_BAD_CHANNEL, 0);
	  silc_fsm_next(fsm, silc_server_st_query_error);
	  return SILC_FSM_CONTINUE;
	}
	query->channel_name = tmp;
      }

      if (!query->nickname && !query->server_name && !query->channel_name) {
	/** Nothing was queried */
	silc_server_query_send_error(server, query,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	silc_fsm_next(fsm, silc_server_st_query_error);
	return SILC_FSM_CONTINUE;
      }

    } else {
      /* Parse the IDs included in the query */
      query->ids = silc_calloc(argc - 4, sizeof(*query->ids));

      for (i = 0; i < argc - 4; i++) {
	tmp = silc_argument_get_arg_type(args, i + 5, &tmp_len);
	if (!tmp)
	  continue;

	if (!silc_id_payload_parse_id(tmp, tmp_len, &id)) {
	  silc_server_query_add_error(server, query, 1, i + 5,
				      SILC_STATUS_ERR_BAD_CLIENT_ID);
	  continue;
	}

	/* Normal server must check whether this ID exist, and if not then
	   send the query to router, unless done so already */
	if (server->server_type == SILC_SERVER && !query->resolved) {
	  if (id.type == SILC_ID_CLIENT) {
	    if (!silc_server_find_client_by_id(server, id, TRUE, NULL)) {
	      /** Send query to router */
	      silc_free(query->ids);
	      query->ids = NULL;
	      query->ids_count = 0;
	      silc_fsm_next(fsm, silc_server_st_query_send_router);
	      return SILC_FSM_CONTINUE;
	    }
	  } else {
	    /* For now all other ID's except Client ID's are explicitly
	       sent to router for resolving. */

	    /** Send query to router */
	    silc_free(query->ids);
	    query->ids = NULL;
	    query->ids_count = 0;
	    silc_fsm_next(fsm, silc_server_st_query_send_router);
	    return SILC_FSM_CONTINUE;
	  }
	}

	query->ids[query->ids_count] = id;
	query->ids_count++;
      }
    }

    /* Get the max count of reply messages allowed */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (tmp && tmp_len == sizeof(SilcUInt32))
      SILC_GET32_MSB(query->reply_count, tmp);
    break;
  }

  /** Find entries for query */
  silc_fsm_next(fsm, silc_server_st_query_find);
  return SILC_FSM_CONTINUE;
}

/* Find the entries according to the query */

SILC_FSM_STATE(silc_server_st_query_find)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcServerCommand cmd = query->cmd;
  SilcIDCacheEntry id_entry;
  SilcID *id;
  void *entry;
  int i;

  SILC_LOG_DEBUG(("Finding entries with %s query",
		  silc_get_command_name(query->querycmd)));

  if (query->nickname) {
    /* Find by nickname */
    if (!silc_server_find_clients(server, query->nickname, &query->clients))
      silc_server_query_add_error(server, query, 1, 1,
				  SILC_STATUS_ERR_NO_SUCH_NICK);
  }

  if (query->server_name) {
    /* Find server by name */
    if (!silc_server_find_server_by_name(server, query->server_name, TRUE,
					 &id_entry))
      silc_server_query_add_error(server, query, 1, 2,
				  SILC_STATUS_ERR_NO_SUCH_SERVER);
    else
      silc_list_add(query->servers, id_entry);
  }

  if (query->channel_name) {
    /* Find channel by name */
    if (!silc_server_find_channel_by_name(server, query->channel_name,
					  &id_entry))
      silc_server_query_add_error(server, query, 1, 3,
				  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    else
      silc_list_add(query->channels, id_entry);
  }

  if (query->ids_count) {
    /* Find entries by the queried IDs */
    for (i = 0; i < query->ids_count; i++) {
      id = &query->ids[i];

      switch (id->type) {

      case SILC_ID_CLIENT:
	/* Get client entry */
	if (!silc_server_find_client_by_id(server, &id->u.client_id, TRUE,
					   &id_entry)) {
	  silc_server_query_add_error(server, query, 0, i,
				      SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
	  continue;
	}

	silc_list_add(query->clients, id_entry);
	break;

      case SILC_ID_SERVER:
	/* Get server entry */
	if (!silc_server_find_server_by_id(server, &id->u.server_id, TRUE,
					   &id_entry)) {
	  silc_server_query_add_error(server, query, 0, i,
				      SILC_STATUS_ERR_NO_SUCH_SERVER_ID);
	  continue;
	}

	silc_list_add(query->servers, id_entry);
	break;

      case SILC_ID_CHANNEL:
	/* Get channel entry */
	if (!silc_server_find_channel_by_id(server, &id->u.channel_id,
					    &id_entry)) {
	  silc_server_query_add_error(server, query, 0, i,
				      SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID);
	  continue;
	}

	silc_list_add(query->channels, id_entry);
	break;

      default:
	break;
      }
    }
  }

  /* Check the attributes to narrow down the search by using them. */
  if (query->attrs) {
    /** Check user attributes */
    silc_fsm_next(fsm, silc_server_st_query_check_attrs);
    return SILC_FSM_CONTINUE;
  }

  /** Process found entries */
  silc_fsm_next(fsm, silc_server_st_query_process);
  return SILC_FSM_CONTINUE;
}

/* Check user attributes to narrow down clients in WHOIS query */

SILC_FSM_STATE(silc_server_st_query_check_attrs)
{

  /** Proecss found entries */
  silc_fsm_next(fsm, silc_server_st_query_process);
  return SILC_FSM_CONTINUE;
}

/* Process found entries */

SILC_FSM_STATE(silc_server_st_query_process)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcServerCommand cmd = query->cmd;
  SilcServerQueryResolve res;
  SilcIDCacheEntry id_entry;
  SilcClientEntry client_entry;
  SilcServerEntry server_entry;
  SilcChannelEntry channel_entry;
  SilcID *id;
  void *entry;
  int i;

  SILC_LOG_DEBUG(("Process %s query",
		  silc_get_command_name(query->querycmd)));

  SILC_LOG_DEBUG(("Querying %d clients", silc_list_count(query->clients)));
  SILC_LOG_DEBUG(("Querying %d servers", silc_list_count(query->servers)));
  SILC_LOG_DEBUG(("Querying %d channels", silc_list_count(query->channels)));

  /* If nothing was found, then just send the errors */
  if (!silc_list_count(query->clients) &&
      !silc_list_count(query->channels) &&
      !silc_list_count(query->servers)) {
    /** Nothing found, send errors */
    silc_fsm_next(fsm, silc_server_st_query_reply);
    return SILC_FSM_CONTINUE;
  }

#if 0
  /* If caller does not want us to resolve anything (has resolved already)
     then just continue with sending the reply */
  if (!resolve) {
    silc_server_query_send_reply(server, query, clients, clients_count,
				 servers, servers_count, channels,
				 channels_count);
    silc_free(clients);
    silc_free(servers);
    silc_free(channels);
    return;
  }
#endif

  /* Now process all found information and if necessary do some more
     resolving. */
  switch (query->querycmd) {

  case SILC_COMMAND_WHOIS:
    silc_list_start(query->clients);
    while ((id_entry = silc_list_get(query->clients)) != SILC_LIST_END) {
      client_entry = id_entry->context;

      /* Ignore unregistered clients */
      if (!SILC_IS_REGISTERED(client_entry)) {
	silc_list_del(query->clients, id_entry);
	continue;
      }

      /* If Requested Attributes is set then we always resolve the client
	 information, if not then check whether the entry is complete or not
	 and decide whether we need to resolve the missing information. */
      if (!query->attrs) {

	/* Even if nickname and stuff are present, we may need to resolve
	   the entry on normal server. */
	if (client_entry->nickname && client_entry->username &&
	    client_entry->userinfo) {

	  /* If we are router, client is local to us, or client is on channel
	     we do not need to resolve the client information. */
	  if (server->server_type != SILC_SERVER ||
	      SILC_IS_LOCAL(client_entry)||
	      silc_hash_table_count(client_entry->channels) ||
	      query->resolved)
	    continue;
	}
      }

      /* Remove the NOATTR status periodically */
      if (client_entry->data.noattr &&
	  client_entry->updated + 600 < time(NULL))
	client_entry->data.noattr = FALSE;

      /* When requested attributes is present and local client is detached
	 we cannot send the command to the client, we'll reply on behalf of
	 the client instead. */
      if (query->attrs && SILC_IS_LOCAL(client_entry) &&
	  (client_entry->mode & SILC_UMODE_DETACHED ||
	   client_entry->data.noattr))
	continue;

#if 0
      /* If attributes are present in query, and in the entry and we have
	 done resolvings already we don't need to resolve anymore */
      if (query->resolved && query->attrs && client_entry->attrs)
	continue;
#endif

      /* Mark this entry to be resolved */
      silc_list_add(query->resolve, id_entry);
    }
    break;

  case SILC_COMMAND_WHOWAS:
    silc_list_start(query->clients);
    while ((id_entry = silc_list_get(query->clients)) != SILC_LIST_END) {
      client_entry = id_entry->context;

      /* Take only unregistered clients */
      if (SILC_IS_REGISTERED(client_entry)) {
	silc_list_del(query->clients, id_entry);
	continue;
      }

      /* If both nickname and username are present no resolving is needed */
      if (client_entry->nickname && client_entry->username)
	continue;

      /* Mark this entry to be resolved */
      silc_list_add(query->resolve, id_entry);
    }
    break;

  case SILC_COMMAND_IDENTIFY:
    silc_list_start(query->clients);
    while ((id_entry = silc_list_get(query->clients)) != SILC_LIST_END) {
      client_entry = id_entry->context;

      /* Ignore unregistered clients */
      if (!SILC_IS_REGISTERED(client_entry))
	continue;

      /* Even if nickname is present, we may need to resolve the entry
	 on normal server. */
      if (client_entry->nickname) {

	/* If we are router, client is local to us, or client is on channel
	   we do not need to resolve the client information. */
	if (server->server_type != SILC_SERVER ||
	    SILC_IS_LOCAL(client_entry)||
	    silc_hash_table_count(client_entry->channels) ||
	    query->resolved)
	  continue;
      }

      /* Mark this entry to be resolved */
      silc_list_add(query->resolve, id_entry);
    }
    break;
  }

  /* If we need to resolve entries, do it now */
  if (silc_list_count(query->resolve)) {
    /** Resolve entries */
    silc_fsm_next(fsm, silc_server_st_query_resolve);
    return SILC_FSM_CONTINUE;
  }

  /** Send reply to query */
  silc_fsm_next(fsm, silc_server_st_query_reply);
  return SILC_FSM_CONTINUE;
}

/* Resolve incomplete client entries.  Other types of entries need not
   resolving. */

SILC_FSM_STATE(silc_server_st_query_resolve)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcArgumentPayload cmd_args = silc_command_get_args(query->cmd->payload);
  SilcServerQueryResolve res;
  SilcIDCacheEntry id_entry;
  unsigned char args[256][28];
  SilcUInt32 arg_lens[256], arg_types[256], argc = 0;
  SilcBuffer res_cmd;
  int i;

  SILC_LOG_DEBUG(("Resolve incomplete entries"));

  silc_list_start(query->resolve);
  while ((id_entry = silc_list_get(query->resolve)) != SILC_LIST_END) {
    client_entry = id_entry->context;

    /* If entry is being resolved, attach to that resolving */
    if (client_entry->data.resolving) {
      res = silc_calloc(1, sizeof(*res));
      if (!res)
	continue;

      silc_fsm_thread_init(&res->thread, fsm, res, NULL, NULL, FALSE);
      res->stream = client_entry->stream;

      res->pending =
	silc_server_command_pending(thread, client_entry->resolve_cmd_ident);
      if (!res->pending) {
	SILC_LOG_ERROR(("BUG: No pending command for resolving client entry"));
	continue;
      }

      res->attached = TRUE;
      silc_list_add(query->resolvings, res);
      continue;
    }

    /* Check if we have resolving destination already set */
    silc_list_start(query->resolvings);
    while ((res = silc_list_get(query->resolvings)) != SILC_LIST_END)
      if (res->stream == client_entry->stream && !res->attached)
	break;

    if (!res) {
      /* Create new resolving context */
      res = silc_calloc(1, sizeof(*res));
      if (!res)
	continue;

      silc_fsm_thread_init(&res->thread, fsm, res, NULL, NULL, FALSE);
      res->stream = client_entry->stream;

      res->pending =
	silc_server_command_pending(thread, silc_server_cmd_ident(server));
      if (!res->pending)
	continue;

      silc_list_add(query->resolvings, res);
    }

    /* Mark the entry as being resolved */
    client_entry->data.resolving = TRUE;
    client_entry->data.resolved = FALSE;
    client_entry->resolve_cmd_ident = res->pending->cmd_ident;
    client_entry->updated = time(NULL);

    if (SILC_IS_LOCAL(client_entry))
      res->local = TRUE;

    switch (query->querycmd) {
    case SILC_COMMAND_WHOIS:
    case SILC_COMMAND_IDENTIFY:
      res->ids = silc_realloc(res->ids, sizeof(*res->ids) *
			      (res->ids_count + 1));
      if (!res->ids)
	continue;

      res->ids[res->ids_count++].u.client_id = client_entry->id;
      break;

    case SILC_COMMAND_WHOWAS:
      break;
    }
  }

  SILC_LOG_DEBUG(("Sending the resolvings"));

  /* Send the resolvings */
  silc_list_start(query->resolvings);
  while ((res = silc_list_get(query->resolvings)) != SILC_LIST_END) {

    if (!res->attached) {

      switch (query->querycmd) {
      case SILC_COMMAND_WHOIS:
      case SILC_COMMAND_IDENTIFY:

	/* If Requested Attributes were present put them to this resolving */
	if (query->attrs && query->querycmd == SILC_COMMAND_WHOIS) {
	  arg_types[argc] = 3;
	  args[argc] = silc_argument_get_arg_type(cmd_args, 3,
						  &arg_lens[argc]);
	  argc++;
	}

	/* Encode IDs */
	for (i = 0; i < res->ids_count; i++) {
	  arg_types[argc] = (query->querycmd == SILC_COMMAND_WHOIS ?
			     4 + i : 5 + i);
	  silc_id_id2str(&res->ids[argc].u.client_id, SILC_ID_CLIENT,
			 args[argc], sizeof(args[argc]), &arg_lens[argc]);
	  argc++;
	  if (i + 1 > 255)
	    break;
	}

	/* Send the command */
	res_cmd = silc_command_payload_encode(query->querycmd, argc,
					      args, arg_lens, arg_types,
					      res->pending->cmd_ident);
	if (!res_cmd) {
	  /** No memory */
	  silc_server_query_send_error(server, query,
				       SILC_STATUS_ERR_RESOURCE_LIMIT, 0);
	  silc_fsm_next(fsm, silc_server_st_query_error);
	  return SILC_FSM_CONTINUE;
	}

	silc_packet_send(res->stream, SILC_PACKET_COMMAND, 0,
			 res_cmd->data, silc_buffer_send(res_cmd));
	silc_buffer_free(res_cmd);
	silc_free(res->ids);
	res->ids = NULL;

	/* Statistics */
	server->stat.commands_sent++;
	break;

      case SILC_COMMAND_WHOWAS:
	/* Send WHOWAS command */
	silc_server_send_command(server, res->stream, query->querycmd,
				 res->pending->cmd_ident, 1,
				 1, query->nickname, strlen(query->nickname));
	break;
      }
    }

    /*** Resolve */
    silc_fsm_set_state_context(&res->thread, query);
    silc_fsm_start_sync(&res->thread, silc_server_st_query_wait_resolve);
  }

  /** Wait all resolvings */
  silc_fsm_next(fsm, silc_server_st_query_resolved);
  return SILC_FSM_CONTINUE;
}

/* Wait for resolving command reply */

SILC_FSM_STATE(silc_server_st_query_wait_resolve)
{
  SilcServerQueryResolve res = fsm_context;
  SilcServerQuery query = state_context;
  SilcBool timedout;

  /* Wait here for the reply */
  SILC_FSM_EVENT_TIMEDWAIT(&res->pending->wait_reply,
			  res->local ? 3 : 10, 0, &timedout);



  silc_list_del(query->resolvings, res);
  silc_server_command_pending_free(res->pending);
  silc_free(res);

  /* Signal main thread that reply was received */
  SILC_FSM_EVENT_SIGNAL(&query->wait_resolve);

  return SILC_FSM_FINISH;
}

/* Wait here that all resolvings has been received */

SILC_FSM_STATE(silc_server_st_query_resolved)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcServerCommand cmd = query->cmd;

  /* Wait here until all resolvings has arrived */
  SILC_FSM_EVENT_WAIT(&query->wait_resolve);
  if (silc_list_count(query->resolvings) > 0)
    return SILC_FSM_CONTINUE;

}

/* Send the reply to the query. */

SILC_FSM_STATE(silc_server_st_query_reply)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerQuery query = state_context;
  SilcServerCommand cmd = query->cmd;
  SilcIDCacheEntry id_entry;

}
