/*

  server.c

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
/*
 * This is the actual SILC server than handles everything relating to
 * servicing the SILC connections. This is also a SILC router as a router 
 * is also normal server.
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

/* Static prototypes */
SILC_TASK_CALLBACK(silc_server_connect_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router_second);
SILC_TASK_CALLBACK(silc_server_connect_to_router_final);
SILC_TASK_CALLBACK(silc_server_accept_new_connection);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_second);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_final);
SILC_TASK_CALLBACK(silc_server_packet_process);
SILC_TASK_CALLBACK(silc_server_packet_parse_real);
SILC_TASK_CALLBACK(silc_server_timeout_remote);
SILC_TASK_CALLBACK(silc_server_failure_callback);
SILC_TASK_CALLBACK(silc_server_rekey_callback);

/* Allocates a new SILC server object. This has to be done before the server
   can be used. After allocation one must call silc_server_init to initialize
   the server. The new allocated server object is returned to the new_server
   argument. */

int silc_server_alloc(SilcServer *new_server)
{
  SilcServer server;

  SILC_LOG_DEBUG(("Allocating new server object"));

  server = silc_calloc(1, sizeof(*server));
  server->server_type = SILC_SERVER;
  server->standalone = TRUE;
  server->local_list = silc_calloc(1, sizeof(*server->local_list));
  server->global_list = silc_calloc(1, sizeof(*server->global_list));
  server->pending_commands = silc_dlist_init();
#ifdef SILC_SIM
  server->sim = silc_dlist_init();
#endif

  *new_server = server;

  return TRUE;
}

/* Free's the SILC server object. This is called at the very end before
   the program ends. */

void silc_server_free(SilcServer server)
{
  if (server) {
#ifdef SILC_SIM
    SilcSimContext *sim;
#endif

    if (server->local_list)
      silc_free(server->local_list);
    if (server->global_list)
      silc_free(server->global_list);
    if (server->rng)
      silc_rng_free(server->rng);

#ifdef SILC_SIM
    while ((sim = silc_dlist_get(server->sim)) != SILC_LIST_END) {
      silc_dlist_del(server->sim, sim);
      silc_sim_free(sim);
    }
    silc_dlist_uninit(server->sim);
#endif

    if (server->params)
      silc_free(server->params);

    if (server->pending_commands)
      silc_dlist_uninit(server->pending_commands);

    silc_free(server);
  }
}

/* Initializes the entire SILC server. This is called always before running
   the server. This is called only once at the initialization of the program.
   This binds the server to its listenning port. After this function returns 
   one should call silc_server_run to start the server. This returns TRUE 
   when everything is ok to run the server. Configuration file must be
   read and parsed before calling this. */

int silc_server_init(SilcServer server)
{
  int *sock = NULL, sock_count = 0, i;
  SilcServerID *id;
  SilcServerEntry id_entry;
  SilcIDListPurge purge;

  SILC_LOG_DEBUG(("Initializing server"));
  assert(server);
  assert(server->config);

  /* Set public and private keys */
  if (!server->config->server_keys ||
      !server->config->server_keys->public_key || 
      !server->config->server_keys->private_key) {
    SILC_LOG_ERROR(("Server public key and/or private key does not exist"));
    return FALSE;
  }
  server->public_key = server->config->server_keys->public_key;
  server->private_key = server->config->server_keys->private_key;

  /* XXX After server is made as Silc Server Library this can be given
     as argument, for now this is hard coded */
  server->params = silc_calloc(1, sizeof(*server->params));
  server->params->retry_count = SILC_SERVER_RETRY_COUNT;
  server->params->retry_interval_min = SILC_SERVER_RETRY_INTERVAL_MIN;
  server->params->retry_interval_max = SILC_SERVER_RETRY_INTERVAL_MAX;
  server->params->retry_keep_trying = FALSE;
  server->params->protocol_timeout = 60;
  server->params->require_reverse_mapping = FALSE;

  /* Set log files where log message should be saved. */
  server->config->server = server;
  silc_server_config_setlogfiles(server->config);
 
  /* Register all configured ciphers, PKCS and hash functions. */
  silc_server_config_register_ciphers(server->config);
  silc_server_config_register_pkcs(server->config);
  silc_server_config_register_hashfuncs(server->config);
  silc_server_config_register_hmacs(server->config);

  /* Initialize random number generator for the server. */
  server->rng = silc_rng_alloc();
  silc_rng_init(server->rng);
  silc_rng_global_init(server->rng);

  /* Initialize hash functions for server to use */
  silc_hash_alloc("md5", &server->md5hash);
  silc_hash_alloc("sha1", &server->sha1hash);

  /* Initialize none cipher */
  silc_cipher_alloc("none", &server->none_cipher);

  /* Create a listening server. Note that our server can listen on
     multiple ports. All listeners are created here and now. */
  /* XXX Still check this whether to use server_info or listen_port. */
  sock_count = 0;
  while(server->config->listen_port) {
    int tmp;

    tmp = silc_net_create_server(server->config->listen_port->port,
				 server->config->listen_port->host);
    if (tmp < 0)
      goto err0;

    sock = silc_realloc(sock, (sizeof(int *) * (sock_count + 1)));
    sock[sock_count] = tmp;
    server->config->listen_port = server->config->listen_port->next;
    sock_count++;
  }

  /* Initialize ID caches */
  server->local_list->clients = 
    silc_idcache_alloc(0, silc_idlist_client_destructor);
  server->local_list->servers = silc_idcache_alloc(0, NULL);
  server->local_list->channels = silc_idcache_alloc(0, NULL);

  /* These are allocated for normal server as well as these hold some 
     global information that the server has fetched from its router. For 
     router these are used as they are supposed to be used on router. */
  server->global_list->clients = 
    silc_idcache_alloc(0, silc_idlist_client_destructor);
  server->global_list->servers = silc_idcache_alloc(0, NULL);
  server->global_list->channels = silc_idcache_alloc(0, NULL);

  /* Allocate the entire socket list that is used in server. Eventually 
     all connections will have entry in this table (it is a table of 
     pointers to the actual object that is allocated individually 
     later). */
  server->sockets = silc_calloc(SILC_SERVER_MAX_CONNECTIONS,
				sizeof(*server->sockets));

  for (i = 0; i < sock_count; i++) {
    SilcSocketConnection newsocket = NULL;

    /* Set socket to non-blocking mode */
    silc_net_set_socket_nonblock(sock[i]);
    server->sock = sock[i];
    
    /* Create a Server ID for the server. */
    silc_id_create_server_id(sock[i], server->rng, &id);
    if (!id) {
      goto err0;
    }
    
    server->id = id;
    server->id_string = silc_id_id2str(id, SILC_ID_SERVER);
    server->id_string_len = silc_id_get_len(SILC_ID_SERVER);
    server->id_type = SILC_ID_SERVER;
    server->server_name = server->config->server_info->server_name;

    /* Add ourselves to the server list. We don't have a router yet 
       beacuse we haven't established a route yet. It will be done later. 
       For now, NULL is sent as router. This allocates new entry to
       the ID list. */
    id_entry = 
      silc_idlist_add_server(server->local_list,
			     server->config->server_info->server_name,
			     server->server_type, server->id, NULL, NULL);
    if (!id_entry) {
      SILC_LOG_ERROR(("Could not add ourselves to cache"));
      goto err0;
    }
    
    /* Add ourselves also to the socket table. The entry allocated above
       is sent as argument for fast referencing in the future. */
    silc_socket_alloc(sock[i], SILC_SOCKET_TYPE_SERVER, id_entry, 
		      &newsocket);

    server->sockets[sock[i]] = newsocket;
    
    /* Perform name and address lookups to resolve the listenning address
       and port. */
    if (!silc_net_check_local_by_sock(sock[i], &newsocket->hostname, 
				     &newsocket->ip)) {
      if ((server->params->require_reverse_mapping && !newsocket->hostname) ||
	  !newsocket->ip) {
	SILC_LOG_ERROR(("IP/DNS lookup failed for local host %s",
			newsocket->hostname ? newsocket->hostname :
			newsocket->ip ? newsocket->ip : ""));
	server->stat.conn_failures++;
	goto err0;
      }
      if (!newsocket->hostname)
	newsocket->hostname = strdup(newsocket->ip);
    }
    newsocket->port = silc_net_get_local_port(sock[i]);

    /* Put the allocated socket pointer also to the entry allocated above 
       for fast back-referencing to the socket list. */
    id_entry->connection = (void *)server->sockets[sock[i]];
    server->id_entry = id_entry;
  }

  /* Register the task queues. In SILC we have by default three task queues. 
     One task queue for non-timeout tasks which perform different kind of 
     I/O on file descriptors, timeout task queue for timeout tasks, and,
     generic non-timeout task queue whose tasks apply to all connections. */
  silc_task_queue_alloc(&server->io_queue, TRUE);
  if (!server->io_queue) {
    goto err0;
  }
  silc_task_queue_alloc(&server->timeout_queue, TRUE);
  if (!server->timeout_queue) {
    goto err1;
  }
  silc_task_queue_alloc(&server->generic_queue, TRUE);
  if (!server->generic_queue) {
    goto err1;
  }

  /* Register protocols */
  silc_server_protocols_register();

  /* Initialize the scheduler */
  silc_schedule_init(&server->io_queue, &server->timeout_queue, 
		     &server->generic_queue, 
		     SILC_SERVER_MAX_CONNECTIONS);
  
  /* Add the first task to the queue. This is task that is executed by
     timeout. It expires as soon as the caller calls silc_server_run. This
     task performs authentication protocol and key exchange with our
     primary router. */
  silc_task_register(server->timeout_queue, sock[0], 
		     silc_server_connect_to_router,
		     (void *)server, 0, 1,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_NORMAL);

  /* Add listener task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  silc_task_register(server->io_queue, sock[0],
		     silc_server_accept_new_connection,
		     (void *)server, 0, 0, 
		     SILC_TASK_FD,
		     SILC_TASK_PRI_NORMAL);
  server->listenning = TRUE;

  /* If server connections has been configured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->config->servers)
    server->server_type = SILC_ROUTER;

  /* Register the ID Cache purge task. This periodically purges the ID cache
     and removes the expired cache entries. */

  /* Clients local list */
  purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->local_list->clients;
  purge->timeout_queue = server->timeout_queue;
  silc_task_register(purge->timeout_queue, 0, 
		     silc_idlist_purge,
		     (void *)purge, 600, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  /* Clients global list */
  purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->global_list->clients;
  purge->timeout_queue = server->timeout_queue;
  silc_task_register(purge->timeout_queue, 0, 
		     silc_idlist_purge,
		     (void *)purge, 300, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  SILC_LOG_DEBUG(("Server initialized"));

  /* We are done here, return succesfully */
  return TRUE;

  silc_task_queue_free(server->timeout_queue);
 err1:
  silc_task_queue_free(server->io_queue);
 err0:
  for (i = 0; i < sock_count; i++)
    silc_net_close_server(sock[i]);

  return FALSE;
}

/* Fork server to background and set gid+uid to non-root.
   Silcd will not run as root, so trying to set either user or group to
   root will cause silcd to exit. */

void silc_server_daemonise(SilcServer server)
{
  /* Are we executing silcd as root or a regular user? */
  if (geteuid()==0) {
    
    struct passwd *pw;
    struct group *gr;
    char *user, *group;
    
    if (!server->config->identity || !server->config->identity->user || 
	!server->config->identity->group) {
      fprintf(stderr, "Error:"
       "\tSILC server must not be run as root.  For the security of your\n"
       "\tsystem it is strongly suggested that you run SILC under dedicated\n"
       "\tuser account.  Modify the [Identity] configuration section to run\n"
       "\tthe server as non-root user.\n");
      exit(1);
    }
    
    /* Get the values given for user and group in configuration file */
    user=server->config->identity->user;
    group=server->config->identity->group;
    
    /* Check whether the user/group information is text */ 
    if (atoi(user)!=0 || atoi(group)!=0) {
      SILC_LOG_DEBUG(("Invalid user and/or group information"));
      SILC_LOG_DEBUG(("User and/or group given as number"));
      fprintf(stderr, "Invalid user and/or group information\n");
      fprintf(stderr, "Please assign them as names, not numbers\n");
      exit(1);
    }
    
    /* Catch the nasty incident of string "0" returning 0 from atoi */
    if (strcmp("0", user)==0 || strcmp("0", group)==0) {
      SILC_LOG_DEBUG(("User and/or group configured to 0. Unacceptable"));
      fprintf(stderr, "User and/or group configured to 0. Exiting\n");
      exit(1);
    }
    
    pw=getpwnam(user);
    gr=getgrnam(group);

    if (!pw) {
      fprintf(stderr, "No such user %s found\n", user);
      exit(1);
    }

    if (!gr) {
      fprintf(stderr, "No such group %s found\n", group);
      exit(1);
    }
    
    /* Check whether user and/or group is set to root. If yes, exit
       immediately. Otherwise, setgid and setuid server to user.group */
    if (gr->gr_gid==0 || pw->pw_uid==0) {
      fprintf(stderr, "Error:"
       "\tSILC server must not be run as root.  For the security of your\n"
       "\tsystem it is strongly suggested that you run SILC under dedicated\n"
       "\tuser account.  Modify the [Identity] configuration section to run\n"
       "\tthe server as non-root user.\n");
      exit(1);
    } else {
      /* Fork server to background, making it a daemon */
      if (fork()) {
        SILC_LOG_DEBUG(("Server started as root. Dropping privileges."));
        SILC_LOG_DEBUG(("Forking SILC server to background"));
        exit(0);
      } 
      setsid();
      
      SILC_LOG_DEBUG(("Changing to group %s", group));
      if(setgid(gr->gr_gid)==0) {
        SILC_LOG_DEBUG(("Setgid to %s", group));
      } else {
        SILC_LOG_DEBUG(("Setgid to %s failed", group));
        fprintf(stderr, "Tried to setgid %s but no such group. Exiting\n",
                group);
        exit(1);
      }
      SILC_LOG_DEBUG(("Changing to user nobody"));
      if(setuid(pw->pw_uid)==0) {
        SILC_LOG_DEBUG(("Setuid to %s", user));
      } else {
        SILC_LOG_DEBUG(("Setuid to %s failed", user));
        fprintf(stderr, "Tried to setuid %s but no such user. Exiting\n",
                user);
        exit(1);
      }
    }
  } else {
    /* Fork server to background, making it a daemon */
    if (fork()) {
      SILC_LOG_DEBUG(("Server started as user")); 
      SILC_LOG_DEBUG(("Forking SILC server to background"));
      exit(0);
    }
    setsid();
  }
}

/* Stops the SILC server. This function is used to shutdown the server. 
   This is usually called after the scheduler has returned. After stopping 
   the server one should call silc_server_free. */

void silc_server_stop(SilcServer server)
{
  SILC_LOG_DEBUG(("Stopping server"));

  /* Stop the scheduler, although it might be already stopped. This
     doesn't hurt anyone. This removes all the tasks and task queues,
     as well. */
  silc_schedule_stop();
  silc_schedule_uninit();

  silc_server_protocols_unregister();

  SILC_LOG_DEBUG(("Server stopped"));
}

/* The heart of the server. This runs the scheduler thus runs the server. 
   When this returns the server has been stopped and the program will
   be terminated. */

void silc_server_run(SilcServer server)
{
  SILC_LOG_DEBUG(("Running server"));

  /* Start the scheduler, the heart of the SILC server. When this returns
     the program will be terminated. */
  silc_schedule();
}

/* Timeout callback that will be called to retry connecting to remote
   router. This is used by both normal and router server. This will wait
   before retrying the connecting. The timeout is generated by exponential
   backoff algorithm. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_retry)
{
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServer server = sconn->server;

  SILC_LOG_INFO(("Retrying connecting to a router"));

  /* Calculate next timeout */
  if (sconn->retry_count >= 1) {
    sconn->retry_timeout = sconn->retry_timeout * SILC_SERVER_RETRY_MULTIPLIER;
    if (sconn->retry_timeout > SILC_SERVER_RETRY_INTERVAL_MAX)
      sconn->retry_timeout = SILC_SERVER_RETRY_INTERVAL_MAX;
  } else {
    sconn->retry_timeout = server->params->retry_interval_min;
  }
  sconn->retry_count++;
  sconn->retry_timeout = sconn->retry_timeout +
    silc_rng_get_rn32(server->rng) % SILC_SERVER_RETRY_RANDOMIZER;

  /* If we've reached max retry count, give up. */
  if (sconn->retry_count > server->params->retry_count && 
      server->params->retry_keep_trying == FALSE) {
    SILC_LOG_ERROR(("Could not connect to router, giving up"));
    return;
  }

  /* Wait one before retrying */
  silc_task_register(server->timeout_queue, fd, silc_server_connect_router,
		     context, sconn->retry_timeout, 
		     server->params->retry_interval_min_usec,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* Generic routine to use connect to a router. */

SILC_TASK_CALLBACK(silc_server_connect_router)
{    
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServer server = sconn->server;
  SilcSocketConnection newsocket;
  SilcProtocol protocol;
  SilcServerKEInternalContext *proto_ctx;
  int sock;

  SILC_LOG_INFO(("Connecting to the router %s on port %d", 
		 sconn->remote_host, sconn->remote_port));

  /* Connect to remote host */
  sock = silc_net_create_connection(sconn->remote_port, 
				    sconn->remote_host);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not connect to router"));
    silc_task_register(server->timeout_queue, fd, 
		       silc_server_connect_to_router_retry,
		       context, 0, 1, SILC_TASK_TIMEOUT, 
		       SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Create socket connection for the connection. Even though we
     know that we are connecting to a router we will mark the socket
     to be unknown connection until we have executed authentication
     protocol. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;
  newsocket->hostname = strdup(sconn->remote_host);
  newsocket->ip = strdup(sconn->remote_host);
  newsocket->port = sconn->remote_port;
  sconn->sock = newsocket;

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->context = (void *)sconn;
  proto_ctx->sock = newsocket;
  proto_ctx->rng = server->rng;
  proto_ctx->responder = FALSE;
      
  /* Perform key exchange protocol. silc_server_connect_to_router_second
     will be called after the protocol is finished. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE, 
		      &protocol, proto_ctx,
		      silc_server_connect_to_router_second);
  newsocket->protocol = protocol;
      
  /* Register a timeout task that will be executed if the protocol
     is not executed within set limit. */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock, 
		       silc_server_timeout_remote,
		       server, server->params->protocol_timeout,
		       server->params->protocol_timeout_usec,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as 
     well. However, this doesn't set the scheduler for outgoing traffic,
     it will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)server;
  SILC_REGISTER_CONNECTION_FOR_IO(sock);
  
  /* Run the protocol */
  protocol->execute(server->timeout_queue, 0, protocol, sock, 0, 0);
}
  
/* This function connects to our primary router or if we are a router this
   establishes all our primary routes. This is called at the start of the
   server to do authentication and key exchange with our router - called
   from schedule. */

SILC_TASK_CALLBACK(silc_server_connect_to_router)
{
  SilcServer server = (SilcServer)context;
  SilcServerConnection sconn;

  SILC_LOG_DEBUG(("Connecting to router(s)"));

  /* If we are normal SILC server we need to connect to our cell's
     router. */
  if (server->server_type == SILC_SERVER) {
    SILC_LOG_DEBUG(("We are normal server"));

    /* Create connection to the router, if configured. */
    if (server->config->routers) {

      /* Allocate connection object for hold connection specific stuff. */
      sconn = silc_calloc(1, sizeof(*sconn));
      sconn->server = server;
      sconn->remote_host = strdup(server->config->routers->host);
      sconn->remote_port = server->config->routers->port;

      silc_task_register(server->timeout_queue, fd, 
			 silc_server_connect_router,
			 (void *)sconn, 0, 1, SILC_TASK_TIMEOUT, 
			 SILC_TASK_PRI_NORMAL);
      return;
    }
  }

  /* If we are a SILC router we need to establish all of our primary
     routes. */
  if (server->server_type == SILC_ROUTER) {
    SilcServerConfigSectionServerConnection *ptr;

    SILC_LOG_DEBUG(("We are router"));

    /* Create the connections to all our routes */
    ptr = server->config->routers;
    while (ptr) {

      SILC_LOG_DEBUG(("Router connection [%s] %s:%d",
		      ptr->initiator ? "Initiator" : "Responder",
		      ptr->host, ptr->port));

      if (ptr->initiator) {
	/* Allocate connection object for hold connection specific stuff. */
	sconn = silc_calloc(1, sizeof(*sconn));
	sconn->server = server;
	sconn->remote_host = strdup(ptr->host);
	sconn->remote_port = ptr->port;

	silc_task_register(server->timeout_queue, fd, 
			   silc_server_connect_router,
			   (void *)sconn, 0, 1, SILC_TASK_TIMEOUT, 
			   SILC_TASK_PRI_NORMAL);
      }

      if (!ptr->next)
	return;

      ptr = ptr->next;
    }
  }

  SILC_LOG_DEBUG(("No router(s), server will be standalone"));
  
  /* There wasn't a configured router, we will continue but we don't
     have a connection to outside world.  We will be standalone server. */
  server->standalone = TRUE;
}

/* Second part of connecting to router(s). Key exchange protocol has been
   executed and now we will execute authentication protocol. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcServerConnection sconn = (SilcServerConnection)ctx->context;
  SilcSocketConnection sock = server->sockets[fd];
  SilcServerConnAuthInternalContext *proto_ctx;
  SilcServerConfigSectionServerConnection *conn = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    return;
  }
  
  /* We now have the key material as the result of the key exchange
     protocol. Take the key material into use. Free the raw key material
     as soon as we've set them into use. */
  if (!silc_server_protocol_ke_set_keys(ctx->ske, ctx->sock, ctx->keymat,
					ctx->ske->prop->cipher,
					ctx->ske->prop->pkcs,
					ctx->ske->prop->hash,
					ctx->ske->prop->hmac,
					ctx->ske->prop->group,
					ctx->responder)) {
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    return;
  }    
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->context = (void *)sconn;
  proto_ctx->sock = sock;
  proto_ctx->ske = ctx->ske;	   /* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Resolve the authentication method used in this connection. Check if 
     we find a match from user configured connections */
  conn = silc_server_config_find_router_conn(server->config,
					     sock->hostname,
					     sock->port);
  if (conn) {
    /* Match found. Use the configured authentication method */
    proto_ctx->auth_meth = conn->auth_meth;
    if (conn->auth_data) {
      proto_ctx->auth_data = strdup(conn->auth_data);
      proto_ctx->auth_data_len = strlen(conn->auth_data);
    }
  } else {
    SILC_LOG_ERROR(("Could not find connection data for %s (%s) on port",
		    sock->hostname, sock->ip, sock->port));
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    return;
  }

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  sock->protocol = NULL;

  /* Allocate the authentication protocol. This is allocated here
     but we won't start it yet. We will be receiving party of this
     protocol thus we will wait that connecting party will make
     their first move. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_CONNECTION_AUTH, 
		      &sock->protocol, proto_ctx, 
		      silc_server_connect_to_router_final);

  /* Register timeout task. If the protocol is not executed inside
     this timelimit the connection will be terminated. Currently
     this is 15 seconds and is hard coded limit (XXX). */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock->sock, 
		       silc_server_timeout_remote,
		       (void *)server, 15, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);

  /* Run the protocol */
  sock->protocol->execute(server->timeout_queue, 0, 
			  sock->protocol, sock->sock, 0, 0);
}

/* Finalizes the connection to router. Registers a server task to the
   queue so that we can accept new connections. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerConnAuthInternalContext *ctx = 
    (SilcServerConnAuthInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcServerConnection sconn = (SilcServerConnection)ctx->context;
  SilcSocketConnection sock = ctx->sock;
  SilcServerEntry id_entry;
  SilcBuffer packet;
  SilcServerHBContext hb_context;
  unsigned char *id_string;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    goto out;
  }

  /* Add a task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  if (!server->listenning) {
    silc_task_register(server->io_queue, server->sock, 
		       silc_server_accept_new_connection,
		       (void *)server, 0, 0, 
		       SILC_TASK_FD,
		       SILC_TASK_PRI_NORMAL);
    server->listenning = TRUE;
  }

  /* Send NEW_SERVER packet to the router. We will become registered
     to the SILC network after sending this packet. */
  id_string = silc_id_id2str(server->id, SILC_ID_SERVER);
  packet = silc_buffer_alloc(2 + 2 + SILC_ID_SERVER_LEN + 
			     strlen(server->server_name));
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_ID_SERVER_LEN),
		     SILC_STR_UI_XNSTRING(id_string, SILC_ID_SERVER_LEN),
		     SILC_STR_UI_SHORT(strlen(server->server_name)),
		     SILC_STR_UI_XNSTRING(server->server_name,
					  strlen(server->server_name)),
		     SILC_STR_END);

  /* Send the packet */
  silc_server_packet_send(server, ctx->sock, SILC_PACKET_NEW_SERVER, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
  silc_free(id_string);

  SILC_LOG_DEBUG(("Connected to router %s", sock->hostname));

  /* Add the connected router to local server list */
  server->standalone = FALSE;
  id_entry = silc_idlist_add_server(server->local_list, strdup(sock->hostname),
				    SILC_ROUTER, ctx->dest_id, NULL, sock);
  if (!id_entry) {
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    goto out;
  }

  silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);
  silc_free(sock->user_data);
  sock->user_data = (void *)id_entry;
  sock->type = SILC_SOCKET_TYPE_ROUTER;
  server->id_entry->router = id_entry;
  server->router = id_entry;
  idata = (SilcIDListData)sock->user_data;
  idata->registered = TRUE;

  /* Perform keepalive. The `hb_context' will be freed automatically
     when finally calling the silc_socket_free function. XXX hardcoded 
     timeout!! */
  hb_context = silc_calloc(1, sizeof(*hb_context));
  hb_context->server = server;
  silc_socket_set_heartbeat(sock, 600, hb_context,
			    silc_server_perform_heartbeat,
			    server->timeout_queue);

  /* Register re-key timeout */
  idata->rekey->timeout = 3600; /* XXX hardcoded */
  idata->rekey->context = (void *)server;
  silc_task_register(server->timeout_queue, sock->sock, 
		     silc_server_rekey_callback,
		     (void *)sock, idata->rekey->timeout, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  /* If we are router then announce our possible servers. */
  if (server->server_type == SILC_ROUTER)
    silc_server_announce_servers(server);

  /* Announce our clients and channels to the router */
  silc_server_announce_clients(server);
  silc_server_announce_channels(server);

 out:
  /* Free the temporary connection data context */
  if (sconn) {
    silc_free(sconn->remote_host);
    silc_free(sconn);
  }

  /* Free the protocol object */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
  sock->protocol = NULL;
}

/* Accepts new connections to the server. Accepting new connections are
   done in three parts to make it async. */

SILC_TASK_CALLBACK(silc_server_accept_new_connection)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection newsocket;
  SilcServerKEInternalContext *proto_ctx;
  int sock, port;
  void *cconfig, *sconfig, *rconfig;
  SilcServerConfigSectionDenyConnection *deny;

  SILC_LOG_DEBUG(("Accepting new connection"));

  server->stat.conn_attempts++;

  sock = silc_net_accept_connection(server->sock);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not accept new connection: %s", strerror(errno)));
    server->stat.conn_failures++;
    return;
  }

  /* Check max connections */
  if (sock > SILC_SERVER_MAX_CONNECTIONS) {
    SILC_LOG_ERROR(("Refusing connection, server is full"));
    server->stat.conn_failures++;
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* We don't create a ID yet, since we don't know what type of connection
     this is yet. But, we do add the connection to the socket table. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;

  /* XXX This MUST be done async as this will block the entire server
     process. Either we have to do our own resolver stuff or in the future
     we can use threads. */
  /* Perform name and address lookups for the remote host. */
  if (!silc_net_check_host_by_sock(sock, &newsocket->hostname, 
				   &newsocket->ip)) {
    if ((server->params->require_reverse_mapping && !newsocket->hostname) ||
	!newsocket->ip) {
      SILC_LOG_ERROR(("IP/DNS lookup failed %s",
		      newsocket->hostname ? newsocket->hostname :
		      newsocket->ip ? newsocket->ip : ""));
      server->stat.conn_failures++;
      return;
    }
    if (!newsocket->hostname)
      newsocket->hostname = strdup(newsocket->ip);
  }
  newsocket->port = silc_net_get_remote_port(sock);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it
     will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  SILC_REGISTER_CONNECTION_FOR_IO(sock);

  port = server->sockets[fd]->port; /* Listenning port */

  /* Check whether this connection is denied to connect to us. */
  deny = silc_server_config_denied_conn(server->config, newsocket->ip, port);
  if (!deny)
    deny = silc_server_config_denied_conn(server->config, newsocket->hostname,
					  port);
  if (deny) {
    /* The connection is denied */
    silc_server_disconnect_remote(server, newsocket, deny->comment ?
				  deny->comment :
				  "Server closed connection: "
				  "Connection refused");
    server->stat.conn_failures++;
    return;
  }

  /* Check whether we have configred this sort of connection at all. We
     have to check all configurations since we don't know what type of
     connection this is. */
  if (!(cconfig = silc_server_config_find_client_conn(server->config,
						      newsocket->ip, port)))
    cconfig = silc_server_config_find_client_conn(server->config,
						  newsocket->hostname, 
						  port);
  if (!(sconfig = silc_server_config_find_server_conn(server->config,
						     newsocket->ip, 
						     port)))
    sconfig = silc_server_config_find_server_conn(server->config,
						  newsocket->hostname,
						  port);
  if (!(rconfig = silc_server_config_find_router_conn(server->config,
						     newsocket->ip, port)))
    rconfig = silc_server_config_find_router_conn(server->config,
						  newsocket->hostname, 
						  port);
  if (!cconfig && !sconfig && !rconfig) {
    silc_server_disconnect_remote(server, newsocket, 
				  "Server closed connection: "
				  "Connection refused");
    server->stat.conn_failures++;
    return;
  }

  /* The connection is allowed */

  SILC_LOG_INFO(("Incoming connection from %s (%s)", newsocket->hostname,
		 newsocket->ip));

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = context;
  proto_ctx->sock = newsocket;
  proto_ctx->rng = server->rng;
  proto_ctx->responder = TRUE;
  proto_ctx->cconfig = cconfig;
  proto_ctx->sconfig = sconfig;
  proto_ctx->rconfig = rconfig;

  /* Prepare the connection for key exchange protocol. We allocate the
     protocol but will not start it yet. The connector will be the
     initiator of the protocol thus we will wait for initiation from 
     there before we start the protocol. */
  server->stat.auth_attempts++;
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE, 
		      &newsocket->protocol, proto_ctx, 
		      silc_server_accept_new_connection_second);

  /* Register a timeout task that will be executed if the connector
     will not start the key exchange protocol within 60 seconds. For
     now, this is a hard coded limit. After 60 secs the connection will
     be closed if the key exchange protocol has not been started. */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, newsocket->sock, 
		       silc_server_timeout_remote,
		       context, 60, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);
}

/* Second part of accepting new connection. Key exchange protocol has been
   performed and now it is time to do little connection authentication
   protocol to figure out whether this connection is client or server
   and whether it has right to access this server (especially server
   connections needs to be authenticated). */

SILC_TASK_CALLBACK(silc_server_accept_new_connection_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = server->sockets[fd];
  SilcServerConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    server->stat.auth_failures++;
    return;
  }

  /* We now have the key material as the result of the key exchange
     protocol. Take the key material into use. Free the raw key material
     as soon as we've set them into use. */
  if (!silc_server_protocol_ke_set_keys(ctx->ske, ctx->sock, ctx->keymat,
					ctx->ske->prop->cipher,
					ctx->ske->prop->pkcs,
					ctx->ske->prop->hash,
					ctx->ske->prop->hmac,
					ctx->ske->prop->group,
					ctx->responder)) {
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    server->stat.auth_failures++;
    return;
  }    
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock;
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->responder = TRUE;
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;
  proto_ctx->cconfig = ctx->cconfig;
  proto_ctx->sconfig = ctx->sconfig;
  proto_ctx->rconfig = ctx->rconfig;

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  sock->protocol = NULL;

  /* Allocate the authentication protocol. This is allocated here
     but we won't start it yet. We will be receiving party of this
     protocol thus we will wait that connecting party will make
     their first move. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_CONNECTION_AUTH, 
		      &sock->protocol, proto_ctx, 
		      silc_server_accept_new_connection_final);

  /* Register timeout task. If the protocol is not executed inside
     this timelimit the connection will be terminated. Currently
     this is 60 seconds and is hard coded limit (XXX). */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock->sock, 
		       silc_server_timeout_remote,
		       (void *)server, 60, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);
}

/* Final part of accepting new connection. The connection has now
   been authenticated and keys has been exchanged. We also know whether
   this is client or server connection. */

SILC_TASK_CALLBACK(silc_server_accept_new_connection_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerConnAuthInternalContext *ctx = 
    (SilcServerConnAuthInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = ctx->sock;
  SilcServerHBContext hb_context;
  void *id_entry = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    if (sock)
      sock->protocol = NULL;
    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_failure_callback);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    server->stat.auth_failures++;
    return;
  }

  sock->type = ctx->conn_type;
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry client;

      SILC_LOG_DEBUG(("Remote host is client"));
      SILC_LOG_INFO(("Connection from %s (%s) is client", sock->hostname,
		     sock->ip));

      /* Add the client to the client ID cache. The nickname and Client ID
	 and other information is created after we have received NEW_CLIENT
	 packet from client. */
      client = silc_idlist_add_client(server->local_list, 
				      NULL, 0, NULL, NULL, NULL, NULL, sock);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to cache"));
	silc_free(sock->user_data);
	break;
      }

      /* Statistics */
      server->stat.my_clients++;
      server->stat.clients++;
      if (server->server_type == SILC_ROUTER)
	server->stat.cell_clients++;

      id_entry = (void *)client;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry new_server;
      SilcServerConfigSectionServerConnection *conn = 
	sock->type == SILC_SOCKET_TYPE_SERVER ? ctx->sconfig : ctx->rconfig;

      SILC_LOG_DEBUG(("Remote host is %s", 
		      sock->type == SILC_SOCKET_TYPE_SERVER ? 
		      "server" : "router"));
      SILC_LOG_INFO(("Connection from %s (%s) is %s", sock->hostname,
		     sock->ip, sock->type == SILC_SOCKET_TYPE_SERVER ? 
		     "server" : "router"));

      /* Add the server into server cache. The server name and Server ID
	 is updated after we have received NEW_SERVER packet from the
	 server. We mark ourselves as router for this server if we really
	 are router. */
      new_server = 
	silc_idlist_add_server(server->local_list, NULL,
			       sock->type == SILC_SOCKET_TYPE_SERVER ?
			       SILC_SERVER : SILC_ROUTER, NULL, 
			       sock->type == SILC_SOCKET_TYPE_SERVER ?
			       server->id_entry : NULL, sock);
      if (!new_server) {
	SILC_LOG_ERROR(("Could not add new server to cache"));
	silc_free(sock->user_data);
	break;
      }

      /* Statistics */
      if (sock->type == SILC_SOCKET_TYPE_SERVER)
	server->stat.my_servers++;
      else
	server->stat.my_routers++;
      server->stat.servers++;

      id_entry = (void *)new_server;

      /* Check whether this connection is to be our primary router connection
	 if we dont' already have the primary route. */
      if (server->standalone && sock->type == SILC_SOCKET_TYPE_ROUTER) {
	if (silc_server_config_is_primary_route(server->config) &&
	    !conn->initiator)
	  break;

	SILC_LOG_DEBUG(("We are not standalone server anymore"));
	server->standalone = FALSE;
	if (!server->id_entry->router) {
	  server->id_entry->router = id_entry;
	  server->router = id_entry;
	}
      }

      break;
    }
  default:
    break;
  }

  /* Add the common data structure to the ID entry. */
  if (id_entry)
    silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);
      
  /* Add to sockets internal pointer for fast referencing */
  silc_free(sock->user_data);
  sock->user_data = id_entry;

  /* Connection has been fully established now. Everything is ok. */
  SILC_LOG_DEBUG(("New connection authenticated"));

  /* Perform keepalive. The `hb_context' will be freed automatically
     when finally calling the silc_socket_free function. XXX hardcoded 
     timeout!! */
  hb_context = silc_calloc(1, sizeof(*hb_context));
  hb_context->server = server;
  silc_socket_set_heartbeat(sock, 600, hb_context,
			    silc_server_perform_heartbeat,
			    server->timeout_queue);

  silc_task_unregister_by_callback(server->timeout_queue,
				   silc_server_failure_callback);
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->dest_id)
    silc_free(ctx->dest_id);
  silc_free(ctx);
  sock->protocol = NULL;
}

/* This function is used to read packets from network and send packets to
   network. This is usually a generic task. */

SILC_TASK_CALLBACK(silc_server_packet_process)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  int ret;

  if (!sock)
    return;

  SILC_LOG_DEBUG(("Processing packet"));

  /* Packet sending */

  if (type == SILC_TASK_WRITE) {
    /* Do not send data to disconnected connection */
    if (SILC_IS_DISCONNECTED(sock))
      return;

    server->stat.packets_sent++;

    if (sock->outbuf->data - sock->outbuf->head)
     silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    /* Send the packet */
    ret = silc_packet_send(sock, TRUE);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;

    if (ret == -1)
      return;
    
    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data 
       available for this connection it will be set for output as well. 
       This call clears the output setting and sets it only for input. */
    SILC_SET_CONNECTION_FOR_INPUT(fd);
    SILC_UNSET_OUTBUF_PENDING(sock);

    silc_buffer_clear(sock->outbuf);
    return;
  }

  /* Packet receiving */

  /* Read some data from connection */
  ret = silc_packet_receive(sock);
  if (ret < 0)
    return;
    
  /* EOF */
  if (ret == 0) {
    SILC_LOG_DEBUG(("Read EOF"));
      
    /* If connection is disconnecting already we will finally
       close the connection */
    if (SILC_IS_DISCONNECTING(sock)) {
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock);
      silc_server_close_connection(server, sock);
      return;
    }
      
    SILC_LOG_DEBUG(("Premature EOF from connection %d", sock->sock));
    SILC_SET_DISCONNECTING(sock);

    /* If the closed connection was our primary router connection the
       start re-connecting phase. */
    if (!server->standalone && sock->type == SILC_SOCKET_TYPE_ROUTER && 
	sock == server->router->connection)
      silc_task_register(server->timeout_queue, 0, 
			 silc_server_connect_to_router,
			 context, 1, 0,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);

    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock);
    silc_server_close_connection(server, sock);
    return;
  }

  /* If connection is disconnecting or disconnected we will ignore
     what we read. */
  if (SILC_IS_DISCONNECTING(sock) || SILC_IS_DISCONNECTED(sock)) {
    SILC_LOG_DEBUG(("Ignoring read data from disonnected connection"));
    return;
  }

  server->stat.packets_received++;

  /* Get keys and stuff from ID entry */
  idata = (SilcIDListData)sock->user_data;
  if (idata) {
    idata->last_receive = time(NULL);
    cipher = idata->receive_key;
    hmac = idata->hmac_receive;
  }
 
  /* Process the packet. This will call the parser that will then
     decrypt and parse the packet. */
  silc_packet_receive_process(sock, cipher, hmac, silc_server_packet_parse, 
			      server);
}

/* Callback function that the silc_packet_decrypt will call to make the
   decision whether the packet is normal or special packet. We will 
   return TRUE if it is normal and FALSE if it is special */

static int silc_server_packet_decrypt_check(SilcPacketType packet_type,
					    SilcBuffer buffer,
					    SilcPacketContext *packet,
					    void *context)
{
  SilcPacketParserContext *parse_ctx = (SilcPacketParserContext *)context;
  SilcServer server = (SilcServer)parse_ctx->context;

  /* Packet is normal packet, if: 

     1) packet is private message packet and does not have private key set
     2) is other packet than channel message packet
     3) is channel message packet and remote is router and we are router 

     all other packets are special packets 
  */

  if (packet_type == SILC_PACKET_PRIVATE_MESSAGE &&
      (buffer->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
    return FALSE;

  if (packet_type != SILC_PACKET_CHANNEL_MESSAGE || 
      (packet_type == SILC_PACKET_CHANNEL_MESSAGE &&
       parse_ctx->sock->type == SILC_SOCKET_TYPE_ROUTER &&
       server->server_type == SILC_ROUTER))
    return TRUE;

  return FALSE;
}
  
/* Parses whole packet, received earlier. */

SILC_TASK_CALLBACK(silc_server_packet_parse_real)
{
  SilcPacketParserContext *parse_ctx = (SilcPacketParserContext *)context;
  SilcServer server = (SilcServer)parse_ctx->context;
  SilcSocketConnection sock = parse_ctx->sock;
  SilcPacketContext *packet = parse_ctx->packet;
  SilcIDListData idata = (SilcIDListData)sock->user_data;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt the received packet */
  ret = silc_packet_decrypt(idata ? idata->receive_key : NULL, 
			    idata ? idata->hmac_receive : NULL, 
			    packet->buffer, packet,
			    silc_server_packet_decrypt_check, parse_ctx);
  if (ret < 0)
    goto out;

  if (ret == 0) {
    /* Parse the packet. Packet type is returned. */
    ret = silc_packet_parse(packet);
  } else {
    /* Parse the packet header in special way as this is "special"
       packet type. */
    ret = silc_packet_parse_special(packet);
  }

  if (ret == SILC_PACKET_NONE)
    goto out;

  /* Check that the the current client ID is same as in the client's packet. */
  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)sock->user_data;
    if (client && client->id) {
      void *id = silc_id_str2id(packet->src_id, packet->src_id_len,
				packet->src_id_type);
      if (!id || SILC_ID_CLIENT_COMPARE(client->id, id)) {
	silc_free(id);
	goto out;
      }
      silc_free(id);
    }
  }

  if (server->server_type == SILC_ROUTER) {
    /* Route the packet if it is not destined to us. Other ID types but
       server are handled separately after processing them. */
    if (!(packet->flags & SILC_PACKET_FLAG_BROADCAST) &&
	packet->dst_id_type == SILC_ID_SERVER && 
	sock->type != SILC_SOCKET_TYPE_CLIENT &&
	SILC_ID_SERVER_COMPARE(packet->dst_id, server->id_string)) {
      
      /* Route the packet to fastest route for the destination ID */
      void *id = silc_id_str2id(packet->dst_id, packet->dst_id_len, 
				packet->dst_id_type);
      if (!id)
	goto out;
      silc_server_packet_route(server,
			       silc_server_route_get(server, id,
						     packet->dst_id_type),
			       packet);
      silc_free(id);
      goto out;
    }
  }

  /* Parse the incoming packet type */
  silc_server_packet_parse_type(server, sock, packet);

  if (server->server_type == SILC_ROUTER) {
    /* Broadcast packet if it is marked as broadcast packet and it is
       originated from router and we are router. */
    if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
	packet->flags & SILC_PACKET_FLAG_BROADCAST &&
	!server->standalone) {
      silc_server_packet_broadcast(server, server->router->connection, packet);
    }
  }

 out:
  /*  silc_buffer_clear(sock->inbuf); */
  silc_packet_context_free(packet);
  silc_free(parse_ctx);
}

/* Parser callback called by silc_packet_receive_process. This merely
   registers timeout that will handle the actual parsing when appropriate. */

void silc_server_packet_parse(SilcPacketParserContext *parser_context)
{
  SilcServer server = (SilcServer)parser_context->context;
  SilcSocketConnection sock = parser_context->sock;

  switch (sock->type) {
  case SILC_SOCKET_TYPE_UNKNOWN:
  case SILC_SOCKET_TYPE_CLIENT:
    /* Parse the packet with timeout */
    silc_task_register(server->timeout_queue, sock->sock,
		       silc_server_packet_parse_real,
		       (void *)parser_context, 0, 100000,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    /* Packets from servers are parsed as soon as possible */
    silc_task_register(server->timeout_queue, sock->sock,
		       silc_server_packet_parse_real,
		       (void *)parser_context, 0, 1,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
    break;
  default:
    return;
  }
}

/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet)
{
  SilcPacketType type = packet->type;

  SILC_LOG_DEBUG(("Parsing packet type %d", type));

  /* Parse the packet type */
  switch(type) {
  case SILC_PACKET_DISCONNECT:
    SILC_LOG_DEBUG(("Disconnect packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    break;

  case SILC_PACKET_SUCCESS:
    /*
     * Success received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * success message is for whatever protocol is executing currently.
     */
    SILC_LOG_DEBUG(("Success packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    if (sock->protocol) {
      sock->protocol->execute(server->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;

  case SILC_PACKET_FAILURE:
    /*
     * Failure received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * failure message is for whatever protocol is executing currently.
     */
    SILC_LOG_DEBUG(("Failure packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    if (sock->protocol) {
      SilcServerFailureContext f;
      f = silc_calloc(1, sizeof(*f));
      f->server = server;
      f->sock = sock;
      
      /* We will wait 5 seconds to process this failure packet */
      silc_task_register(server->timeout_queue, sock->sock,
			 silc_server_failure_callback, (void *)f, 5, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    }
    break;

  case SILC_PACKET_REJECT:
    SILC_LOG_DEBUG(("Reject packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    return;
    break;

  case SILC_PACKET_NOTIFY:
    /*
     * Received notify packet. Server can receive notify packets from
     * router. Server then relays the notify messages to clients if needed.
     */
    SILC_LOG_DEBUG(("Notify packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_notify_list(server, sock, packet);
    else
      silc_server_notify(server, sock, packet);
    break;

    /* 
     * Channel packets
     */
  case SILC_PACKET_CHANNEL_MESSAGE:
    /*
     * Received channel message. Channel messages are special packets
     * (although probably most common ones) thus they are handled
     * specially.
     */
    SILC_LOG_DEBUG(("Channel Message packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_channel_message(server, sock, packet);
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for channel. As channels are created by the router
     * the keys are as well. We will distribute the key to all of our
     * locally connected clients on the particular channel. Router
     * never receives this channel and thus is ignored.
     */
    SILC_LOG_DEBUG(("Channel Key packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_channel_key(server, sock, packet);
    break;

    /*
     * Command packets
     */
  case SILC_PACKET_COMMAND:
    /*
     * Recived command. Processes the command request and allocates the
     * command context and calls the command.
     */
    SILC_LOG_DEBUG(("Command packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_command_process(server, sock, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Received command reply packet. Received command reply to command. It
     * may be reply to command sent by us or reply to command sent by client
     * that we've routed further.
     */
    SILC_LOG_DEBUG(("Command Reply packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_command_reply(server, sock, packet);
    break;

    /*
     * Private Message packets
     */
  case SILC_PACKET_PRIVATE_MESSAGE:
    /*
     * Received private message packet. The packet is coming from either
     * client or server.
     */
    SILC_LOG_DEBUG(("Private Message packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_private_message(server, sock, packet);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Private message key packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_private_message_key(server, sock, packet);
    break;

    /*
     * Key Exchange protocol packets
     */
  case SILC_PACKET_KEY_EXCHANGE:
    SILC_LOG_DEBUG(("KE packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE) {

      SilcServerKEInternalContext *proto_ctx = 
	(SilcServerKEInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));

      /* XXX Trigger KE protocol?? Rekey actually, maybe. */
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_1:
    SILC_LOG_DEBUG(("KE 1 packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	(sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {
	SilcServerRekeyInternalContext *proto_ctx = 
	  (SilcServerRekeyInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	sock->protocol->execute(server->timeout_queue, 0, 
				sock->protocol, sock->sock, 0, 0);
      } else {
	SilcServerKEInternalContext *proto_ctx = 
	  (SilcServerKEInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;

	/* Let the protocol handle the packet */
	sock->protocol->execute(server->timeout_queue, 0, 
				sock->protocol, sock->sock,
				0, 100000);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_2:
    SILC_LOG_DEBUG(("KE 2 packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	(sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {
	SilcServerRekeyInternalContext *proto_ctx = 
	  (SilcServerRekeyInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	sock->protocol->execute(server->timeout_queue, 0, 
				sock->protocol, sock->sock, 0, 0);
      } else {
	SilcServerKEInternalContext *proto_ctx = 
	  (SilcServerKEInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;

	/* Let the protocol handle the packet */
	sock->protocol->execute(server->timeout_queue, 0, 
				sock->protocol, sock->sock,
				0, 100000);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 2 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /*
     * Connection authentication request packet. When we receive this packet
     * we will send to the other end information about our mandatory
     * authentication method for the connection. This packet maybe received
     * at any time. 
     */
    SILC_LOG_DEBUG(("Connection authentication request packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_connection_auth_request(server, sock, packet);
    break;

    /*
     * Connection Authentication protocol packets
     */
  case SILC_PACKET_CONNECTION_AUTH:
    /* Start of the authentication protocol. We receive here the 
       authentication data and will verify it. */
    SILC_LOG_DEBUG(("Connection auth packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol->type 
	== SILC_PROTOCOL_SERVER_CONNECTION_AUTH) {

      SilcServerConnAuthInternalContext *proto_ctx = 
	(SilcServerConnAuthInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Connection Auth packet but no authentication "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_NEW_ID:
    /*
     * Received New ID packet. This includes some new ID that has been
     * created. It may be for client, server or channel. This is the way
     * to distribute information about new registered entities in the
     * SILC network.
     */
    SILC_LOG_DEBUG(("New ID packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_id_list(server, sock, packet);
    else
      silc_server_new_id(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CLIENT:
    /*
     * Received new client packet. This includes client information that
     * we will use to create initial client ID. After creating new
     * ID we will send it to the client.
     */
    SILC_LOG_DEBUG(("New Client packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_client(server, sock, packet);
    break;

  case SILC_PACKET_NEW_SERVER:
    /*
     * Received new server packet. This includes Server ID and some other
     * information that we may save. This is received after server has 
     * connected to us.
     */
    SILC_LOG_DEBUG(("New Server packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_server(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL:
    /*
     * Received new channel packet. Information about new channel in the
     * network are distributed using this packet.
     */
    SILC_LOG_DEBUG(("New Channel packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_channel_list(server, sock, packet);
    else
      silc_server_new_channel(server, sock, packet);
    break;

  case SILC_PACKET_HEARTBEAT:
    /*
     * Received heartbeat.
     */
    SILC_LOG_DEBUG(("Heartbeat packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /*
     * Received heartbeat.
     */
    SILC_LOG_DEBUG(("Key agreement packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_key_agreement(server, sock, packet);
    break;

  case SILC_PACKET_REKEY:
    /*
     * Received re-key packet. The sender wants to regenerate the session
     * keys.
     */
    SILC_LOG_DEBUG(("Re-key packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_rekey(server, sock, packet);
    break;

  case SILC_PACKET_REKEY_DONE:
    /*
     * The re-key is done.
     */
    SILC_LOG_DEBUG(("Re-key done packet"));
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {

      SilcServerRekeyInternalContext *proto_ctx = 
	(SilcServerRekeyInternalContext *)sock->protocol->context;

      if (proto_ctx->packet)
	silc_packet_context_free(proto_ctx->packet);

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Re-key done packet but no re-key "
		      "protocol active, packet dropped."));
    }
    break;

  default:
    SILC_LOG_ERROR(("Incorrect packet type %d, packet dropped", type));
    break;
  }
  
}

/* Creates connection to a remote router. */

void silc_server_create_connection(SilcServer server,
				   char *remote_host, uint32 port)
{
  SilcServerConnection sconn;

  /* Allocate connection object for hold connection specific stuff. */
  sconn = silc_calloc(1, sizeof(*sconn));
  sconn->server = server;
  sconn->remote_host = strdup(remote_host);
  sconn->remote_port = port;

  silc_task_register(server->timeout_queue, 0, 
		     silc_server_connect_router,
		     (void *)sconn, 0, 1, SILC_TASK_TIMEOUT, 
		     SILC_TASK_PRI_NORMAL);
}

SILC_TASK_CALLBACK(silc_server_close_connection_final)
{
  silc_socket_free((SilcSocketConnection)context);
}

/* Closes connection to socket connection */

void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock)
{
  SILC_LOG_INFO(("Closing connection %s:%d [%s] (%d)", sock->hostname,
		 sock->port,  
		 (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		  sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		  sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		  "Router"), sock->sock));

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(sock->sock);

  /* Unregister all tasks */
  silc_task_unregister_by_fd(server->io_queue, sock->sock);
  silc_task_unregister_by_fd(server->timeout_queue, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);
  server->sockets[sock->sock] = NULL;

  silc_task_register(server->timeout_queue, 0, 
		     silc_server_close_connection_final,
		     (void *)sock, 0, 1, SILC_TASK_TIMEOUT, 
		     SILC_TASK_PRI_NORMAL);
}

/* Sends disconnect message to remote connection and disconnects the 
   connection. */

void silc_server_disconnect_remote(SilcServer server,
				   SilcSocketConnection sock,
				   const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  if (!sock)
    return;

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  SILC_LOG_DEBUG(("Disconnecting remote host"));

  SILC_LOG_INFO(("Disconnecting %s:%d [%s]", sock->hostname,
                  sock->port,
                  (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
                   sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
                   sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
                   "Router")));

  /* Notify remote end that the conversation is over. The notify message
     is tried to be sent immediately. */
  silc_server_packet_send(server, sock, SILC_PACKET_DISCONNECT, 0,  
			  buf, strlen(buf), TRUE);

  /* Mark the connection to be disconnected */
  SILC_SET_DISCONNECTED(sock);
  silc_server_close_connection(server, sock);
}

typedef struct {
  SilcServer server;
  SilcClientEntry client;
} *FreeClientInternal;

SILC_TASK_CALLBACK(silc_server_free_client_data_timeout)
{
  FreeClientInternal i = (FreeClientInternal)context;

  silc_idlist_del_data(i->client);
  silc_idcache_purge_by_context(i->server->local_list->clients, i->client);
  silc_free(i);
}

/* Frees client data and notifies about client's signoff. */

void silc_server_free_client_data(SilcServer server, 
				  SilcSocketConnection sock,
				  SilcClientEntry client, 
				  int notify,
				  char *signoff)
{
  FreeClientInternal i = silc_calloc(1, sizeof(*i));

  /* If there is pending outgoing data for the client then purge it
     to the network before removing the client entry. */
  if (sock && SILC_IS_OUTBUF_PENDING(sock) && 
      (SILC_IS_DISCONNECTED(sock) == FALSE)) {
    server->stat.packets_sent++;

    if (sock->outbuf->data - sock->outbuf->head)
     silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    silc_packet_send(sock, TRUE);

    SILC_SET_CONNECTION_FOR_INPUT(sock->sock);
    SILC_UNSET_OUTBUF_PENDING(sock);
    silc_buffer_clear(sock->outbuf);
  }

  /* Send SIGNOFF notify to routers. */
  if (notify && !server->standalone && server->router)
    silc_server_send_notify_signoff(server, server->router->connection,
				    server->server_type == SILC_SERVER ?
				    FALSE : TRUE, client->id, 
				    SILC_ID_CLIENT_LEN, signoff);

  /* Remove client from all channels */
  if (notify)
    silc_server_remove_from_channels(server, NULL, client, 
				     TRUE, signoff, TRUE);
  else
    silc_server_remove_from_channels(server, NULL, client, 
				     FALSE, NULL, FALSE);

  /* We will not delete the client entry right away. We will take it
     into history (for WHOWAS command) for 5 minutes */
  i->server = server;
  i->client = client;
  silc_task_register(server->timeout_queue, 0, 
		     silc_server_free_client_data_timeout,
		     (void *)i, 300, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
  client->data.registered = FALSE;

  /* Free the client entry and everything in it */
  server->stat.my_clients--;
  server->stat.clients--;
  if (server->server_type == SILC_ROUTER)
    server->stat.cell_clients--;
}

/* Frees user_data pointer from socket connection object. This also sends
   appropriate notify packets to the network to inform about leaving
   entities. */

void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock)
{
  SILC_LOG_DEBUG(("Start"));

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry user_data = (SilcClientEntry)sock->user_data;
      silc_server_free_client_data(server, sock, user_data, TRUE, NULL);
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry user_data = (SilcServerEntry)sock->user_data;

      /* Free all client entries that this server owns as they will
	 become invalid now as well. */
      if (user_data->id)
	silc_server_remove_clients_by_server(server, user_data, TRUE);

      /* If this was our primary router connection then we're lost to
	 the outside world. */
      if (server->router == user_data) {
	server->id_entry->router = NULL;
	server->router = NULL;
	server->standalone = TRUE;
      }

      /* Free the server entry */
      silc_idlist_del_data(user_data);
      silc_idlist_del_server(server->local_list, user_data);
      server->stat.my_servers--;
      server->stat.servers--;
      if (server->server_type == SILC_ROUTER)
	server->stat.cell_servers--;
      break;
    }
  default:
    {
      SilcUnknownEntry user_data = (SilcUnknownEntry)sock->user_data;

      silc_idlist_del_data(user_data);
      silc_free(user_data);
      break;
    }
  }

  sock->user_data = NULL;
}

/* This function is used to remove all client entries by the server `entry'.
   This is called when the connection is lost to the server. In this case
   we must invalidate all the client entries owned by the server `entry'. 
   If the `server_signoff' is TRUE then the SERVER_SIGNOFF notify is
   distributed to our local clients. */

int silc_server_remove_clients_by_server(SilcServer server, 
					 SilcServerEntry entry,
					 int server_signoff)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcBuffer idp;
  SilcClientEntry *clients = NULL;
  uint32 clients_c = 0;
  unsigned char **argv = NULL;
  uint32 *argv_lens = NULL, *argv_types = NULL, argc = 0;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (server_signoff) {
    idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
    argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
    argv_lens = silc_realloc(argv_lens,  sizeof(*argv_lens) * (argc + 1));
    argv_types = silc_realloc(argv_types, sizeof(*argv_types) * (argc + 1));
    argv[argc] = idp->data;
    argv_lens[argc] = idp->len;
    argv_types[argc] = argc + 1;
    argc++;
    silc_buffer_free(idp);
  }

  if (silc_idcache_find_by_id(server->local_list->clients, 
			      SILC_ID_CACHE_ANY, SILC_ID_CLIENT, &list)) {

    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (client->data.registered == FALSE) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (client->router != entry) {
	  if (server_signoff && client->connection) {
	    clients = silc_realloc(clients, 
				   sizeof(*clients) * (clients_c + 1));
	    clients[clients_c] = client;
	    clients_c++;
	  }

	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (server_signoff) {
	  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	  argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	  argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				   (argc + 1));
	  argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				    (argc + 1));
	  argv[argc] = silc_calloc(idp->len, sizeof(*argv[0]));
	  memcpy(argv[argc], idp->data, idp->len);
	  argv_lens[argc] = idp->len;
	  argv_types[argc] = argc + 1;
	  argc++;
	  silc_buffer_free(idp);
	}

	/* Remove the client entry */
	silc_server_remove_from_channels(server, NULL, client, FALSE, 
					 NULL, FALSE);
	silc_idlist_del_client(server->local_list, client);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
  
  if (silc_idcache_find_by_id(server->global_list->clients, 
			      SILC_ID_CACHE_ANY, SILC_ID_CLIENT, &list)) {

    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (client->data.registered == FALSE) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}
	
	if (client->router != entry) {
	  if (server_signoff && client->connection) {
	    clients = silc_realloc(clients, 
				   sizeof(*clients) * (clients_c + 1));
	    clients[clients_c] = client;
	    clients_c++;
	  }

	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (server_signoff) {
	  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	  argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	  argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				   (argc + 1));
	  argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				    (argc + 1));
	  argv[argc] = silc_calloc(idp->len, sizeof(*argv[0]));
	  memcpy(argv[argc], idp->data, idp->len);
	  argv_lens[argc] = idp->len;
	  argv_types[argc] = argc + 1;
	  argc++;
	  silc_buffer_free(idp);
	}

	/* Remove the client entry */
	silc_server_remove_from_channels(server, NULL, client, FALSE,
					 NULL, FALSE);
	silc_idlist_del_client(server->global_list, client);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  /* Send the SERVER_SIGNOFF notify */
  if (server_signoff) {
    SilcBuffer args;

    /* Send SERVER_SIGNOFF notify to our primary router */
    if (!server->standalone && server->router) {
      args = silc_argument_payload_encode(1, argv, argv_lens,
					  argv_types);
      silc_server_send_notify_args(server, 
				   server->router->connection,
				   server->server_type == SILC_SERVER ? 
				   FALSE : TRUE, 
				   SILC_NOTIFY_TYPE_SERVER_SIGNOFF,
				   argc, args);
      silc_buffer_free(args);
    }

    args = silc_argument_payload_encode(argc, argv, argv_lens,
					argv_types);
    /* Send to local clients */
    for (i = 0; i < clients_c; i++) {
      silc_server_send_notify_args(server, clients[i]->connection,
				   FALSE, SILC_NOTIFY_TYPE_SERVER_SIGNOFF,
				   argc, args);
    }

    silc_free(clients);
    silc_buffer_free(args);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
  }

  return TRUE;
}

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */

int silc_server_channel_has_global(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */

int silc_server_channel_has_local(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (!chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Removes client from all channels it has joined. This is used when client
   connection is disconnected. If the client on a channel is last, the
   channel is removed as well. This sends the SIGNOFF notify types. */

void silc_server_remove_from_channels(SilcServer server, 
				      SilcSocketConnection sock,
				      SilcClientEntry client,
				      int notify,
				      char *signoff_message,
				      int keygen)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Start"));

  if (!client || !client->id)
    return;

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    channel = chl->channel;

    /* Remove channel from client's channel list */
    silc_list_del(client->channels, chl);

    /* Remove channel if there is no users anymore */
    if (server->server_type == SILC_ROUTER &&
	silc_list_count(channel->user_list) < 2) {
      server->stat.my_channels--;

      if (channel->rekey)
	silc_task_unregister_by_context(server->timeout_queue, channel->rekey);

      if (channel->founder_key) {
	/* The founder auth data exists, do not remove the channel entry */
	SilcChannelClientEntry chl2;

	channel->id = NULL;

	silc_list_start(channel->user_list);
	while ((chl2 = silc_list_get(channel->user_list)) != SILC_LIST_END) {
	  silc_list_del(chl2->client->channels, chl2);
	  silc_list_del(channel->user_list, chl2);
	  silc_free(chl2);
	}
	continue;
      }

      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      continue;
    }

    /* Remove client from channel's client list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);
    server->stat.my_chanclients--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    /* If there is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_local(channel)) {
      /* Notify about leaving client if this channel has global users. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					   SILC_NOTIFY_TYPE_SIGNOFF, 
					   signoff_message ? 2 : 1,
					   clidp->data, clidp->len,
					   signoff_message, signoff_message ?
					   strlen(signoff_message) : 0);

      if (channel->rekey)
	silc_task_unregister_by_context(server->timeout_queue, channel->rekey);

      if (channel->founder_key) {
	/* The founder auth data exists, do not remove the channel entry */
	SilcChannelClientEntry chl2;

	channel->id = NULL;

	silc_list_start(channel->user_list);
	while ((chl2 = silc_list_get(channel->user_list)) != SILC_LIST_END) {
	  silc_list_del(chl2->client->channels, chl2);
	  silc_list_del(channel->user_list, chl2);
	  silc_free(chl2);
	}
	continue;
      }

      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      server->stat.my_channels--;
      continue;
    }

    /* Send notify to channel about client leaving SILC and thus
       the entire channel. */
    if (notify)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					 SILC_NOTIFY_TYPE_SIGNOFF, 
					 signoff_message ? 2 : 1,
					 clidp->data, clidp->len,
					 signoff_message, signoff_message ?
					 strlen(signoff_message) : 0);

    if (keygen && !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
      /* Re-generate channel key */
      silc_server_create_channel_key(server, channel, 0);
      
      /* Send the channel key to the channel. The key of course is not sent
	 to the client who was removed from the channel. */
      silc_server_send_channel_key(server, client->connection, channel, 
				   server->server_type == SILC_ROUTER ? 
				   FALSE : !server->standalone);
    }
  }

  silc_buffer_free(clidp);
}

/* Removes client from one channel. This is used for example when client
   calls LEAVE command to remove itself from the channel. Returns TRUE
   if channel still exists and FALSE if the channel is removed when
   last client leaves the channel. If `notify' is FALSE notify messages
   are not sent. */

int silc_server_remove_from_one_channel(SilcServer server, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					SilcClientEntry client,
					int notify)
{
  SilcChannelEntry ch;
  SilcChannelClientEntry chl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Start"));

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove the client from the channel. The client is removed from
     the channel's user list. */
  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    if (chl->channel != channel)
      continue;

    ch = chl->channel;

    /* Remove channel from client's channel list */
    silc_list_del(client->channels, chl);

    /* Remove channel if there is no users anymore */
    if (server->server_type == SILC_ROUTER &&
	silc_list_count(channel->user_list) < 2) {
      if (channel->rekey)
	silc_task_unregister_by_context(server->timeout_queue, channel->rekey);
      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      silc_buffer_free(clidp);
      server->stat.my_channels--;
      return FALSE;
    }

    /* Remove client from channel's client list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);
    server->stat.my_chanclients--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    /* If there is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_local(channel)) {
      /* Notify about leaving client if this channel has global users. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					   SILC_NOTIFY_TYPE_LEAVE, 1,
					   clidp->data, clidp->len);

      silc_buffer_free(clidp);

      if (channel->rekey)
	silc_task_unregister_by_context(server->timeout_queue, channel->rekey);

      if (channel->founder_key) {
	/* The founder auth data exists, do not remove the channel entry */
	SilcChannelClientEntry chl2;

	channel->id = NULL;

	silc_list_start(channel->user_list);
	while ((chl2 = silc_list_get(channel->user_list)) != SILC_LIST_END) {
	  silc_list_del(chl2->client->channels, chl2);
	  silc_list_del(channel->user_list, chl2);
	  silc_free(chl2);
	}
	return FALSE;
      }

      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      server->stat.my_channels--;
      return FALSE;
    }

    /* Send notify to channel about client leaving the channel */
    if (notify)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					 SILC_NOTIFY_TYPE_LEAVE, 1,
					 clidp->data, clidp->len);
    break;
  }

  silc_buffer_free(clidp);
  return TRUE;
}

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */

int silc_server_client_on_channel(SilcClientEntry client,
				  SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  if (!client || !channel)
    return FALSE;

  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END)
    if (chl->channel == channel)
      return TRUE;

  return FALSE;
}

/* Timeout callback. This is called if connection is idle or for some
   other reason is not responding within some period of time. This 
   disconnects the remote end. */

SILC_TASK_CALLBACK(silc_server_timeout_remote)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];

  if (!sock)
    return;

  if (sock->user_data)
    silc_server_free_sock_user_data(server, sock);

  silc_server_disconnect_remote(server, sock, 
				"Server closed connection: "
				"Connection timeout");
}

/* Creates new channel. Sends NEW_CHANNEL packet to primary route. This
   function may be used only by router. In real SILC network all channels
   are created by routers thus this function is never used by normal
   server. */

SilcChannelEntry silc_server_create_new_channel(SilcServer server, 
						SilcServerID *router_id,
						char *cipher, 
						char *hmac,
						char *channel_name,
						int broadcast)
{
  SilcChannelID *channel_id;
  SilcChannelEntry entry;
  SilcCipher key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel"));

  if (!cipher)
    cipher = "aes-256-cbc";
  if (!hmac)
    hmac = "hmac-sha1-96";

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &key))
    return NULL;

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel */
  silc_id_create_channel_id(router_id, server->rng, &channel_id);
  entry = silc_idlist_add_channel(server->local_list, channel_name, 
				  SILC_CHANNEL_MODE_NONE, channel_id, 
				  NULL, key, newhmac);
  if (!entry) {
    silc_free(channel_name);
    return NULL;
  }

  entry->cipher = strdup(cipher);
  entry->hmac_name = strdup(hmac);

  /* Now create the actual key material */
  silc_server_create_channel_key(server, entry, 
				 silc_cipher_get_key_len(key) / 8);

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast && server->standalone == FALSE)
    silc_server_send_new_channel(server, server->router->connection, TRUE, 
				 channel_name, entry->id, SILC_ID_CHANNEL_LEN,
				 entry->mode);

  server->stat.my_channels++;

  return entry;
}

/* Same as above but creates the channel with Channel ID `channel_id. */

SilcChannelEntry 
silc_server_create_new_channel_with_id(SilcServer server, 
				       char *cipher, 
				       char *hmac,
				       char *channel_name,
				       SilcChannelID *channel_id,
				       int broadcast)
{
  SilcChannelEntry entry;
  SilcCipher key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel"));

  if (!cipher)
    cipher = "aes-256-cbc";
  if (!hmac)
    hmac = "hmac-sha1-96";

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &key))
    return NULL;

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel */
  entry = silc_idlist_add_channel(server->local_list, channel_name, 
				  SILC_CHANNEL_MODE_NONE, channel_id, 
				  NULL, key, newhmac);
  if (!entry) {
    silc_free(channel_name);
    return NULL;
  }

  /* Now create the actual key material */
  silc_server_create_channel_key(server, entry, 
				 silc_cipher_get_key_len(key) / 8);

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast && server->standalone == FALSE)
    silc_server_send_new_channel(server, server->router->connection, TRUE, 
				 channel_name, entry->id, SILC_ID_CHANNEL_LEN,
				 entry->mode);

  server->stat.my_channels++;

  return entry;
}

/* Channel's key re-key timeout callback. */

SILC_TASK_CALLBACK(silc_server_channel_key_rekey)
{
  SilcServerChannelRekey rekey = (SilcServerChannelRekey)context;
  SilcServer server = (SilcServer)rekey->context;

  silc_server_create_channel_key(server, rekey->channel, rekey->key_len);
  silc_server_send_channel_key(server, NULL, rekey->channel, FALSE);

  silc_task_register(server->timeout_queue, 0, 
		     silc_server_channel_key_rekey,
		     (void *)rekey, 3600, 0,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_NORMAL);
}

/* Generates new channel key. This is used to create the initial channel key
   but also to re-generate new key for channel. If `key_len' is provided
   it is the bytes of the key length. */

void silc_server_create_channel_key(SilcServer server, 
				    SilcChannelEntry channel,
				    uint32 key_len)
{
  int i;
  unsigned char channel_key[32], hash[32];
  uint32 len;

  SILC_LOG_DEBUG(("Generating channel key"));

  if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
    SILC_LOG_DEBUG(("Channel has private keys, will not generate new key"));
    return;
  }

  if (!channel->channel_key)
    if (!silc_cipher_alloc("aes-256-cbc", &channel->channel_key))
      return;

  if (key_len)
    len = key_len;
  else if (channel->key_len)
    len = channel->key_len / 8;
  else
    len = silc_cipher_get_key_len(channel->channel_key) / 8;

  /* Create channel key */
  for (i = 0; i < len; i++) channel_key[i] = silc_rng_get_byte(server->rng);
  
  /* Set the key */
  silc_cipher_set_key(channel->channel_key, channel_key, len * 8);

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
  }

  /* Save the key */
  channel->key_len = len * 8;
  channel->key = silc_calloc(len, sizeof(*channel->key));
  memcpy(channel->key, channel_key, len);
  memset(channel_key, 0, sizeof(channel_key));

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    silc_hmac_alloc("hmac-sha1-96", NULL, &channel->hmac);
  silc_hash_make(channel->hmac->hash, channel->key, len, hash);
  silc_hmac_set_key(channel->hmac, hash, silc_hash_len(channel->hmac->hash));
  memset(hash, 0, sizeof(hash));

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->context = (void *)server;
    channel->rekey->channel = channel;
    channel->rekey->key_len = key_len;

    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_channel_key_rekey);
    silc_task_register(server->timeout_queue, 0, 
		       silc_server_channel_key_rekey,
		       (void *)channel->rekey, 3600, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
  }
}

/* Saves the channel key found in the encoded `key_payload' buffer. This 
   function is used when we receive Channel Key Payload and also when we're
   processing JOIN command reply. Returns entry to the channel. */

SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel)
{
  SilcChannelKeyPayload payload = NULL;
  SilcChannelID *id = NULL;
  unsigned char *tmp, hash[32];
  uint32 tmp_len;
  char *cipher;

  SILC_LOG_DEBUG(("Start"));

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(key_payload);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload, dropped"));
    channel = NULL;
    goto out;
  }

  /* Get the channel entry */
  if (!channel) {

    /* Get channel ID */
    tmp = silc_channel_key_get_id(payload, &tmp_len);
    id = silc_id_str2id(tmp, tmp_len, SILC_ID_CHANNEL);
    if (!id) {
      channel = NULL;
      goto out;
    }

    channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
      if (!channel) {
	SILC_LOG_ERROR(("Received key for non-existent channel"));
	goto out;
      }
    }
  }

  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp) {
    channel = NULL;
    goto out;
  }

  cipher = silc_channel_key_get_cipher(payload, NULL);
  if (!cipher) {
    channel = NULL;
    goto out;
  }

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
    silc_cipher_free(channel->channel_key);
  }

  /* Create new cipher */
  if (!silc_cipher_alloc(cipher, &channel->channel_key)) {
    channel = NULL;
    goto out;
  }

  if (channel->cipher)
    silc_free(channel->cipher);
  channel->cipher = strdup(cipher);

  /* Save the key */
  channel->key_len = tmp_len * 8;
  channel->key = silc_calloc(tmp_len, sizeof(unsigned char));
  memcpy(channel->key, tmp, tmp_len);
  silc_cipher_set_key(channel->channel_key, tmp, channel->key_len);

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    silc_hmac_alloc("hmac-sha1-96", NULL, &channel->hmac);
  silc_hash_make(channel->hmac->hash, tmp, tmp_len, hash);
  silc_hmac_set_key(channel->hmac, hash, silc_hash_len(channel->hmac->hash));

  memset(hash, 0, sizeof(hash));
  memset(tmp, 0, tmp_len);

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->context = (void *)server;
    channel->rekey->channel = channel;

    silc_task_unregister_by_callback(server->timeout_queue,
				     silc_server_channel_key_rekey);
    silc_task_register(server->timeout_queue, 0, 
		       silc_server_channel_key_rekey,
		       (void *)channel->rekey, 3600, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
  }

 out:
  if (id)
    silc_free(id);
  if (payload)
    silc_channel_key_payload_free(payload);

  return channel;
}

/* Heartbeat callback. This function is set as argument for the
   silc_socket_set_heartbeat function. The library will call this function
   at the set time interval. */

void silc_server_perform_heartbeat(SilcSocketConnection sock,
				   void *hb_context)
{
  SilcServerHBContext hb = (SilcServerHBContext)hb_context;

  SILC_LOG_DEBUG(("Sending heartbeat to %s (%s)", sock->hostname,
		  sock->ip));

  /* Send the heartbeat */
  silc_server_send_heartbeat(hb->server, sock);
}

/* Returns assembled of all servers in the given ID list. The packet's
   form is dictated by the New ID payload. */

static void silc_server_announce_get_servers(SilcServer server,
					     SilcIDList id_list,
					     SilcBuffer *servers)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;
  SilcBuffer idp;

  /* Go through all clients in the list */
  if (silc_idcache_find_by_id(id_list->clients, SILC_ID_CACHE_ANY, 
			      SILC_ID_SERVER, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	entry = (SilcServerEntry)id_cache->context;

	idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);

	*servers = silc_buffer_realloc(*servers, 
				       (*servers ? 
					(*servers)->truelen + idp->len : 
					idp->len));
	silc_buffer_pull_tail(*servers, ((*servers)->end - (*servers)->data));
	silc_buffer_put(*servers, idp->data, idp->len);
	silc_buffer_pull(*servers, idp->len);
	silc_buffer_free(idp);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

/* This function is used by router to announce existing servers to our
   primary router when we've connected to it. */

void silc_server_announce_servers(SilcServer server)
{
  SilcBuffer servers = NULL;

  SILC_LOG_DEBUG(("Announcing servers"));

  /* Get servers in local list */
  silc_server_announce_get_servers(server, server->local_list, &servers);

  /* Get servers in global list */
  silc_server_announce_get_servers(server, server->global_list, &servers);

  if (servers) {
    silc_buffer_push(servers, servers->data - servers->head);
    SILC_LOG_HEXDUMP(("servers"), servers->data, servers->len);

    /* Send the packet */
    silc_server_packet_send(server, server->router->connection,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    servers->data, servers->len, TRUE);

    silc_buffer_free(servers);
  }
}

/* Returns assembled packet of all clients in the given ID list. The
   packet's form is dictated by the New ID Payload. */

static void silc_server_announce_get_clients(SilcServer server,
					     SilcIDList id_list,
					     SilcBuffer *clients)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcClientEntry client;
  SilcBuffer idp;

  /* Go through all clients in the list */
  if (silc_idcache_find_by_id(id_list->clients, SILC_ID_CACHE_ANY, 
			      SILC_ID_CLIENT, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;

	idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

	*clients = silc_buffer_realloc(*clients, 
				       (*clients ? 
					(*clients)->truelen + idp->len : 
					idp->len));
	silc_buffer_pull_tail(*clients, ((*clients)->end - (*clients)->data));
	silc_buffer_put(*clients, idp->data, idp->len);
	silc_buffer_pull(*clients, idp->len);
	silc_buffer_free(idp);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

/* This function is used to announce our existing clients to our router
   when we've connected to it. */

void silc_server_announce_clients(SilcServer server)
{
  SilcBuffer clients = NULL;

  SILC_LOG_DEBUG(("Announcing clients"));

  /* Get clients in local list */
  silc_server_announce_get_clients(server, server->local_list,
				   &clients);

  /* As router we announce our global list as well */
  if (server->server_type == SILC_ROUTER)
    silc_server_announce_get_clients(server, server->global_list,
				     &clients);

  if (clients) {
    silc_buffer_push(clients, clients->data - clients->head);
    SILC_LOG_HEXDUMP(("clients"), clients->data, clients->len);

    /* Send the packet */
    silc_server_packet_send(server, server->router->connection,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    clients->data, clients->len, TRUE);

    silc_buffer_free(clients);
  }
}

static SilcBuffer 
silc_server_announce_encode_join(uint32 argc, ...)
{
  va_list ap;

  va_start(ap, argc);
  return silc_notify_payload_encode(SILC_NOTIFY_TYPE_JOIN, argc, ap);
}

/* Returns assembled packets for channel users of the `channel'. */

void silc_server_announce_get_channel_users(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *channel_users)
{
  SilcChannelClientEntry chl;
  SilcBuffer chidp, clidp;
  SilcBuffer tmp;
  int len;

  SILC_LOG_DEBUG(("Start"));

  /* Now find all users on the channel */
  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    clidp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    tmp = silc_server_announce_encode_join(2, clidp->data, clidp->len,
					   chidp->data, chidp->len);
    len = tmp->len;
    *channel_users = 
      silc_buffer_realloc(*channel_users, 
			  (*channel_users ? 
			   (*channel_users)->truelen + len : len));
    silc_buffer_pull_tail(*channel_users, 
			  ((*channel_users)->end - 
			   (*channel_users)->data));
    
    silc_buffer_put(*channel_users, tmp->data, tmp->len);
    silc_buffer_pull(*channel_users, len);
    silc_buffer_free(clidp);
    silc_buffer_free(tmp);
  }
  silc_buffer_free(chidp);
}

/* Returns assembled packets for all channels and users on those channels
   from the given ID List. The packets are in the form dictated by the
   New Channel and New Channel User payloads. */

void silc_server_announce_get_channels(SilcServer server,
				       SilcIDList id_list,
				       SilcBuffer *channels,
				       SilcBuffer *channel_users)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcChannelEntry channel;
  unsigned char *cid;
  uint16 name_len;
  int len;

  SILC_LOG_DEBUG(("Start"));

  /* Go through all channels in the list */
  if (silc_idcache_find_by_id(id_list->channels, SILC_ID_CACHE_ANY, 
			      SILC_ID_CHANNEL, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	channel = (SilcChannelEntry)id_cache->context;
	
	cid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
	name_len = strlen(channel->channel_name);

	len = 4 + name_len + SILC_ID_CHANNEL_LEN + 4;
	*channels = 
	  silc_buffer_realloc(*channels, 
			      (*channels ? (*channels)->truelen + len : len));
	silc_buffer_pull_tail(*channels, 
			      ((*channels)->end - (*channels)->data));
	silc_buffer_format(*channels,
			   SILC_STR_UI_SHORT(name_len),
			   SILC_STR_UI_XNSTRING(channel->channel_name, 
						name_len),
			   SILC_STR_UI_SHORT(SILC_ID_CHANNEL_LEN),
			   SILC_STR_UI_XNSTRING(cid, SILC_ID_CHANNEL_LEN),
			   SILC_STR_UI_INT(channel->mode),
			   SILC_STR_END);
	silc_buffer_pull(*channels, len);

	silc_server_announce_get_channel_users(server, channel,
					       channel_users);

	silc_free(cid);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

/* This function is used to announce our existing channels to our router
   when we've connected to it. This also announces the users on the
   channels to the router. */

void silc_server_announce_channels(SilcServer server)
{
  SilcBuffer channels = NULL, channel_users = NULL;

  SILC_LOG_DEBUG(("Announcing channels and channel users"));

  /* Get channels and channel users in local list */
  silc_server_announce_get_channels(server, server->local_list,
				    &channels, &channel_users);

  /* Get channels and channel users in global list */
  silc_server_announce_get_channels(server, server->global_list,
				    &channels, &channel_users);

  if (channels) {
    silc_buffer_push(channels, channels->data - channels->head);
    SILC_LOG_HEXDUMP(("channels"), channels->data, channels->len);

    /* Send the packet */
    silc_server_packet_send(server, server->router->connection,
			    SILC_PACKET_NEW_CHANNEL, SILC_PACKET_FLAG_LIST,
			    channels->data, channels->len,
			    FALSE);

    silc_buffer_free(channels);
  }

  if (channel_users) {
    silc_buffer_push(channel_users, channel_users->data - channel_users->head);
    SILC_LOG_HEXDUMP(("channel users"), channel_users->data, 
		     channel_users->len);

    /* Send the packet */
    silc_server_packet_send(server, server->router->connection,
			    SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
			    channel_users->data, channel_users->len,
			    FALSE);

    silc_buffer_free(channel_users);
  }
}

/* Failure timeout callback. If this is called then we will immediately
   process the received failure. We always process the failure with timeout
   since we do not want to blindly trust to received failure packets. 
   This won't be called (the timeout is cancelled) if the failure was
   bogus (it is bogus if remote does not close the connection after sending
   the failure). */

SILC_TASK_CALLBACK(silc_server_failure_callback)
{
  SilcServerFailureContext f = (SilcServerFailureContext)context;

  if (f->sock->protocol) {
    f->sock->protocol->state = SILC_PROTOCOL_STATE_FAILURE;
    f->sock->protocol->execute(f->server->timeout_queue, 0,
			       f->sock->protocol, f->sock->sock, 0, 0);
  }

  silc_free(f);
}

/* Assembles user list and users mode list from the `channel'. */

void silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      uint32 *user_count)
{
  SilcChannelClientEntry chl;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  SilcBuffer idp;
  uint32 list_count = 0;

  client_id_list = silc_buffer_alloc((SILC_ID_CLIENT_LEN + 4) * 
				     silc_list_count(channel->user_list));
  client_mode_list = silc_buffer_alloc(4 * 
				       silc_list_count(channel->user_list));
  silc_buffer_pull_tail(client_id_list, SILC_BUFFER_END(client_id_list));
  silc_buffer_pull_tail(client_mode_list, SILC_BUFFER_END(client_mode_list));
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    /* Client ID */
    idp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    silc_buffer_put(client_id_list, idp->data, idp->len);
    silc_buffer_pull(client_id_list, idp->len);
    silc_buffer_free(idp);

    /* Client's mode on channel */
    SILC_PUT32_MSB(chl->mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);

    list_count++;
  }
  silc_buffer_push(client_id_list, 
		   client_id_list->data - client_id_list->head);
  silc_buffer_push(client_mode_list, 
		   client_mode_list->data - client_mode_list->head);

  *user_list = client_id_list;
  *mode_list = client_mode_list;
  *user_count = list_count;
}

/* Saves users and their modes to the `channel'. */

void silc_server_save_users_on_channel(SilcServer server,
				       SilcSocketConnection sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       uint32 user_count)
{
  int i;

  /* Cache the received Client ID's and modes. This cache expires
     whenever server sends notify message to channel. It means two things;
     some user has joined or leaved the channel. XXX TODO! */
  for (i = 0; i < user_count; i++) {
    uint16 idp_len;
    uint32 mode;
    SilcClientID *client_id;
    SilcClientEntry client;

    /* Client ID */
    SILC_GET16_MSB(idp_len, user_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(user_list->data, idp_len);
    silc_buffer_pull(user_list, idp_len);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, mode_list->data);
    silc_buffer_pull(mode_list, 4);

    if (noadd && !SILC_ID_CLIENT_COMPARE(client_id, noadd)) {
      silc_free(client_id);
      continue;
    }
    
    /* Check if we have this client cached already. */
    client = silc_idlist_find_client_by_id(server->local_list, client_id,
					   NULL);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, NULL);
    if (!client) {
      /* If router did not find such Client ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type == SILC_ROUTER) {
	silc_free(client_id);
	continue;
      }

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be 
	 global. */
      client = silc_idlist_add_client(server->global_list, NULL, 0, NULL, 
				      NULL, 
				      silc_id_dup(client_id, SILC_ID_CLIENT), 
				      sock->user_data, NULL);
      if (!client) {
	silc_free(client_id);
	continue;
      }

      client->data.registered = TRUE;
    }

    silc_free(client_id);

    if (!silc_server_client_on_channel(client, channel)) {
      /* Client was not on the channel, add it. */
      SilcChannelClientEntry chl = silc_calloc(1, sizeof(*chl));
      chl->client = client;
      chl->mode = mode;
      chl->channel = channel;
      silc_list_add(channel->user_list, chl);
      silc_list_add(client->channels, chl);
    }
  }
}

/* Lookups route to the client indicated by the `id_data'. The connection
   object and internal data object is returned. Returns NULL if route
   could not be found to the client. If the `client_id' is specified then
   it is used and the `id_data' is ignored. */

SilcSocketConnection silc_server_get_client_route(SilcServer server,
						  unsigned char *id_data,
						  uint32 id_len,
						  SilcClientID *client_id,
						  SilcIDListData *idata)
{
  SilcClientID *id;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  /* Decode destination Client ID */
  if (!client_id) {
    id = silc_id_str2id(id_data, id_len, SILC_ID_CLIENT);
    if (!id) {
      SILC_LOG_ERROR(("Could not decode destination Client ID, dropped"));
      return NULL;
    }
  } else {
    id = silc_id_dup(client_id, SILC_ID_CLIENT);
  }

  /* If the destination belongs to our server we don't have to route
     the packet anywhere but to send it to the local destination. */
  client = silc_idlist_find_client_by_id(server->local_list, id, NULL);
  if (client) {
    silc_free(id);

    if (client && client->data.registered == FALSE)
      return NULL;

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      /* We are of course in this case the client's router thus the real
	 "router" of the client is the server who owns the client. Thus
	 we will send the packet to that server. */
      if (idata)
	*idata = (SilcIDListData)client->router;
      return client->router->connection;
    }

    /* Seems that client really is directly connected to us */
    if (idata)
      *idata = (SilcIDListData)client;
    return client->connection;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type == SILC_SERVER && !server->standalone) {
    silc_free(id);
    if (idata)
      *idata = (SilcIDListData)server->router;
    return server->router->connection;
  }

  /* We are router and we will perform route lookup for the destination 
     and send the packet to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {
    /* Check first that the ID is valid */
    client = silc_idlist_find_client_by_id(server->global_list, id, NULL);
    if (client) {
      SilcSocketConnection dst_sock;

      dst_sock = silc_server_route_get(server, id, SILC_ID_CLIENT);

      silc_free(id);
      if (idata)
	*idata = (SilcIDListData)dst_sock->user_data;
      return dst_sock;
    }
  }

  silc_free(id);
  return NULL;
}

/* Encodes and returns channel list of channels the `client' has joined.
   Secret channels are not put to the list. */

SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client)
{
  SilcBuffer buffer = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  unsigned char *cid;
  uint16 name_len;
  int len;

  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    channel = chl->channel;

    if (channel->mode & SILC_CHANNEL_MODE_SECRET)
      continue;

    cid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
    name_len = strlen(channel->channel_name);
    
    len = 4 + name_len + SILC_ID_CHANNEL_LEN + 4;
    buffer = silc_buffer_realloc(buffer, 
				 (buffer ? (buffer)->truelen + len : len));
    silc_buffer_pull_tail(buffer, ((buffer)->end - (buffer)->data));
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(name_len),
		       SILC_STR_UI_XNSTRING(channel->channel_name, 
					    name_len),
		       SILC_STR_UI_SHORT(SILC_ID_CHANNEL_LEN),
		       SILC_STR_UI_XNSTRING(cid, SILC_ID_CHANNEL_LEN),
		       SILC_STR_UI_INT(chl->mode), /* Client's mode */
		       SILC_STR_END);
    silc_buffer_pull(buffer, len);
    silc_free(cid);
  }

  if (buffer)
    silc_buffer_push(buffer, buffer->data - buffer->head);

  return buffer;
}

/* Finds client entry by Client ID and if it is not found then resolves
   it using WHOIS command. */

SilcClientEntry silc_server_get_client_resolve(SilcServer server,
					       SilcClientID *client_id)
{
  SilcClientEntry client;

  client = silc_idlist_find_client_by_id(server->local_list, client_id, NULL);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, NULL);
    if (!client && server->server_type == SILC_ROUTER)
      return NULL;
  }

  if (!client && server->standalone)
    return NULL;

  if (!client || !client->nickname || !client->username) {
    SilcBuffer buffer, idp;

    idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_WHOIS,
					    ++server->cmd_ident, 1,
					    3, idp->data, idp->len);
    silc_server_packet_send(server, client ? client->router->connection :
			    server->router->connection,
			    SILC_PACKET_COMMAND, 0,
			    buffer->data, buffer->len, FALSE);
    silc_buffer_free(idp);
    silc_buffer_free(buffer);
  }

  return client;
}

/* A timeout callback for the re-key. We will be the initiator of the
   re-key protocol. */

SILC_TASK_CALLBACK(silc_server_rekey_callback)
{
  SilcSocketConnection sock = (SilcSocketConnection)context;
  SilcIDListData idata = (SilcIDListData)sock->user_data;
  SilcServer server = (SilcServer)idata->rekey->context;
  SilcProtocol protocol;
  SilcServerRekeyInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock;
  proto_ctx->responder = FALSE;
  proto_ctx->pfs = idata->rekey->pfs;
      
  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_REKEY, 
		      &protocol, proto_ctx, silc_server_rekey_final);
  sock->protocol = protocol;
      
  /* Run the protocol */
  protocol->execute(server->timeout_queue, 0, protocol, 
		    sock->sock, 0, 0);

  /* Re-register re-key timeout */
  silc_task_register(server->timeout_queue, sock->sock, 
		     silc_server_rekey_callback,
		     context, idata->rekey->timeout, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* The final callback for the REKEY protocol. This will actually take the
   new key material into use. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerRekeyInternalContext *ctx =
    (SilcServerRekeyInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = ctx->sock;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_cancel(server->timeout_queue, protocol);
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx);
    return;
  }

  /* Cleanup */
  silc_protocol_free(protocol);
  sock->protocol = NULL;
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
}
