/*

  client_ftp.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "clientlibincludes.h"
#include "client_internal.h"

static int
silc_client_connect_to_client(SilcClient client, 
			      SilcClientConnection conn, int port,
			      char *host, void *context);
static int 
silc_client_connect_to_client_internal(SilcClientInternalConnectContext *ctx);
SILC_TASK_CALLBACK(silc_client_ftp_connected);
static void silc_client_ftp_start_key_agreement(SilcClientFtpSession session,
						int sock);

/* File transmission session */
struct SilcClientFtpSessionStruct {
  uint32 session_id;
  SilcClient client;
  SilcClientConnection conn;
  SilcClientEntry client_entry;

  SilcSocketConnection sock;
  SilcBuffer packet;

  char *hostname;
  uint16 port;
  int listener;

  SilcClientFileMonitor monitor;
  void *monitor_context;
  char *filepath;

  SilcSFTP sftp;
  SilcSFTPFilesystem fs;
  bool server;

  SilcSFTPHandle dir_handle;
  SilcSFTPHandle read_handle;
  uint64 filesize;
  uint64 read_offset;
  int fd;
};

SILC_TASK_CALLBACK(silc_client_ftp_connected)
{
  SilcClientInternalConnectContext *ctx =
    (SilcClientInternalConnectContext *)context;
  SilcClient client = ctx->client;
  SilcClientConnection conn = ctx->conn;
  SilcClientFtpSession session = (SilcClientFtpSession)ctx->context;
  int opt, opt_len = sizeof(opt);

  SILC_LOG_DEBUG(("Start"));

  /* Check the socket status as it might be in error */
  silc_net_get_socket_opt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
  if (opt != 0) {
    if (ctx->tries < 2) {
      /* Connection failed but lets try again */
      client->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
		       "Could not connect to client %s: %s",
		       ctx->host, strerror(opt));
      client->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT, 
		       "Connecting to port %d of client %s resumed", 
		       ctx->port, ctx->host);

      /* Unregister old connection try */
      silc_schedule_unset_listen_fd(client->schedule, fd);
      silc_net_close_connection(fd);
      silc_schedule_task_del(client->schedule, ctx->task);

      /* Try again */
      silc_client_connect_to_client_internal(ctx);
      ctx->tries++;
    } else {
      /* Connection failed and we won't try anymore */
      client->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
		       "Could not connect to client %s: %s",
		       ctx->host, strerror(opt));
      silc_schedule_unset_listen_fd(client->schedule, fd);
      silc_net_close_connection(fd);
      silc_schedule_task_del(client->schedule, ctx->task);
      silc_free(ctx);
      silc_client_ftp_session_free(session);
    }
    return;
  }

  silc_schedule_unset_listen_fd(client->schedule, fd);
  silc_schedule_task_del(client->schedule, ctx->task);

  /* Start the key agreement */
  silc_client_ftp_start_key_agreement(session, fd);
}

static int 
silc_client_connect_to_client_internal(SilcClientInternalConnectContext *ctx)
{
  int sock;

  /* Create connection to server asynchronously */
  sock = silc_net_create_connection_async(NULL, ctx->port, ctx->host);
  if (sock < 0)
    return -1;

  /* Register task that will receive the async connect and will
     read the result. */
  ctx->task = silc_schedule_task_add(ctx->client->schedule, sock, 
				     silc_client_ftp_connected,
				     (void *)ctx, 0, 0, 
				     SILC_TASK_FD,
				     SILC_TASK_PRI_NORMAL);
  silc_schedule_set_listen_fd(ctx->client->schedule, sock, SILC_TASK_WRITE);
  ctx->sock = sock;
  return sock;
}

static int
silc_client_connect_to_client(SilcClient client, 
			      SilcClientConnection conn, int port,
			      char *host, void *context)
{
  SilcClientInternalConnectContext *ctx;

  /* Allocate internal context for connection process. This is
     needed as we are doing async connecting. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->client = client;
  ctx->conn = conn;
  ctx->host = strdup(host);
  ctx->port = port;
  ctx->tries = 0;
  ctx->context = context;

  /* Do the actual connecting process */
  return silc_client_connect_to_client_internal(ctx);
}

/* SFTP packet send callback. This will use preallocated buffer to avoid
   reallocation of outgoing data buffer everytime. */

static void silc_client_ftp_send_packet(SilcSocketConnection sock,
					SilcBuffer packet, void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;
  SilcClient client = session->client;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate outgoing packet */
  if (!session->packet)
    session->packet = silc_buffer_alloc(1 + packet->len);

  /* Enlarge outgoing packet if needed */
  if (session->packet->truelen < 1 + packet->len)
    session->packet = silc_buffer_realloc(session->packet, 1 + packet->len);

  /* Encode packet */
  silc_buffer_pull_tail(session->packet, 1 + packet->len);
  silc_buffer_format(session->packet,
		     SILC_STR_UI_CHAR(1),
		     SILC_STR_UI_XNSTRING(packet->data, packet->len),
		     SILC_STR_END);

  /* Send the packet immediately */
  silc_client_packet_send(client, sock, SILC_PACKET_FTP, NULL, 0, NULL, NULL,
			  session->packet->data, session->packet->len, TRUE);

  /* Clear buffer */
  session->packet->data = session->packet->tail = session->packet->head;
  session->packet->len = 0;
}

/* SFTP monitor callback for SFTP server. This reports the application 
   how the transmission is going along. This function is for the client
   who made the file available for download. */

static void silc_client_ftp_monitor(SilcSFTP sftp,
				    SilcSFTPMonitors type,
				    const SilcSFTPMonitorData data,
				    void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  if (type == SILC_SFTP_MONITOR_READ) {
    /* Call the monitor for application */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_SEND,
			  data->offset, session->filesize,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
  }
}

/* Returns the read data. This is the downloader's function (client side)
   to receive the read data and read more until EOF is received from
   the other side. This will also monitor the transmission and notify
   the application. */

static void silc_client_ftp_data(SilcSFTP sftp,
				 SilcSFTPStatus status,
				 const unsigned char *data,
				 uint32 data_len,
				 void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  if (status == SILC_SFTP_STATUS_EOF) {
    /* EOF received */

    /* Close the handle */
    silc_sftp_close(sftp, session->read_handle, NULL, NULL);
    session->read_handle = NULL;

    /* Close the read file descriptor */
    silc_file_close(session->fd);
    return;
  }

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);

    /* Close the handle */
    silc_sftp_close(sftp, session->read_handle, NULL, NULL);
    session->read_handle = NULL;

    /* Close the read file descriptor */
    silc_file_close(session->fd);
    return;
  }

  /* Read more, until EOF is received */
  session->read_offset += data_len;
  silc_sftp_read(sftp, session->read_handle, session->read_offset, 64512,
		 silc_client_ftp_data, session);

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_RECEIVE,
			session->read_offset, session->filesize,
			session->client_entry, session->session_id,
			session->filepath, session->monitor_context);

  /* Write the read data to the real file */
  silc_file_write(session->fd, data, data_len);
}

/* Returns handle for the opened file. This is the downloader's function.
   This will begin reading the data from the file. */

static void silc_client_ftp_open_handle(SilcSFTP sftp,
					SilcSFTPStatus status,
					SilcSFTPHandle handle,
					void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Open the actual local file */
  session->fd = silc_file_open(session->filepath, O_RDWR | O_CREAT);
  if (session->fd < 0) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  session->read_handle = handle;

  /* Now, start reading the file */
  silc_sftp_read(sftp, session->read_handle, session->read_offset, 64512,
		 silc_client_ftp_data, session);

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_RECEIVE,
			session->read_offset, session->filesize,
			session->client_entry, session->session_id,
			session->filepath, session->monitor_context);
}

/* Returns the file name available for download. This is the downloader's
   function. */

static void silc_client_ftp_readdir_name(SilcSFTP sftp,
					 SilcSFTPStatus status,
					 const SilcSFTPName name,
					 void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;
  SilcSFTPAttributesStruct attr;

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Now open the file */
  memset(&attr, 0, sizeof(attr));
  silc_sftp_open(sftp, name->filename[0], SILC_SFTP_FXF_READ, &attr,
		 silc_client_ftp_open_handle, session);

  /* Save the important attributes */
  session->filepath = strdup(name->filename[0]);
  session->filesize = name->attrs[0]->size;

  /* Close the directory handle */
  silc_sftp_close(sftp, session->dir_handle, NULL, NULL);
  session->dir_handle = NULL;
}

/* Returns the file handle after giving opendir command. This is the
   downloader's function. */

static void silc_client_ftp_opendir_handle(SilcSFTP sftp,
					   SilcSFTPStatus status,
					   SilcSFTPHandle handle,
					   void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Now, read the directory */
  silc_sftp_readdir(sftp, handle, silc_client_ftp_readdir_name, session);
  session->dir_handle = handle;
}

/* SFTP version callback for SFTP client. This is the downloader's function
   after initializing the SFTP connection to the remote client. This will
   find out the filename available for download. */

static void silc_client_ftp_version(SilcSFTP sftp,
				    SilcSFTPStatus status,
				    SilcSFTPVersion version,
				    void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* The SFTP session is open, now retrieve the info about available file. */
  silc_sftp_opendir(sftp, "", silc_client_ftp_opendir_handle, session);
}

/* This callback is called after the key agreement protocol has been
   performed. This calls the final completion callback for the application. */

SILC_TASK_CALLBACK(silc_client_ftp_key_agreement_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClientFtpSession session = (SilcClientFtpSession)ctx->context;
  SilcClientConnection conn = (SilcClientConnection)ctx->sock->user_data;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_ske_free_key_material(ctx->keymat);
    goto out;
  }

  /* Set keys into use */
  silc_client_protocol_ke_set_keys(ctx->ske, ctx->sock, ctx->keymat,
				   ctx->ske->prop->cipher,
				   ctx->ske->prop->pkcs,
				   ctx->ske->prop->hash,
				   ctx->ske->prop->hmac,
				   ctx->ske->prop->group,
				   ctx->responder);

  /* If we are the SFTP client then start the SFTP session and retrieve
     the info about the file available for download. */
  if (!session->server) {
    session->sftp = silc_sftp_client_start(conn->sock,
					   silc_client_ftp_send_packet,
					   session, 
					   silc_client_ftp_version, session);
  }

  /* Set this as active session */
  conn->active_session = session;

 out:
  silc_ske_free_key_material(ctx->keymat);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx->dest_id);
  ctx->sock->protocol = NULL;
  silc_socket_free(ctx->sock);
  silc_free(ctx);
  silc_protocol_free(protocol);
}

/* The downloader's function to start the key agreement protocol with the
   remote client after we have connected to it. */

static void silc_client_ftp_start_key_agreement(SilcClientFtpSession session,
						int sock)
{
  SilcClient client = session->client;
  SilcClientKEInternalContext *proto_ctx;
  SilcProtocol protocol;
  SilcClientConnection conn;
  void *context;

  SILC_LOG_DEBUG(("Start"));

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT, 0, 0,
			session->client_entry, session->session_id,
			NULL, session->monitor_context);

  /* Add new connection for this session */
  conn = silc_client_add_connection(client, session->hostname,
				    session->port, session);

  /* Allocate new socket connection object */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_CLIENT, (void *)conn, &conn->sock);
  conn->sock->hostname = strdup(session->hostname);
  conn->sock->port = silc_net_get_remote_port(sock);
  session->sock = silc_socket_dup(conn->sock);

  /* Allocate the SFTP */
  if (session->server) {
    session->sftp = silc_sftp_server_start(conn->sock,
					   silc_client_ftp_send_packet,
					   session, session->fs);

    /* Monitor transmission */
    silc_sftp_server_set_monitor(session->sftp, SILC_SFTP_MONITOR_READ,
				 silc_client_ftp_monitor, session);
  }

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = client;
  proto_ctx->sock = silc_socket_dup(conn->sock);
  proto_ctx->rng = client->rng;
  proto_ctx->responder = FALSE;
  proto_ctx->context = session;
  proto_ctx->send_packet = silc_client_protocol_ke_send_packet;
  proto_ctx->verify = silc_client_protocol_ke_verify_key;

  /* Perform key exchange protocol. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &protocol, (void *)proto_ctx,
		      silc_client_ftp_key_agreement_final);
  conn->sock->protocol = protocol;

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it will 
     be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(sock);

  /* Execute the protocol */
  silc_protocol_execute(protocol, client->schedule, 0, 0);
}

/* The remote client's (the client who made the file available for download)
   function for accepting incoming connection. This will also start the
   key agreement protocol with the other client. */

SILC_TASK_CALLBACK(silc_client_ftp_process_key_agreement)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;
  SilcClient client = session->client;
  SilcClientConnection conn;
  SilcSocketConnection newsocket;
  SilcClientKEInternalContext *proto_ctx;
  int sock;

  SILC_LOG_DEBUG(("Start"));

  sock = silc_net_accept_connection(session->listener);
  if (sock < 0) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Allocate new socket connection object */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_CLIENT, NULL, &newsocket);

  /* Perform name and address lookups for the remote host. */
  silc_net_check_host_by_sock(sock, &newsocket->hostname, &newsocket->ip);
  if (!newsocket->hostname && !newsocket->ip) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }
  if (!newsocket->hostname)
    newsocket->hostname = strdup(newsocket->ip);
  newsocket->port = silc_net_get_remote_port(sock);

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT, 0, 0,
			session->client_entry, session->session_id,
			NULL, session->monitor_context);

  /* Add new connection for this session */
  conn = silc_client_add_connection(client, newsocket->hostname,
				    newsocket->port, session);
  conn->sock = newsocket;
  conn->sock->user_data = conn;
  session->sock = silc_socket_dup(conn->sock);

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = client;
  proto_ctx->sock = silc_socket_dup(conn->sock);
  proto_ctx->rng = client->rng;
  proto_ctx->responder = TRUE;
  proto_ctx->context = session;
  proto_ctx->send_packet = silc_client_protocol_ke_send_packet;
  proto_ctx->verify = silc_client_protocol_ke_verify_key;

  /* Prepare the connection for key exchange protocol. We allocate the
     protocol but will not start it yet. The connector will be the
     initiator of the protocol thus we will wait for initiation from 
     there before we start the protocol. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &newsocket->protocol, proto_ctx, 
		      silc_client_ftp_key_agreement_final);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it
     will be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(sock);
}

/* Free all file transfer sessions. */

void silc_client_ftp_free_sessions(SilcClient client,
				   SilcClientConnection conn)
{
  if (conn->ftp_sessions) {
    SilcClientFtpSession session;
    silc_dlist_start(conn->ftp_sessions);
    while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
      if (session->sock)
	session->sock->user_data = NULL;
      silc_client_ftp_session_free(session);
    }
    silc_dlist_del(conn->ftp_sessions, session);
    silc_dlist_uninit(conn->ftp_sessions);
  }
}

/* Free file transfer session by client entry. */

void silc_client_ftp_session_free_client(SilcClientConnection conn,
					 SilcClientEntry client_entry)
{
  SilcClientFtpSession session;

  if (!conn->ftp_sessions)
    return;

  /* Get the session */
  silc_dlist_start(conn->ftp_sessions);
  while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
    if (session->client_entry == client_entry) {
      if (session->sock)
	session->sock->user_data = NULL;
      silc_client_ftp_session_free(session);
      break;
    }
  }
}

/* Free session resources. */

void silc_client_ftp_session_free(SilcClientFtpSession session)
{
  SilcClientConnection conn;

  SILC_LOG_DEBUG(("Free session"));

  silc_dlist_del(session->conn->ftp_sessions, session);

  if (session->sftp) {
    if (session->server)
      silc_sftp_server_shutdown(session->sftp);
    else
      silc_sftp_client_shutdown(session->sftp);
  }

  if (session->fs)
    silc_sftp_fs_memory_free(session->fs);

  /* Destroy listener */
  if (session->listener) {
    silc_schedule_unset_listen_fd(session->client->schedule, 
				  session->listener);
    silc_net_close_connection(session->listener);
    silc_schedule_task_del_by_fd(session->client->schedule, session->listener);
  }

  /* Destroy session connection */
  if (session->sock) {
    silc_schedule_unset_listen_fd(session->client->schedule, 
				  session->sock->sock);
    silc_net_close_connection(session->sock->sock);

    if (session->sock->user_data) {
      conn = (SilcClientConnection)session->sock->user_data;

      if (conn->active_session == session)
	conn->active_session = NULL;

      silc_client_close_connection(session->client, session->sock, conn);
    } else {
      silc_socket_free(session->sock);
    }
  }

  if (session->packet)
    silc_buffer_free(session->packet);

  silc_free(session->hostname);
  silc_free(session->filepath);
  silc_free(session);
}

/* Sends a file indicated by the `filepath' to the remote client 
   indicated by the `client_entry'.  This will negotiate a secret key
   with the remote client before actually starting the transmission of
   the file.  The `monitor' callback will be called to monitor the
   transmission of the file.

   This returns a file session ID for the file transmission.  It can
   be used to close the session (and abort the file transmission) by
   calling the silc_client_file_close function.  The session ID is
   also returned in the `monitor' callback. This returns 0 if the
   file indicated by the `filepath' is being transmitted to the remote
   client indicated by the `client_entry', already. */

uint32 silc_client_file_send(SilcClient client,
			     SilcClientConnection conn,
			     SilcClientFileMonitor monitor,
			     void *monitor_context,
			     SilcClientEntry client_entry,
			     const char *filepath)
{
  SilcClientFtpSession session;
  SilcBuffer keyagr, ftp;
  char *filename, *path;

  SILC_LOG_DEBUG(("Start"));

  /* Check for existing session for `filepath'. */
  silc_dlist_start(conn->ftp_sessions);
  while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
    if (!strcmp(session->filepath, filepath) && 
	session->client_entry == client_entry)
      return 0;
  }

  /* Add new session */
  session = silc_calloc(1, sizeof(*session));
  session->session_id = ++conn->next_session_id;
  session->client = client;
  session->conn = conn;
  session->client_entry = client_entry;
  session->monitor = monitor;
  session->monitor_context = monitor_context;
  session->filepath = strdup(filepath);
  session->server = TRUE;
  silc_dlist_add(conn->ftp_sessions, session);

  path = silc_calloc(strlen(filepath) + 8, sizeof(*path));
  strcat(path, "file://");
  strncat(path, filepath, strlen(filepath));

  /* Allocate memory filesystem and put the file to it */
  if (strrchr(path, '/'))
    filename = strrchr(path, '/') + 1;
  else
    filename = (char *)path;
  session->fs = silc_sftp_fs_memory_alloc(SILC_SFTP_FS_PERM_READ |
					  SILC_SFTP_FS_PERM_EXEC);
  silc_sftp_fs_memory_add_file(session->fs, NULL, SILC_SFTP_FS_PERM_READ,
			       filename, path);

  session->filesize = silc_file_size(filepath);

  /* Send the key agreement inside FTP packet */
  keyagr = silc_key_agreement_payload_encode(NULL, 0);

  ftp = silc_buffer_alloc(1 + keyagr->len);
  silc_buffer_pull_tail(ftp, SILC_BUFFER_END(ftp));
  silc_buffer_format(ftp,
		     SILC_STR_UI_CHAR(1),
		     SILC_STR_UI_XNSTRING(keyagr->data, keyagr->len),
		     SILC_STR_END);
  silc_client_packet_send(client, conn->sock, SILC_PACKET_FTP,
			  client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			  ftp->data, ftp->len, FALSE);

  silc_buffer_free(keyagr);
  silc_buffer_free(ftp);
  silc_free(path);

  return session->session_id;
}

/* Receives a file from a client indicated by the `client_entry'.  The
   `session_id' indicates the file transmission session and it has been
   received in the `ftp' client operation function.  This will actually
   perform the key agreement protocol with the remote client before
   actually starting the file transmission.  The `monitor' callback
   will be called to monitor the transmission. */

SilcClientFileError 
silc_client_file_receive(SilcClient client,
			 SilcClientConnection conn,
			 SilcClientFileMonitor monitor,
			 void *monitor_context,
			 SilcClientEntry client_entry,
			 uint32 session_id)
{
  SilcClientFtpSession session;
  SilcBuffer keyagr, ftp;

  SILC_LOG_DEBUG(("Start, Session ID: %d", session_id));

  /* Get the session */
  silc_dlist_start(conn->ftp_sessions);
  while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
    if (session->session_id == session_id) {
      break;
    }
  }

  if (session == SILC_LIST_END) {
    SILC_LOG_DEBUG(("Unknown session ID: %d\n", session_id));
    return SILC_CLIENT_FILE_UNKNOWN_SESSION;
  }

  /* See if we have this session running already */
  if (session->sftp || session->listener) {
    SILC_LOG_DEBUG(("Session already started"));
    return SILC_CLIENT_FILE_ALREADY_STARTED;
  }

  session->monitor = monitor;
  session->monitor_context = monitor_context;
  session->client_entry = client_entry;
  session->conn = conn;

  /* If the hostname and port already exists then the remote client did
     provide the connection point to us and we won't create listener, but
     create the connection ourselves. */
  if (session->hostname && session->port) {
    if (silc_client_connect_to_client(client, conn, session->port, 
				      session->hostname, session) < 0)
      return SILC_CLIENT_FILE_ERROR;
  } else {
    /* Add the listener for the key agreement */
    session->hostname = silc_net_localip();
    session->listener = silc_net_create_server(0, session->hostname);
    if (session->listener < 0) {
      SILC_LOG_DEBUG(("Could not create listener"));
      return SILC_CLIENT_FILE_ERROR;
    }
    session->port = silc_net_get_local_port(session->listener);
    silc_schedule_task_add(client->schedule, session->listener,
			   silc_client_ftp_process_key_agreement, session,
			   0, 0, SILC_TASK_FD, SILC_TASK_PRI_NORMAL);
    
    /* Send the key agreement inside FTP packet */
    keyagr = silc_key_agreement_payload_encode(session->hostname, 
					       session->port);
    ftp = silc_buffer_alloc(1 + keyagr->len);
    silc_buffer_pull_tail(ftp, SILC_BUFFER_END(ftp));
    silc_buffer_format(ftp,
		       SILC_STR_UI_CHAR(1),
		       SILC_STR_UI_XNSTRING(keyagr->data, keyagr->len),
		       SILC_STR_END);
    silc_client_packet_send(client, conn->sock, SILC_PACKET_FTP,
			    client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			    ftp->data, ftp->len, FALSE);
    
    silc_buffer_free(keyagr);
    silc_buffer_free(ftp);
  }

  return SILC_CLIENT_FILE_OK;
}

/* Closes file transmission session indicated by the `session_id'.
   If file transmission is being conducted it will be aborted
   automatically. This function is also used to close the session
   after successful file transmission. This function can be used
   also to reject incoming file transmission request. */

SilcClientFileError silc_client_file_close(SilcClient client,
					   SilcClientConnection conn,
					   uint32 session_id)
{
  SilcClientFtpSession session;

  SILC_LOG_DEBUG(("Start, Session ID: %d", session_id));

  /* Get the session */
  silc_dlist_start(conn->ftp_sessions);
  while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
    if (session->session_id == session_id) {
      break;
    }
  }

  if (session == SILC_LIST_END) {
    SILC_LOG_DEBUG(("Unknown session ID: %d\n", session_id));
    return SILC_CLIENT_FILE_UNKNOWN_SESSION;
  }

  silc_client_ftp_session_free(session);

  return SILC_CLIENT_FILE_OK;
}

/* Callback called after remote client information has been resolved.
   This will try to find existing session for the client entry.  If found
   then continue with the key agreement protocol.  If not then it means
   this is a file transfer request and we let the application know. */

static void silc_client_ftp_resolve_cb(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry *clients,
				       uint32 clients_count,
				       void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;
  SilcClientFtpSession session;
  SilcKeyAgreementPayload payload = NULL;
  SilcClientEntry client_entry;
  char *hostname;
  uint16 port;

  SILC_LOG_DEBUG(("Start"));

  if (!clients)
    goto out;

  client_entry = clients[0];

  silc_dlist_start(conn->ftp_sessions);
  while ((session = silc_dlist_get(conn->ftp_sessions)) != SILC_LIST_END) {
    if (session->client_entry == client_entry)
      break;
  }

  /* Parse the key agreement payload */
  payload = silc_key_agreement_payload_parse(packet->buffer);
  if (!payload)
    goto out;

  hostname = silc_key_agreement_get_hostname(payload);
  port = silc_key_agreement_get_port(payload);

  if (session == SILC_LIST_END) {
    /* No session found, create one and let the application know about
       incoming file transfer request. */
    
    /* Add new session */
    session = silc_calloc(1, sizeof(*session));
    session->session_id = ++conn->next_session_id;
    session->client = client;
    session->conn = conn;
    silc_dlist_add(conn->ftp_sessions, session);

    /* Let the application know */
    client->ops->ftp(client, conn, client_entry,
		     session->session_id, hostname, port);

    if (hostname && port) {
      session->hostname = strdup(hostname);
      session->port = port;
    }
    
    goto out;
  }

  if (!hostname)
    goto out;

  session->hostname = strdup(hostname);
  session->port = port;

  /* Session exists, continue with key agreement protocol. */
  if (silc_client_connect_to_client(client, conn, port, 
				    hostname, session) < 0) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
  }

 out:
  if (payload)
    silc_key_agreement_payload_free(payload);
  silc_packet_context_free(packet);
}

/* Called when file transfer packet is received. This will parse the
   packet and give it to the file transfer protocol. */

void silc_client_ftp(SilcClient client,
		     SilcSocketConnection sock,
		     SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  uint8 type;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Parse the payload */
  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI_CHAR(&type),
			     SILC_STR_END);
  if (ret == -1)
    return;

  /* We support only type number 1 (== SFTP) */
  if (type != 1)
    return;

  silc_buffer_pull(packet->buffer, 1);

  /* If we have active FTP session then give the packet directly to the
     protocol processor. */
  if (conn->active_session) {
    /* Give it to the SFTP */
    if (conn->active_session->server)
      silc_sftp_server_receive_process(conn->active_session->sftp, sock, 
				       packet);
    else
      silc_sftp_client_receive_process(conn->active_session->sftp, sock, 
				       packet);
  } else {
    /* We don't have active session, resolve the remote client information
       and then try to find the correct session. */
    SilcClientID *remote_id;

    if (packet->src_id_type != SILC_ID_CLIENT)
      return;

    remote_id = silc_id_str2id(packet->src_id, packet->src_id_len, 
			       SILC_ID_CLIENT);
    if (!remote_id)
      return;

    /* Resolve the client */
    silc_client_get_client_by_id_resolve(client, sock->user_data, remote_id,
					 silc_client_ftp_resolve_cb,
					 silc_packet_context_dup(packet));
    silc_free(remote_id);
  }
}
