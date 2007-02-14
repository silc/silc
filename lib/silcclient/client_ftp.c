/*

  client_ftp.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

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

/************************** Types and definitions ***************************/

/* File transmission session */
struct SilcClientFtpSessionStruct {
  SilcClient client;		      /* Client */
  SilcClientConnection conn;	      /* Connection to remote host */
  SilcClientEntry client_entry;	      /* The client entry */
  SilcClientListener listener;	      /* Listener */
  SilcAsyncOperation op;	      /* Operation for connecting */
  SilcClientConnectionParams params;  /* Connection params */
  SilcPublicKey public_key;	      /* Public key used in key exchange */
  SilcPrivateKey private_key;	      /* Private key used in key exchange */
  SilcUInt32 session_id;	      /* File transfer ID */

  SilcClientFileMonitor monitor;      /* File transfer monitor callback */
  void *monitor_context;
  SilcClientFileAskName ask_name;     /* File name asking callback */
  void *ask_name_context;
  char *filepath;		      /* The remote filename */
  char *path;			      /* User given path to save the file  */

  SilcStream stream;		      /* Wrapped SilcPacketStream */
  SilcSFTP sftp;		      /* SFTP server/client */
  SilcSFTPFilesystem fs;	      /* SFTP memory file system */
  SilcSFTPHandle dir_handle;	      /* SFTP session directory handle */
  SilcSFTPHandle read_handle;	      /* SFTP session file handles */

  char *hostname;		      /* Remote host */
  SilcUInt16 port;		      /* Remote port */
  SilcUInt64 filesize;		      /* File size */
  SilcUInt64 read_offset;	      /* Current read offset */
  int fd;			      /* File descriptor */
  unsigned int initiator : 1;	      /* File sender sets this to TRUE */
  unsigned int closed    : 1;	      /* silc_client_file_close called */
};

/************************* SFTP Server Callbacks ****************************/

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
			  SILC_CLIENT_FILE_OK,
			  data->offset, session->filesize,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
  }
}

/************************* SFTP Client Callbacks ****************************/

/* Returns the read data. This is the downloader's function (client side)
   to receive the read data and read more until EOF is received from
   the other side. This will also monitor the transmission and notify
   the application. */

static void silc_client_ftp_data(SilcSFTP sftp,
				 SilcSFTPStatus status,
				 const unsigned char *data,
				 SilcUInt32 data_len,
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
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  (status == SILC_SFTP_STATUS_NO_SUCH_FILE ?
			   SILC_CLIENT_FILE_NO_SUCH_FILE :
			   status == SILC_SFTP_STATUS_PERMISSION_DENIED ?
			   SILC_CLIENT_FILE_PERMISSION_DENIED :
			   SILC_CLIENT_FILE_ERROR), 0, 0,
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
  silc_sftp_read(sftp, session->read_handle, session->read_offset,
                 SILC_PACKET_MAX_LEN - 1024,
		 silc_client_ftp_data, session);

  /* Write the read data to the real file */
  silc_file_write(session->fd, data, data_len);

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_RECEIVE,
			SILC_CLIENT_FILE_OK,
			session->read_offset, session->filesize,
			session->client_entry, session->session_id,
			session->filepath, session->monitor_context);
}

/* Returns handle for the opened file. This is the downloader's function.
   This will begin reading the data from the file. */

static void silc_client_ftp_open_handle(SilcSFTP sftp,
					SilcSFTPStatus status,
					SilcSFTPHandle handle,
					void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;
  char path[512];

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  (status == SILC_SFTP_STATUS_NO_SUCH_FILE ?
			   SILC_CLIENT_FILE_NO_SUCH_FILE :
			   status == SILC_SFTP_STATUS_PERMISSION_DENIED ?
			   SILC_CLIENT_FILE_PERMISSION_DENIED :
			   SILC_CLIENT_FILE_ERROR), 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Open the actual local file */
  memset(path, 0, sizeof(path));
  silc_snprintf(path, sizeof(path) - 1, "%s%s", session->path ?
		session->path : "", session->filepath);
  session->fd = silc_file_open(path, O_RDWR | O_CREAT | O_EXCL);
  if (session->fd < 0) {
    /* Call monitor callback */
    session->client->internal->ops->say(session->client, session->conn,
					SILC_CLIENT_MESSAGE_ERROR,
					"File `%s' open failed: %s",
					session->filepath,
					strerror(errno));

    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  SILC_CLIENT_FILE_PERMISSION_DENIED, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  session->read_handle = handle;

  /* Now, start reading the file */
  silc_sftp_read(sftp, session->read_handle, session->read_offset,
                 SILC_PACKET_MAX_LEN - 1024,
		 silc_client_ftp_data, session);

  /* Call monitor callback */
  if (session->monitor)
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_RECEIVE,
			SILC_CLIENT_FILE_OK,
			session->read_offset, session->filesize,
			session->client_entry, session->session_id,
			session->filepath, session->monitor_context);
}

/* Ask filename completion callback.  Delivers the filepath selected by
   user. */

static void silc_client_ftp_ask_name(const char *filepath,
				     void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;
  SilcSFTPAttributesStruct attr;
  char *remote_file = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (filepath) {
    remote_file = session->filepath;
    session->filepath = NULL;
    silc_free(session->path);
    session->path = NULL;
    session->filepath = strdup(filepath);
  } else {
    remote_file = strdup(session->filepath);
  }

  /* Now open the file */
  memset(&attr, 0, sizeof(attr));
  silc_sftp_open(session->sftp, remote_file, SILC_SFTP_FXF_READ, &attr,
		 silc_client_ftp_open_handle, session);

  /* Close the directory handle */
  silc_sftp_close(session->sftp, session->dir_handle, NULL, NULL);
  session->dir_handle = NULL;

  silc_free(remote_file);
}

/* Returns the file name available for download. This is the downloader's
   function. */

static void silc_client_ftp_readdir_name(SilcSFTP sftp,
					 SilcSFTPStatus status,
					 const SilcSFTPName name,
					 void *context)
{
  SilcClientFtpSession session = (SilcClientFtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  if (status != SILC_SFTP_STATUS_OK) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  (status == SILC_SFTP_STATUS_NO_SUCH_FILE ?
			   SILC_CLIENT_FILE_NO_SUCH_FILE :
			   status == SILC_SFTP_STATUS_PERMISSION_DENIED ?
			   SILC_CLIENT_FILE_PERMISSION_DENIED :
			   SILC_CLIENT_FILE_ERROR), 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* Save the important attributes like filename and file size */
  session->filepath = strdup(name->filename[0]);
  session->filesize = name->attrs[0]->size;

  /* If the path was not provided, ask from application where to save the
     downloaded file. */
  if (!session->path && session->ask_name) {
    session->ask_name(session->client, session->conn, session->session_id,
		      name->filename[0], silc_client_ftp_ask_name, session,
		      session->ask_name_context);
    return;
  }

  /* Start downloading immediately to current directory. */
  silc_client_ftp_ask_name(NULL, session);
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
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  (status == SILC_SFTP_STATUS_NO_SUCH_FILE ?
			   SILC_CLIENT_FILE_NO_SUCH_FILE :
			   status == SILC_SFTP_STATUS_PERMISSION_DENIED ?
			   SILC_CLIENT_FILE_PERMISSION_DENIED :
			   SILC_CLIENT_FILE_ERROR), 0, 0,
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
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  (status == SILC_SFTP_STATUS_NO_SUCH_FILE ?
			   SILC_CLIENT_FILE_NO_SUCH_FILE :
			   status == SILC_SFTP_STATUS_PERMISSION_DENIED ?
			   SILC_CLIENT_FILE_PERMISSION_DENIED :
			   SILC_CLIENT_FILE_ERROR), 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
    return;
  }

  /* The SFTP session is open, now retrieve the info about available file. */
  silc_sftp_opendir(sftp, "", silc_client_ftp_opendir_handle, session);
}

/* SFTP stream error callback */

static void silc_client_ftp_error(SilcSFTP sftp, SilcSFTPStatus status,
				  void *context)
{

}

/************************ Static utility functions **************************/

/* Free session resources.   Connection must be closed before getting
   here. */

static void silc_client_ftp_session_free(SilcClientFtpSession session)
{
  SILC_LOG_DEBUG(("Free session %d", session->session_id));

  silc_dlist_del(session->client->internal->ftp_sessions, session);

  /* Abort connecting  */
  if (session->op)
    silc_async_abort(session->op, NULL, NULL);

  /* Destroy SFTP */
  if (session->sftp) {
    if (session->initiator)
      silc_sftp_server_shutdown(session->sftp);
    else
      silc_sftp_client_shutdown(session->sftp);
  }
  if (session->fs)
    silc_sftp_fs_memory_free(session->fs);

  /* Destroy listener */
  if (session->listener)
    silc_client_listener_free(session->listener);

  /* Destroy wrapped stream */
  if (session->stream)
    silc_stream_destroy(session->stream);

  silc_client_unref_client(session->client, session->conn,
			   session->client_entry);
  silc_free(session->hostname);
  silc_free(session->filepath);
  silc_free(session->path);
  silc_free(session);
}

/* File transfer session timeout */

SILC_TASK_CALLBACK(silc_client_ftp_timeout)
{
  SilcClientFtpSession session = context;

  SILC_LOG_DEBUG(("Timeout"));

  /* Close connection (destroyes the session context later).  If it is
     already closed, destroy the session now. */
  if (session->conn) {
    silc_client_close_connection(session->client, session->conn);
    session->conn = NULL;
  } else {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  SILC_CLIENT_FILE_TIMEOUT, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);

    silc_client_ftp_session_free(context);
  }
}

/* File transfer session closing task callback */

SILC_TASK_CALLBACK(silc_client_file_close_final)
{
  SilcClientFtpSession session = context;

  /* Close connection (destroyes the session context later).  If it is
     already closed, destroy the session now. */
  if (session->conn) {
    silc_client_close_connection(session->client, session->conn);
    session->conn = NULL;
  } else {
    silc_client_ftp_session_free(context);
  }
}

/* Client resolving callback.  Continues with the FTP packet processing */

static void silc_client_ftp_client_resolved(SilcClient client,
					    SilcClientConnection conn,
					    SilcStatus status,
					    SilcDList clients,
					    void *context)
{
  SilcFSMThread thread = context;
  SilcPacket packet = silc_fsm_get_state_context(thread);

  /* If no client found, ignore the packet, a silent error */
  if (!clients) {
    silc_packet_free(packet);
    silc_fsm_finish(thread);
    return;
  }

  /* Continue processing the packet */
  SILC_FSM_CALL_CONTINUE(context);
}

/* FTP packet payload encoder/decoder.  This is called for every FTP packet.
   We add/remove FTP payload in this function, because SFTP library does not
   add/remove it. */

static SilcBool
silc_client_ftp_coder(SilcStream stream, SilcStreamStatus status,
		      SilcBuffer buffer, void *context)
{
  /* Pull FTP type in the payload, revealing SFTP payload */
  if (status == SILC_STREAM_CAN_READ) {
    if (silc_buffer_len(buffer) >= 1)
      silc_buffer_pull(buffer, 1);
    return TRUE;
  }

  /* Add FTP type before SFTP data */
  if (status == SILC_STREAM_CAN_WRITE) {
    if (silc_buffer_format(buffer,
			   SILC_STR_UI_CHAR(1),
			   SILC_STR_END) < 0)
      return FALSE;
    return TRUE;
  }

  return FALSE;
}

/* FTP Connection callback.  The SFTP session is started here. */

static void
silc_client_ftp_connect_completion(SilcClient client,
				   SilcClientConnection conn,
				   SilcClientConnectionStatus status,
				   SilcStatus error,
				   const char *message,
				   void *context)
{
  SilcClientFtpSession session = context;

  session->conn = conn;
  session->op = NULL;

  silc_schedule_task_del_by_context(client->schedule, session);

  switch (status) {
  case SILC_CLIENT_CONN_SUCCESS:
    SILC_LOG_DEBUG(("Connected, conn %p", conn));

    /* Wrap the connection packet stream */
    session->stream = silc_packet_stream_wrap(conn->stream, SILC_PACKET_FTP,
					      0, FALSE,
					      silc_client_ftp_coder, session);
    if (!session->stream) {
      /* Call monitor callback */
      if (session->monitor)
	(*session->monitor)(session->client, session->conn,
			    SILC_CLIENT_FILE_MONITOR_ERROR,
			    SILC_CLIENT_FILE_ERROR, 0, 0,
			    session->client_entry, session->session_id,
			    session->filepath, session->monitor_context);
      silc_client_close_connection(client, conn);
      session->conn = NULL;
      return;
    }

    if (!session->initiator) {
      /* If we are the SFTP client then start the SFTP session and retrieve
	 the info about the file available for download. */
      session->sftp = silc_sftp_client_start(session->stream,
					     conn->internal->schedule,
					     silc_client_ftp_version,
					     silc_client_ftp_error, session);
    } else {
      /* Start SFTP server */
      session->sftp = silc_sftp_server_start(session->stream,
					     conn->internal->schedule,
					     silc_client_ftp_error, session,
					     session->fs);

      /* Monitor transmission */
      silc_sftp_server_set_monitor(session->sftp, SILC_SFTP_MONITOR_READ,
				   silc_client_ftp_monitor, session);
    }

    break;

  case SILC_CLIENT_CONN_DISCONNECTED:
    SILC_LOG_DEBUG(("Disconnected %p", conn));

    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_DISCONNECT,
			  SILC_CLIENT_FILE_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);

    /* Connection already closed */
    session->conn = NULL;

    /* If closed by user, destroy the session now */
    if (session->closed)
      silc_client_ftp_session_free(session);
    break;

  case SILC_CLIENT_CONN_ERROR_TIMEOUT:
    SILC_LOG_DEBUG(("Connecting timeout"));

    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  SILC_CLIENT_FILE_TIMEOUT, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);

    /* Connection already closed */
    session->conn = NULL;
    break;

  default:
    SILC_LOG_DEBUG(("Connecting error %d", status));

    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  status != SILC_CLIENT_CONN_ERROR ?
			  SILC_CLIENT_FILE_KEY_AGREEMENT_FAILED :
			  SILC_CLIENT_FILE_CONNECT_FAILED, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);

    /* Connection already closed */
    session->conn = NULL;
    break;
  }
}

/*************************** File Transfer API ******************************/

/* Free all file transfer sessions. */

void silc_client_ftp_free_sessions(SilcClient client)
{
  SilcClientFtpSession session;

  if (!client->internal->ftp_sessions)
    return;

  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions)))
    silc_client_ftp_session_free(session);
  silc_dlist_del(client->internal->ftp_sessions, session);
}

/* Free file transfer session by client entry. */

void silc_client_ftp_session_free_client(SilcClient client,
					 SilcClientEntry client_entry)
{
  SilcClientFtpSession session;

  if (!client->internal->ftp_sessions)
    return;

  /* Get the session */
  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions)))
    if (session->client_entry == client_entry)
      silc_client_ftp_session_free(session);
}

/* Sends a file indicated by the `filepath' to the remote client
   indicated by the `client_entry'.  This will negotiate a secret key
   with the remote client before actually starting the transmission of
   the file.  The `monitor' callback will be called to monitor the
   transmission of the file. */

SilcClientFileError
silc_client_file_send(SilcClient client,
		      SilcClientConnection conn,
		      SilcClientEntry client_entry,
		      SilcClientConnectionParams *params,
		      SilcPublicKey public_key,
		      SilcPrivateKey private_key,
		      SilcClientFileMonitor monitor,
		      void *monitor_context,
		      const char *filepath,
		      SilcUInt32 *session_id)
{
  SilcClientFtpSession session;
  SilcBuffer keyagr;
  char *filename, *path;
  int fd;

  SILC_LOG_DEBUG(("File send request (file: %s)", filepath));

  if (!client || !client_entry || !filepath || !params ||
      !public_key || !private_key)
    return SILC_CLIENT_FILE_ERROR;

  /* Check for existing session for `filepath'. */
  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions))) {
    if (session->filepath && !strcmp(session->filepath, filepath) &&
	session->client_entry == client_entry)
      return SILC_CLIENT_FILE_ALREADY_STARTED;
  }

  /* See whether the file exists and can be opened */
  fd = silc_file_open(filepath, O_RDONLY);
  if (fd < 0)
    return SILC_CLIENT_FILE_NO_SUCH_FILE;
  silc_file_close(fd);

  /* Add new session */
  session = silc_calloc(1, sizeof(*session));
  if (!session)
    return SILC_CLIENT_FILE_ERROR;
  session->session_id = ++client->internal->next_session_id;
  session->client = client;
  session->initiator = TRUE;
  session->client_entry = silc_client_ref_client(client, conn, client_entry);
  session->monitor = monitor;
  session->monitor_context = monitor_context;
  session->filepath = strdup(filepath);
  session->params = *params;
  session->public_key = public_key;
  session->private_key = private_key;

  if (silc_asprintf(&path, "file://%s", filepath) < 0) {
    silc_free(session);
    return SILC_CLIENT_FILE_NO_MEMORY;
  }

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

  /* If local IP is provided, create listener for incoming key exchange */
  if (params->local_ip || params->bind_ip) {
    session->listener =
      silc_client_listener_add(client,
			       conn->internal->schedule,
			       params, public_key, private_key,
			       silc_client_ftp_connect_completion,
			       session);
    if (!session->listener) {
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Cannot create listener for file transfer: "
				 "%s", strerror(errno));
      silc_free(session);
      return SILC_CLIENT_FILE_NO_MEMORY;
    }

    session->hostname = (params->bind_ip ? strdup(params->bind_ip) :
			 strdup(params->local_ip));
    session->port = silc_client_listener_get_local_port(session->listener);
  }

  SILC_LOG_DEBUG(("Sending key agreement for file transfer"));

  /* Send the key agreement inside FTP packet */
  keyagr = silc_key_agreement_payload_encode(session->hostname, 0,
					     session->port);
  if (!keyagr) {
    if (session->listener)
      silc_client_listener_free(session->listener);
    silc_free(session);
    return SILC_CLIENT_FILE_NO_MEMORY;
  }
  silc_packet_send_va_ext(conn->stream, SILC_PACKET_FTP, 0, 0, NULL,
			  SILC_ID_CLIENT, &client_entry->id, NULL, NULL,
			  SILC_STR_UI_CHAR(1),
			  SILC_STR_DATA(silc_buffer_data(keyagr),
					silc_buffer_len(keyagr)),
			  SILC_STR_END);

  silc_buffer_free(keyagr);
  silc_free(path);

  silc_dlist_add(client->internal->ftp_sessions, session);
  if (session_id)
    *session_id = session->session_id;

  /* Add session request timeout */
  if (params && params->timeout_secs)
    silc_schedule_task_add_timeout(client->schedule,
				   silc_client_ftp_timeout, session,
				   params->timeout_secs, 0);

  return SILC_CLIENT_FILE_OK;
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
			 SilcClientConnectionParams *params,
			 SilcPublicKey public_key,
			 SilcPrivateKey private_key,
			 SilcClientFileMonitor monitor,
			 void *monitor_context,
			 const char *path,
			 SilcUInt32 session_id,
			 SilcClientFileAskName ask_name,
			 void *ask_name_context)
{
  SilcClientFtpSession session;
  SilcBuffer keyagr;

  if (!client || !conn)
    return SILC_CLIENT_FILE_ERROR;

  SILC_LOG_DEBUG(("Start, Session ID: %d", session_id));

  /* Get the session */
  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions))
	 != SILC_LIST_END) {
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
  session->ask_name = ask_name;
  session->ask_name_context = ask_name_context;
  session->path = path ? strdup(path) : NULL;

  /* If the hostname and port already exists then the remote client did
     provide the connection point to us and we won't create listener, but
     create the connection ourselves. */
  if (session->hostname && session->port) {
    SILC_LOG_DEBUG(("Connecting to remote client"));
    /* Connect to the remote client.  Performs key exchange automatically. */
    session->op =
      silc_client_connect_to_client(client, params, public_key, private_key,
				    session->hostname, session->port,
				    silc_client_ftp_connect_completion,
				    session);
    if (!session->op) {
      silc_free(session);
      return SILC_CLIENT_FILE_ERROR;
    }
  } else {
    /* Add the listener for the key agreement */
    SILC_LOG_DEBUG(("Creating listener for file transfer"));
    if (!params || (!params->local_ip && !params->bind_ip)) {
      silc_free(session);
      return SILC_CLIENT_FILE_ERROR;
    }
    session->listener =
      silc_client_listener_add(client, conn->internal->schedule, params,
			       public_key, private_key,
			       silc_client_ftp_connect_completion,
			       session);
    if (!session->listener) {
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Cannot create listener for file transfer: "
				 "%s", strerror(errno));
      silc_free(session);
      return SILC_CLIENT_FILE_NO_MEMORY;
    }
    session->hostname = (params->bind_ip ? strdup(params->bind_ip) :
			 strdup(params->local_ip));
    session->port = silc_client_listener_get_local_port(session->listener);

    /* Send the key agreement inside FTP packet */
    SILC_LOG_DEBUG(("Sending key agreement for file transfer"));
    keyagr = silc_key_agreement_payload_encode(session->hostname, 0,
					       session->port);
    if (!keyagr) {
      silc_client_listener_free(session->listener);
      silc_free(session);
      return SILC_CLIENT_FILE_NO_MEMORY;
    }
    silc_packet_send_va_ext(conn->stream, SILC_PACKET_FTP, 0, 0, NULL,
			    SILC_ID_CLIENT, &session->client_entry->id,
			    NULL, NULL,
			    SILC_STR_UI_CHAR(1),
			    SILC_STR_DATA(silc_buffer_data(keyagr),
					  silc_buffer_len(keyagr)),
			    SILC_STR_END);
    silc_buffer_free(keyagr);

    /* Add session request timeout */
    if (params && params->timeout_secs)
      silc_schedule_task_add_timeout(client->schedule,
				     silc_client_ftp_timeout, session,
				     params->timeout_secs, 0);
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
					   SilcUInt32 session_id)
{
  SilcClientFtpSession session;

  if (!client || !conn)
    return SILC_CLIENT_FILE_ERROR;

  SILC_LOG_DEBUG(("Closing file transer session %d", session_id));

  /* Get the session */
  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions))
	 != SILC_LIST_END) {
    if (session->session_id == session_id)
      break;
  }

  if (session == SILC_LIST_END) {
    SILC_LOG_DEBUG(("Unknown session ID: %d\n", session_id));
    return SILC_CLIENT_FILE_UNKNOWN_SESSION;
  }

  if (session->monitor) {
    (*session->monitor)(session->client, session->conn,
			SILC_CLIENT_FILE_MONITOR_CLOSED,
			SILC_CLIENT_FILE_OK, 0, 0,
			session->client_entry, session->session_id,
			session->filepath, session->monitor_context);

    /* No more callbacks to application */
    session->monitor = NULL;
  }

  session->closed = TRUE;

  /* Destroy via timeout */
  silc_schedule_task_add_timeout(conn->internal->schedule,
				 silc_client_file_close_final, session,
				 0, 1);

  return SILC_CLIENT_FILE_OK;
}

/************************** FTP Request Processing **************************/

/* Received file transfer packet.  Only file transfer requests get here.
   The actual file transfer is handled by the SFTP library when we give it
   the packet stream wrapped into SilcStream context. */

SILC_FSM_STATE(silc_client_ftp)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcClientFtpSession session;
  SilcClientID remote_id;
  SilcClientEntry remote_client;
  SilcKeyAgreementPayload payload;
  char *hostname;
  SilcUInt16 port;

  SILC_LOG_DEBUG(("Process file transfer packet"));

  if (silc_buffer_len(&packet->buffer) < 1)
    goto out;

  /* We support file transfer type number 1 (== SFTP) */
  if (packet->buffer.data[0] != 0x01) {
    SILC_LOG_DEBUG(("Unsupported file transfer type %d",
		    packet->buffer.data[0]));
    goto out;
  }

  if (!silc_id_str2id(packet->src_id, packet->src_id_len,
		      SILC_ID_CLIENT, &remote_id, sizeof(remote_id))) {
    SILC_LOG_DEBUG(("Invalid client ID"));
    goto out;
  }

  /* Check whether we know this client already */
  remote_client = silc_client_get_client_by_id(client, conn, &remote_id);
  if (!remote_client || !remote_client->internal.valid) {
    /** Resolve client info */
    silc_client_unref_client(client, conn, remote_client);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &remote_id, NULL,
					 silc_client_ftp_client_resolved,
					 fsm));
    /* NOT REACHED */
  }

  /* Get session */
  silc_dlist_start(client->internal->ftp_sessions);
  while ((session = silc_dlist_get(client->internal->ftp_sessions))) {
    if (session->client_entry == remote_client &&
	(!session->initiator || !session->listener))
      break;
  }

  /* Parse the key agreement payload */
  payload =
    silc_key_agreement_payload_parse(silc_buffer_data(&packet->buffer) + 1,
				     silc_buffer_len(&packet->buffer) - 1);
  if (!payload) {
    SILC_LOG_DEBUG(("Invalid key agreement payload"));
    goto out;
  }

  hostname = silc_key_agreement_get_hostname(payload);
  port = silc_key_agreement_get_port(payload);
  if (!hostname || !port) {
    hostname = NULL;
    port = 0;
  }

  /* If session doesn't exist, we create new one.  If session exists, but
     we are responder it means that the remote sent another request and user
     hasn't even accepted the first one yet.  We assume this session is new
     session as well. */
  if (!session || !hostname || !session->initiator) {
    /* New file transfer session */
    SILC_LOG_DEBUG(("New file transfer session %d",
		    client->internal->next_session_id + 1));

    session = silc_calloc(1, sizeof(*session));
    if (!session)
      goto out;
    session->session_id = ++client->internal->next_session_id;
    session->client = client;
    session->client_entry = silc_client_ref_client(client, conn,
						   remote_client);
    if (hostname && port) {
      session->hostname = strdup(hostname);
      session->port = port;
    }
    silc_dlist_add(client->internal->ftp_sessions, session);

    /* Notify application of incoming FTP request */
    client->internal->ops->ftp(client, conn, remote_client,
			       session->session_id, hostname, port);
    goto out;
  }

  /* Session exists, continue with key agreement protocol. */
  SILC_LOG_DEBUG(("Session %d exists, connecting to remote client",
		  session->session_id));

  session->hostname = strdup(hostname);
  session->port = port;

  /* Connect to the remote client.  Performs key exchange automatically. */
  session->op =
    silc_client_connect_to_client(client, &session->params,
				  session->public_key, session->private_key,
				  session->hostname, session->port,
				  silc_client_ftp_connect_completion,
				  session);
  if (!session->op) {
    /* Call monitor callback */
    if (session->monitor)
      (*session->monitor)(session->client, session->conn,
			  SILC_CLIENT_FILE_MONITOR_ERROR,
			  SILC_CLIENT_FILE_ERROR, 0, 0,
			  session->client_entry, session->session_id,
			  session->filepath, session->monitor_context);
  }

 out:
  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}
