/*

  sftp_server.c 

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

#include "silcincludes.h"
#include "silcsftp.h"
#include "sftp_util.h"

/* SFTP Server context */
typedef struct {
  SilcSocketConnection sock;
  SilcSFTPSendPacketCallback send_packet;
  void *send_context;
  SilcSFTPFilesystem fs;
  void *fs_context;
} *SilcSFTPServer;

/* General routine to send SFTP packet to the SFTP client. */

static void silc_sftp_send_packet(SilcSFTPServer sftp,
				  SilcSFTPPacket type, 
				  uint32 len, ...)
{
  SilcBuffer packet;
  va_list vp;

  va_start(vp, len);
  packet = silc_sftp_packet_encode_vp(type, len, vp);
  va_end(vp);

  if (!packet)
    return;

  SILC_LOG_HEXDUMP(("SFTP packet to client"), packet->data, packet->len);

  /* Send the packet */
  (*sftp->send_packet)(sftp->sock, packet, sftp->send_context);

  silc_buffer_free(packet);
}

/* Sends error to the client */

static void silc_sftp_send_error(SilcSFTPServer sftp,
				 SilcSFTPStatus status,
				 uint32 id)
{
  SILC_LOG_DEBUG(("Send error %d", status));

  silc_sftp_send_packet(sftp, SILC_SFTP_STATUS, 16,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_INT(status),
			SILC_STR_UI_INT(0),      /* Error */
			SILC_STR_UI_INT(0),	 /* Language tag */
			SILC_STR_END);
}

/* Status callback */

static void silc_sftp_server_status(SilcSFTP sftp,
				    SilcSFTPStatus status,
				    const char *message,
				    const char *language_tag,
				    void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;
  int mlen, llen;

  SILC_LOG_DEBUG(("Status callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));
  
  if (!message)
    message = "";
  if (!language_tag)
    language_tag = "";
  mlen = strlen(message);
  llen = strlen(language_tag);

  silc_sftp_send_packet(server, SILC_SFTP_STATUS, 16 + mlen + llen,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_INT(status),
			SILC_STR_UI_INT(mlen),
			SILC_STR_UI32_STRING(message),
			SILC_STR_UI_INT(llen),
			SILC_STR_UI32_STRING(language_tag),
			SILC_STR_END);
}

/* Handle callback */

static void silc_sftp_server_handle(SilcSFTP sftp,
				    SilcSFTPStatus status,
				    SilcSFTPHandle handle,
				    void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;
  unsigned char *hdata;
  uint32 hdata_len;

  SILC_LOG_DEBUG(("Handle callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));

  if (status != SILC_SFTP_STATUS_OK) {
    silc_sftp_send_error(server, status, id);
    return;
  }

  hdata = server->fs->sftp_encode_handle(server->fs_context, sftp,
					 handle, &hdata_len);
  if (!hdata) {
    silc_sftp_send_error(server, SILC_SFTP_STATUS_FAILURE, id);
    return;
  }

  silc_sftp_send_packet(server, SILC_SFTP_HANDLE, 8 + hdata_len,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_INT(hdata_len),
			SILC_STR_UI_XNSTRING(hdata, hdata_len),
			SILC_STR_END);
}

/* Data callback */

static void silc_sftp_server_data(SilcSFTP sftp,
				  SilcSFTPStatus status,
				  const unsigned char *data,
				  uint32 data_len,
				  void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;

  SILC_LOG_DEBUG(("Data callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));

  if (status != SILC_SFTP_STATUS_OK) {
    silc_sftp_send_error(server, status, id);
    return;
  }

  silc_sftp_send_packet(server, SILC_SFTP_DATA, 8 + data_len,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_INT(data_len),
			SILC_STR_UI_XNSTRING(data, data_len),
			SILC_STR_END);
}

/* Name callback */

static void silc_sftp_server_name(SilcSFTP sftp,
				  SilcSFTPStatus status,
				  const SilcSFTPName name,
				  void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;
  SilcBuffer namebuf;

  SILC_LOG_DEBUG(("Name callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));

  if (status != SILC_SFTP_STATUS_OK) {
    silc_sftp_send_error(server, status, id);
    return;
  }

  namebuf = silc_sftp_name_encode(name);
  if (!namebuf) {
    silc_sftp_send_error(server, SILC_SFTP_STATUS_FAILURE, id);
    return;
  }

  silc_sftp_send_packet(server, SILC_SFTP_NAME, 4 + namebuf->len,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_XNSTRING(namebuf->data, namebuf->len),
			SILC_STR_END);
}

/* Attributes callback */

static void silc_sftp_server_attr(SilcSFTP sftp,
				  SilcSFTPStatus status,
				  const SilcSFTPAttributes attrs,
				  void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;
  SilcBuffer attr_buf;

  SILC_LOG_DEBUG(("Attr callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));

  if (status != SILC_SFTP_STATUS_OK) {
    silc_sftp_send_error(server, status, id);
    return;
  }

  attr_buf = silc_sftp_attr_encode(attrs);

  silc_sftp_send_packet(server, SILC_SFTP_ATTRS, 4 + attr_buf->len,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_XNSTRING(attr_buf->data, attr_buf->len),
			SILC_STR_END);

  silc_buffer_free(attr_buf);
}

/* Extended callback */

static void silc_sftp_server_extended(SilcSFTP sftp,
				      SilcSFTPStatus status,
				      const unsigned char *data,
				      uint32 data_len,
				      void *context)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  uint32 id = (uint32)context;

  SILC_LOG_DEBUG(("Extended callback"));
  SILC_LOG_DEBUG(("Request ID: %d", id));

  if (status != SILC_SFTP_STATUS_OK) {
    silc_sftp_send_error(server, status, id);
    return;
  }

  silc_sftp_send_packet(server, SILC_SFTP_EXTENDED, 4 + data_len,
			SILC_STR_UI_INT(id),
			SILC_STR_UI_XNSTRING(data, data_len),
			SILC_STR_END);
}

/* Starts SFTP server by associating the socket connection `sock' to the
   created SFTP server context.  This function returns the allocated
   SFTP client context or NULL on error. The `send_packet' is called
   by the library when it needs to send a packet. The `fs' is the
   structure containing filesystem access callbacks. */

SilcSFTP silc_sftp_server_start(SilcSocketConnection sock,
				SilcSFTPSendPacketCallback send_packet,
				void *send_context,
				SilcSFTPFilesystem fs,
				void *fs_context)
{
  SilcSFTPServer server;

  server = silc_calloc(1, sizeof(*server));
  server->sock = sock;
  server->send_packet = send_packet;
  server->send_context = send_context;
  server->fs = fs;
  server->fs_context = fs_context;

  SILC_LOG_DEBUG(("Starting SFTP server %p", server));

  return (SilcSFTP)server;
}

/* Shutdown's the SFTP server.  The caller is responsible of closing
   the associated socket connection.  The SFTP context is freed and is
   invalid after this function returns. */

void silc_sftp_server_shutdown(SilcSFTP sftp)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;

  SILC_LOG_DEBUG(("Stopping SFTP server %p", server));

  silc_free(server);
}

/* Function that is called to process the incmoing SFTP packet. */
/* XXX Some day this will go away and we have automatic receive callbacks
   for SilcSocketConnection API or SilcPacketContext API. */

void silc_sftp_server_receive_process(SilcSFTP sftp,
				      SilcSocketConnection sock,
				      SilcPacketContext *packet)
{
  SilcSFTPServer server = (SilcSFTPServer)sftp;
  SilcSFTPPacket type;
  char *filename = NULL, *path = NULL;
  const unsigned char *payload = NULL;
  uint32 payload_len;
  int ret;
  SilcBufferStruct buf;
  uint32 id;
  SilcSFTPAttributes attrs;
  SilcSFTPHandle handle;

  SILC_LOG_DEBUG(("Start"));

  /* Parse the packet */
  type = silc_sftp_packet_decode(packet->buffer, (unsigned char **)&payload, 
				 &payload_len);
  if (!type)
    return;

  silc_buffer_set(&buf, (unsigned char *)payload, payload_len);

  switch (type) {
  case SILC_SFTP_INIT:
    {
      SilcSFTPVersion version;

      SILC_LOG_DEBUG(("Init request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&version),
				 SILC_STR_END);
      if (ret < 0)
	break;

      silc_sftp_send_packet(server, SILC_SFTP_VERSION, 4,
			    SILC_STR_UI_INT(SILC_SFTP_PROTOCOL_VERSION),
			    SILC_STR_END);
    }
    break;

  case SILC_SFTP_OPEN:
    {
      SilcSFTPFileOperation pflags;
      unsigned char *attr_buf;
      uint32 attr_len = 0;
      SilcBufferStruct tmpbuf;

      SILC_LOG_DEBUG(("Open request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&filename),
				 SILC_STR_UI_INT(&pflags),
				 SILC_STR_UI32_NSTRING(&attr_buf, 
						       &attr_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      if (attr_len) {
	silc_buffer_set(&tmpbuf, attr_buf, attr_len);
	attrs = silc_sftp_attr_decode(&tmpbuf);
      } else {
	attrs = silc_calloc(1, sizeof(*attrs));
      }

      /* Open operation */
      server->fs->sftp_open(server->fs_context, sftp, filename, pflags,
			    attrs, silc_sftp_server_handle, (void *)id);

      silc_free(filename);
      silc_sftp_attr_free(attrs);
    }
    break;

  case SILC_SFTP_CLOSE:
    {
      unsigned char *hdata;
      uint32 hdata_len;

      SILC_LOG_DEBUG(("Close request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Close operation */
      server->fs->sftp_close(server->fs_context, sftp, handle,
			     silc_sftp_server_status, (void *)id);
    }
    break;

  case SILC_SFTP_READ:
    {
      unsigned char *hdata;
      uint32 hdata_len;
      uint64 offset;
      uint32 len;

      SILC_LOG_DEBUG(("Read request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_UI_INT64(&offset),
				 SILC_STR_UI_INT(&len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Read operation */
      server->fs->sftp_read(server->fs_context, sftp, handle, offset, len,
			    silc_sftp_server_data, (void *)id);
    }
    break;

  case SILC_SFTP_WRITE:
    {
      unsigned char *hdata;
      uint32 hdata_len;
      uint64 offset;
      unsigned char *data;
      uint32 data_len;

      SILC_LOG_DEBUG(("Read request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_UI_INT64(&offset),
				 SILC_STR_UI32_NSTRING(&data, 
						       &data_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Write operation */
      server->fs->sftp_write(server->fs_context, sftp, handle, offset, 
			     (const unsigned char *)data, data_len,
			     silc_sftp_server_status, (void *)id);
    }
    break;

  case SILC_SFTP_REMOVE:
    {
      SILC_LOG_DEBUG(("Remove request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&filename),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Remove operation */
      server->fs->sftp_remove(server->fs_context, sftp, filename,
			      silc_sftp_server_status, (void *)id);

      silc_free(filename);
    }
    break;

  case SILC_SFTP_RENAME:
    {
      char *newname = NULL;

      SILC_LOG_DEBUG(("Rename request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&filename),
				 SILC_STR_UI32_STRING_ALLOC(&newname),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Rename operation */
      server->fs->sftp_rename(server->fs_context, sftp, filename, newname,
			      silc_sftp_server_status, (void *)id);

      silc_free(filename);
      silc_free(newname);
    }
    break;

  case SILC_SFTP_MKDIR:
    {
      unsigned char *attr_buf;
      uint32 attr_len = 0;
      SilcBufferStruct tmpbuf;

      SILC_LOG_DEBUG(("Mkdir request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_UI32_NSTRING(&attr_buf,
						       &attr_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      if (attr_len) {
	silc_buffer_set(&tmpbuf, attr_buf, attr_len);
	attrs = silc_sftp_attr_decode(&tmpbuf);
      } else {
	attrs = silc_calloc(1, sizeof(*attrs));
      }

      /* Mkdir operation */
      server->fs->sftp_mkdir(server->fs_context, sftp, path, attrs,
			     silc_sftp_server_status, (void *)id);

      silc_sftp_attr_free(attrs);
      silc_free(path);
    }
    break;

  case SILC_SFTP_RMDIR:
    {
      SILC_LOG_DEBUG(("Rmdir request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Rmdir operation */
      server->fs->sftp_rmdir(server->fs_context, sftp, path,
			     silc_sftp_server_status, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_OPENDIR:
    {
      SILC_LOG_DEBUG(("Opendir request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Opendir operation */
      server->fs->sftp_opendir(server->fs_context, sftp, path,
			       silc_sftp_server_handle, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_READDIR:
    {
      unsigned char *hdata;
      uint32 hdata_len;

      SILC_LOG_DEBUG(("Readdir request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Readdir operation */
      server->fs->sftp_readdir(server->fs_context, sftp, handle,
			       silc_sftp_server_name, (void *)id);
    }
    break;

  case SILC_SFTP_STAT:
    {
      SILC_LOG_DEBUG(("Stat request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Stat operation */
      server->fs->sftp_stat(server->fs_context, sftp, path,
			    silc_sftp_server_attr, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_LSTAT:
    {
      SILC_LOG_DEBUG(("Lstat request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Lstat operation */
      server->fs->sftp_lstat(server->fs_context, sftp, path,
			     silc_sftp_server_attr, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_FSTAT:
    {
      unsigned char *hdata;
      uint32 hdata_len;

      SILC_LOG_DEBUG(("Fstat request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Fstat operation */
      server->fs->sftp_fstat(server->fs_context, sftp, handle,
			     silc_sftp_server_attr, (void *)id);
    }
    break;

  case SILC_SFTP_SETSTAT:
    {
      unsigned char *attr_buf;
      uint32 attr_len = 0;
      SilcBufferStruct tmpbuf;

      SILC_LOG_DEBUG(("Setstat request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_UI32_NSTRING(&attr_buf,
						       &attr_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      if (attr_len) {
	silc_buffer_set(&tmpbuf, attr_buf, attr_len);
	attrs = silc_sftp_attr_decode(&tmpbuf);
      } else {
	attrs = silc_calloc(1, sizeof(*attrs));
      }

      /* Setstat operation */
      server->fs->sftp_setstat(server->fs_context, sftp, path, attrs,
			       silc_sftp_server_status, (void *)id);

      silc_sftp_attr_free(attrs);
      silc_free(path);
    }
    break;

  case SILC_SFTP_FSETSTAT:
    {
      unsigned char *hdata, *attr_buf;
      uint32 hdata_len, attr_len = 0;
      SilcBufferStruct tmpbuf;

      SILC_LOG_DEBUG(("Fsetstat request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_NSTRING(&hdata, 
						       &hdata_len),
				 SILC_STR_UI32_NSTRING(&attr_buf,
						       &attr_len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      if (attr_len) {
	silc_buffer_set(&tmpbuf, attr_buf, attr_len);
	attrs = silc_sftp_attr_decode(&tmpbuf);
      } else {
	attrs = silc_calloc(1, sizeof(*attrs));
      }

      /* Get the handle */
      handle = server->fs->sftp_get_handle(server->fs_context, sftp,
					   (const unsigned char *)hdata,
					   hdata_len);
      if (!handle) {
	silc_sftp_send_error(server, SILC_SFTP_STATUS_NO_SUCH_FILE, id);
	break;
      }

      /* Fsetstat operation */
      server->fs->sftp_fsetstat(server->fs_context, sftp, handle, attrs,
				silc_sftp_server_status, (void *)id);

      silc_sftp_attr_free(attrs);
    }
    break;

  case SILC_SFTP_READLINK:
    {
      SILC_LOG_DEBUG(("Readlink request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Readlink operation */
      server->fs->sftp_readlink(server->fs_context, sftp, path,
				silc_sftp_server_name, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_SYMLINK:
    {
      char *target = NULL;

      SILC_LOG_DEBUG(("Symlink request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_UI32_STRING_ALLOC(&target),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Symlink operation */
      server->fs->sftp_symlink(server->fs_context, sftp, path, target,
			       silc_sftp_server_status, (void *)id);

      silc_free(path);
      silc_free(target);
    }
    break;

  case SILC_SFTP_REALPATH:
    {
      SILC_LOG_DEBUG(("Realpath request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&path),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      /* Realpath operation */
      server->fs->sftp_realpath(server->fs_context, sftp, path,
				silc_sftp_server_name, (void *)id);

      silc_free(path);
    }
    break;

  case SILC_SFTP_EXTENDED:
    {
      char *request = NULL;
      unsigned char *data;
      uint32 data_len;

      SILC_LOG_DEBUG(("Extended request"));

      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_INT(&id),
				 SILC_STR_UI32_STRING_ALLOC(&request),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;

      data_len = 8 + strlen(request);
      silc_buffer_pull(&buf, data_len);
      ret = silc_buffer_unformat(&buf,
				 SILC_STR_UI_XNSTRING(&data, buf.len),
				 SILC_STR_END);
      if (ret < 0)
	goto failure;
      data_len = buf.len;

      /* Extended operation */
      server->fs->sftp_extended(server->fs_context, sftp, 
				request, data, data_len,
				silc_sftp_server_extended, (void *)id);

      silc_free(request);
    }
    break;

  default:
    break;
  }

  return;

 failure:
  silc_sftp_send_error(server, SILC_SFTP_STATUS_FAILURE, id);
}
