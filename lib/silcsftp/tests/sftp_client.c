/*

  sftp_client.c 

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

#include "silcincludes.h"
#include "silcsftp.h"

typedef struct {
  SilcSchedule schedule;
  SilcSocketConnection sock;
  SilcSFTP sftp;
} *Client;

Client gclient;

char *dir;
char *file;
bool opendir;
SilcUInt64 offset;
bool success = FALSE;

static void sftp_name(SilcSFTP sftp, SilcSFTPStatus status,
		      const SilcSFTPName name, void *context);
static void sftp_handle(SilcSFTP sftp, SilcSFTPStatus status,
			SilcSFTPHandle handle, void *context);
static void sftp_data(SilcSFTP sftp, SilcSFTPStatus status,
		      const unsigned char *data, SilcUInt32 data_len,
		      void *context);
static void end_test(void);

static void send_packet(SilcBuffer packet, void *context)
{
  Client client = (Client)context;
  SilcSocketConnection sock = client->sock;
  SilcPacketContext packetdata;
  const SilcBufferStruct p;
  int ret;

  memset(&packetdata, 0, sizeof(packetdata));
  packetdata.type = SILC_PACKET_FTP;
  packetdata.truelen = packet->len + SILC_PACKET_HEADER_LEN;
  SILC_PACKET_PADLEN(packetdata.truelen, 0, packetdata.padlen);
  silc_packet_assemble(&packetdata, NULL, NULL, NULL, sock,
		       packet->data, packet->len, (const SilcBuffer)&p);
  ret = silc_packet_send(sock, TRUE);
  if (ret != -2)
    return;
  
  silc_schedule_set_listen_fd(client->schedule, sock->sock, 
			      (SILC_TASK_READ | SILC_TASK_WRITE), FALSE);
  SILC_SET_OUTBUF_PENDING(sock);
}

static bool packet_parse(SilcPacketParserContext *parser, void *context)
{
  Client client = (Client)parser->context;
  SilcSocketConnection sock = parser->sock;
  SilcPacketContext *packet = parser->packet;
  int ret;
  
  ret = silc_packet_parse(packet, NULL);
  assert(packet->type == SILC_PACKET_FTP);

  silc_sftp_client_receive_process(client->sftp, sock, packet);
    
  return TRUE;
}

SILC_TASK_CALLBACK(packet_process)
{
  Client client = (Client)context;
  SilcSocketConnection sock = client->sock;
  int ret;

  if (type == SILC_TASK_WRITE) {
    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    ret = silc_packet_send(sock, TRUE);
    if (ret < 0)
      return;
      
    silc_schedule_set_listen_fd(client->schedule, fd, SILC_TASK_READ, FALSE);
    SILC_UNSET_OUTBUF_PENDING(sock);
    silc_buffer_clear(sock->outbuf);
    return;
    
  }

  if (type == SILC_TASK_READ) {
    ret = silc_packet_receive(sock);
    if (ret < 0)
      return;
  
    if (ret == 0) {
      silc_net_close_connection(sock->sock);
      silc_socket_free(sock);
      exit(0);
    }

    silc_packet_receive_process(sock, FALSE, NULL, NULL, 0, 
				packet_parse, client);
  }
}

static void sftp_data(SilcSFTP sftp, SilcSFTPStatus status,
		      const unsigned char *data, SilcUInt32 data_len,
		      void *context)
{
  SilcSFTPHandle handle = (SilcSFTPHandle)context;
  int debug = silc_debug;

  if (status != SILC_SFTP_STATUS_OK) {
    SilcSFTPAttributesStruct attrs;

    fprintf(stderr, "Status %d\n", status);

    if (status != SILC_SFTP_STATUS_EOF) {
      SILC_LOG_DEBUG(("Error status"));
      success = FALSE;
      end_test();
      return;
    }
    
    if (!strcmp(file, "/sftp/sftp_server.c")) {
      success = TRUE;
      end_test();
      return;
    }
      
    /* Open another file */
    opendir = FALSE;
    memset(&attrs, 0, sizeof(attrs));
    file = "/sftp/sftp_server.c";
    fprintf(stderr, "Opening file %s\n", file);
    offset = 0;
    silc_sftp_open(sftp, file, SILC_SFTP_FXF_READ,
		   &attrs, sftp_handle, gclient);
    return;
  }

  if (!debug)
    silc_debug = 1;
  SILC_LOG_HEXDUMP(("data"), (unsigned char *)data, data_len);
  silc_debug = debug;

  offset += data_len;

  /* Attempt to read more */
  fprintf(stderr, "Reading more of file %s\n", file);
  silc_sftp_read(sftp, handle, offset, 2048, sftp_data, handle);
}

static void sftp_name(SilcSFTP sftp, SilcSFTPStatus status,
		      const SilcSFTPName name, void *context)
{
  Client client = (Client)context;
  int i;

  SILC_LOG_DEBUG(("Name"));
  fprintf(stderr, "Status %d\n", status);

  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }
  
  fprintf(stderr, "Directory: %s\n", dir);
  for (i = 0; i < name->count; i++) {
    fprintf(stderr, "%s\n", name->long_filename[i]);
  }

  if (!strcmp(dir, "sftp")) {
    SilcSFTPAttributesStruct attrs;

    /* open */
    opendir = FALSE;
    memset(&attrs, 0, sizeof(attrs));
    file = "passwd";
    fprintf(stderr, "Opening file %s\n", file);
    offset = 0;
    silc_sftp_open(sftp, file, SILC_SFTP_FXF_READ,
		   &attrs, sftp_handle, client);
    return;
  }

  if (!strcmp(dir, "/"))
    dir = "sftp";

  fprintf(stderr, "Opening %s\n", dir);

  /* opendir */
  opendir = TRUE;
  silc_sftp_opendir(sftp, dir, sftp_handle, client);
}

static void sftp_handle(SilcSFTP sftp, SilcSFTPStatus status,
			SilcSFTPHandle handle, void *context)
{
  Client client = (Client)context;

  SILC_LOG_DEBUG(("Handle"));
  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }
  
  if (opendir) {
    fprintf(stderr, "Reading %s\n", dir);
    /* Readdir */
    silc_sftp_readdir(sftp, handle, sftp_name, client);
  } else {
    fprintf(stderr, "Reading file %s\n", file);

    /* Read */
    silc_sftp_read(sftp, handle, 0, 2048, sftp_data, handle);
  }
}

static void sftp_version(SilcSFTP sftp, SilcSFTPStatus status,
			 SilcSFTPVersion version, void *context)
{
  Client client = (Client)context;
  fprintf(stderr, "Version: %d\n", (int)version);

  SILC_LOG_DEBUG(("Version"));
  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }

  /* opendir */
  dir = "/";
  fprintf(stderr, "Opening %s\n", dir);
  opendir = TRUE;
  silc_sftp_opendir(sftp, dir, sftp_handle, client);
}

int main(int argc, char **argv)
{
  Client client = silc_calloc(1, sizeof(*client));
  int sock;

  gclient = client;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_debug = 1;
    silc_debug_hexdump = 1;
    silc_log_set_debug_string("*sftp*");
  }

  client->schedule = silc_schedule_init(100, NULL);
  if (!client->schedule)
    return -1;

  /* Connecto to server */
  sock = silc_net_create_connection(NULL, 5000, "127.0.0.1");
  if (sock < 0)
    return -1;
  silc_socket_alloc(sock, 0, NULL, &client->sock);
  silc_schedule_task_add(client->schedule, sock,
			 packet_process, client, 0, 0,
			 SILC_TASK_GENERIC, SILC_TASK_PRI_NORMAL);

  /* Start SFTP session */
  client->sftp = silc_sftp_client_start(send_packet, client,
					sftp_version, client);

  silc_schedule(client->schedule);
  return 0;
}

static void end_test(void)
{
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");
  exit(success);
}
