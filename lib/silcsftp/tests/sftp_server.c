/*

  sprp_server.c 

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
  SilcSocketConnection sock;
  void *server;
} *ServerSession;

typedef struct {
  SilcSchedule schedule;
  int sock;
  SilcSFTPFilesystem fs;
  ServerSession sessions[100];
  SilcSFTP sftp[100];
} *Server;

static void send_packet(SilcBuffer packet, void *context)
{
  ServerSession session = context;
  Server server = session->server;
  SilcPacketContext packetdata;
  const SilcBufferStruct p;
  int ret;

  memset(&packetdata, 0, sizeof(packetdata));
  packetdata.type = SILC_PACKET_FTP;
  packetdata.truelen = packet->len + SILC_PACKET_HEADER_LEN;
  SILC_PACKET_PADLEN(packetdata.truelen, 0, packetdata.padlen);
  silc_packet_assemble(&packetdata, NULL, NULL, NULL, session->sock,
		       packet->data, packet->len, (const SilcBuffer)&p);
  ret = silc_packet_send(session->sock, TRUE);
  if (ret != -2)
    return;

  silc_schedule_set_listen_fd(server->schedule, session->sock->sock, 
			      (SILC_TASK_READ | SILC_TASK_WRITE), FALSE);
  SILC_SET_OUTBUF_PENDING(session->sock);
}

static bool packet_parse(SilcPacketParserContext *parser, void *context)
{
  Server server = (Server)parser->context;
  SilcSocketConnection sock = parser->sock;
  SilcPacketContext *packet = parser->packet;
  int ret;
  
  ret = silc_packet_parse(packet, NULL);
  assert(packet->type == SILC_PACKET_FTP);

  silc_sftp_server_receive_process(server->sftp[sock->sock], sock, packet);

  return TRUE;
}

SILC_TASK_CALLBACK(packet_process)
{
  Server server = context;
  ServerSession session = server->sessions[fd];
  SilcSocketConnection sock;
  int ret;

  if (!session)
    return;
  sock = session->sock;

  if (type == SILC_TASK_WRITE) {
    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    ret = silc_packet_send(sock, TRUE);
    if (ret < 0)
      return;

    silc_schedule_set_listen_fd(server->schedule, fd, SILC_TASK_READ, FALSE);
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
      silc_schedule_unset_listen_fd(server->schedule, sock->sock);
      silc_free(server->sessions[sock->sock]);
      server->sessions[sock->sock] = NULL;
      silc_socket_free(sock);
      return;
    }

    silc_packet_receive_process(sock, FALSE, NULL, NULL, 0, packet_parse, 
				server);
  }
}

SILC_TASK_CALLBACK(accept_connection)
{
  Server server = (Server)context;
  SilcSocketConnection sc;
  int sock;

  sock = silc_net_accept_connection(server->sock);
  if (sock < 0)
    exit(1);

  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  silc_socket_alloc(sock, 0, NULL, &sc);
  server->sessions[sock] = silc_calloc(1, sizeof(server->sessions[0]));
  server->sessions[sock]->sock = sc;
  server->sessions[sock]->server = server;
  server->sftp[sock] = 
    silc_sftp_server_start(send_packet, server->sessions[sock],
			   server->fs);
  silc_schedule_task_add(server->schedule, sock, packet_process,
			 server, 0, 0, SILC_TASK_GENERIC,
			 SILC_TASK_PRI_NORMAL);
}

int main()
{
  Server server = silc_calloc(1, sizeof(*server));
  void *dir;

  silc_debug = 1;
  silc_debug_hexdump = 1;
  silc_log_set_debug_string("*sftp*");
  
  server->schedule = silc_schedule_init(100, NULL);
  if (!server->schedule)
    return -1;

  server->sock = silc_net_create_server(5000, NULL);
  if (server->sock < 0)
    return -1;

  /* Make test filesystem hierarchy */

  server->fs = silc_sftp_fs_memory_alloc((SILC_SFTP_FS_PERM_READ |
					  SILC_SFTP_FS_PERM_WRITE));
  dir =
    silc_sftp_fs_memory_add_dir(server->fs, NULL, (SILC_SFTP_FS_PERM_READ |
						   SILC_SFTP_FS_PERM_WRITE |
						   SILC_SFTP_FS_PERM_EXEC),
				"sftp");
  silc_sftp_fs_memory_add_file(server->fs, NULL, SILC_SFTP_FS_PERM_READ,
			       "passwd", "file:///etc/passwd");
  silc_sftp_fs_memory_add_file(server->fs, NULL, (SILC_SFTP_FS_PERM_READ |
						  SILC_SFTP_FS_PERM_WRITE),
			       "writeme", "file://./writeme-test");
  silc_sftp_fs_memory_add_file(server->fs, dir, SILC_SFTP_FS_PERM_READ,
			       "shadow", "file:///etc/shadow");
  silc_sftp_fs_memory_add_file(server->fs, dir, SILC_SFTP_FS_PERM_READ,
			       "sftp_server.c", "file://sftp_server.c");
  silc_sftp_fs_memory_add_dir(server->fs, dir, (SILC_SFTP_FS_PERM_READ |
						SILC_SFTP_FS_PERM_WRITE |
						SILC_SFTP_FS_PERM_EXEC),
			       "Mail");
  silc_sftp_fs_memory_add_file(server->fs, NULL, SILC_SFTP_FS_PERM_EXEC,
			       "testi", "file://sftp_client.c");

  silc_schedule_task_add(server->schedule, server->sock, 
			 accept_connection, server, 0, 0,
			 SILC_TASK_FD, SILC_TASK_PRI_NORMAL);
  silc_schedule(server->schedule);

  return 0;
}
