/*

  sprp_server.c

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

#include "silc.h"
#include "silcsftp.h"

typedef struct ServerSessionStruct {
  SilcStream stream;
  SilcSFTP sftp;
} *ServerSession;

typedef struct {
  SilcSchedule schedule;
  SilcNetListener listener;
  SilcSFTPFilesystem fs;
} *Server;

static void error_cb(SilcSFTP sftp, SilcSFTPStatus status, void *context)
{
  ServerSession session = context;

  if (status == SILC_SFTP_STATUS_EOF) {
    SILC_LOG_DEBUG(("Eof"));
    silc_stream_destroy(session->stream);
    silc_free(session);
  }

  SILC_LOG_DEBUG(("Error %d", status));
}

static void net_callback(SilcNetStatus status, SilcStream stream,
			 void *context)
{
  Server server = context;
  ServerSession session;

  SILC_LOG_DEBUG(("New connection"));

  session = silc_calloc(1, sizeof(*session));
  if (!session)
    return;
  session->stream = stream;
  session->sftp = silc_sftp_server_start(stream, server->schedule, error_cb,
					 session, server->fs);

}

int main()
{
  Server server = silc_calloc(1, sizeof(*server));
  void *dir;
  const char *ip = "127.0.0.1";

  silc_log_debug(TRUE);
  silc_log_debug_hexdump(TRUE);
  silc_log_set_debug_string("*sftp*");

  server->schedule = silc_schedule_init(0, NULL);
  if (!server->schedule)
    return -1;

  server->listener = silc_net_tcp_create_listener(&ip, 1, 5000, FALSE,
						  FALSE, server->schedule,
						  net_callback, server);
  if (!server->listener)
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

  silc_schedule(server->schedule);

  return 0;
}
