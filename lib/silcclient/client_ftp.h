/*

  client_ftp.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_FTP_H
#define CLIENT_FTP_H

SILC_FSM_STATE(silc_client_ftp);
void silc_client_ftp_free_sessions(SilcClient client);
void silc_client_ftp_session_free_client(SilcClient client,
					 SilcClientEntry client_entry);

#endif /* CLIENT_FTP_H */
