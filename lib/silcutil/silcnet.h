/*

  silcnet.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCNET_H
#define SILCNET_H

/* Prototypes */
int silc_net_create_server(int port, char *ip_addr);
void silc_net_close_server(int sock);
int silc_net_create_connection(int port, char *host);
int silc_net_create_connection_async(int port, char *host);
void silc_net_close_connection(int sock);
int silc_net_accept_connection(int sock);
int silc_net_set_socket_nonblock(int sock);
int silc_net_set_socket_opt(int sock, int level, int option, int on);
int silc_net_is_ip(const char *addr);
void silc_net_check_host_by_sock(int sock, char **hostname, char **ip);
uint16 silc_net_get_remote_port(int sock);
uint16 silc_net_get_local_port(int sock);
char *silc_net_localhost();

#endif
