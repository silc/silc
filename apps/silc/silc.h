/*

  silc.h

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

#ifndef SILC_H
#define SILC_H

/* Default client configuration file. This can be overridden at the
   compilation time. Otherwise, use default. This can be overridden on
   command line as well. */
#ifndef SILC_CLIENT_CONFIG_FILE
#define SILC_CLIENT_CONFIG_FILE "/etc/silc/silc.conf"
#endif

/* Default user configuration file. This file is searched from users'
   home directory. This may override global configuration settings. */
#define SILC_CLIENT_HOME_CONFIG_FILE ".silcrc"

/* Default public and private key file names */
#define SILC_CLIENT_PUBLIC_KEY_NAME "public_key.pub"
#define SILC_CLIENT_PRIVATE_KEY_NAME "private_key.prv"

/* Default key expiration time, one year. */
#define SILC_CLIENT_KEY_EXPIRES 365

/* Default settings for creating key pair */
#define SILC_CLIENT_DEF_PKCS "rsa"
#define SILC_CLIENT_DEF_PKCS_LEN 1024

/* XXX This is entirely temporary structure until UI is written again. */
typedef struct {
  /* Input buffer that holds the characters user types. This is
     used only to store the typed chars for a while. */
  SilcBuffer input_buffer;

  /* The SILC client screen object */
  SilcScreen screen;

  /* Current physical window */
  void *current_win;

  SilcClientConnection conn;

  /* Configuration object */
  SilcClientConfig config;

#ifdef SILC_SIM
  /* SIM (SILC Module) table */
  SilcSimContext **sim;
  unsigned int sim_count;
#endif

  /* The allocated client */
  SilcClient client;
} *SilcClientInternal;

/* Macros */

#ifndef CTRL
#define CTRL(x) ((x) & 0x1f)	/* Ctrl+x */
#endif

#endif
