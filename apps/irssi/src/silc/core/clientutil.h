/*

  client.h

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

#ifndef CLIENTUTIL_H
#define CLIENTUTIL_H

#include "signals.h"

/* Prototypes */
void silc_client_list_ciphers();
void silc_client_list_hash_funcs();
void silc_client_list_hmacs();
void silc_client_list_pkcs();
int silc_client_check_silc_dir();
int silc_client_load_keys(SilcClient client);

#ifdef SILC_PLUGIN
typedef struct {
  char *old, *passphrase, *file, *pkcs;
  int bits;
} CREATE_KEY_REC;

void create_key_passphrase(const char *answer, CREATE_KEY_REC *rec);
void change_private_key_passphrase(const char *answer, CREATE_KEY_REC *rec);
#endif

#endif
