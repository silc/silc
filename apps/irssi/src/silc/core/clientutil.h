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

/* Prototypes */
void silc_print_to_window(WINDOW *win, char *message);
void silc_print(SilcClient client, char *msg, ...);
char *silc_get_mail_path();
int silc_get_number_of_emails();
int silc_client_time_til_next_min();
int silc_client_ask_yes_no(SilcClient client, char *prompt);
char *silc_client_get_input(const char *prompt);
char *silc_client_get_passphrase(const char *prompt);
void silc_client_list_ciphers();
void silc_client_list_hash_funcs();
void silc_client_list_pkcs();
char *silc_client_create_identifier();
int silc_client_create_key_pair(char *pkcs_name, int bits,
				char *public_key, char *private_key,
				char *identifier, 
				SilcPublicKey *ret_pub_key,
				SilcPrivateKey *ret_prv_key);
int silc_client_check_silc_dir();
int silc_client_load_keys(SilcClient client);
int silc_client_show_key(char *keyfile);

#endif
